"""
Video Pipeline — decode video stream from Q10 drone's custom UDP packets.

The drone sends video as UDP packets with:
  - Magic byte: 0x93
  - 36-byte outer header (sequence counter at byte 32, LE32)
  - 1044-byte payload per fragment:
      - 20-byte sub-header:
          bytes 0-3:   LE32  fragment_count (total fragments in this frame)
          bytes 4-7:   LE32  frame_size (total data bytes for this frame)
          bytes 8-9:   LE16  width (1280)
          bytes 10-11: LE16  height (720)
          byte  12:    codec type (0x32)
          byte  13:    keyframe flag (0x01 = keyframe first frag)
          bytes 14-15: flags (0x04 0x00)
          bytes 16-17: LE16  fragment_index (0-based)
          bytes 18-19: magic (0xAA 0xA8)
      - 1024 bytes of video data

Each video frame is split across ~55 fragments. This module reassembles
fragments into complete frames, then decodes them as "headless JPEG" —
the drone sends raw JPEG scan data without file headers (SOI/DQT/SOF/DHT/SOS).
We prepend a pre-built header with the correct single quantization table.
"""

import logging
import struct
import threading
import time
from collections import deque
from typing import Optional

import cv2
import numpy as np

log = logging.getLogger("Q10.video")

# Output frame dimensions for the web UI
FRAME_W = 320
FRAME_H = 240

# How many decoded frames to buffer (drop old if full)
FRAME_QUEUE_SIZE = 3

# Outer header length on each 0x93 packet
OUTER_HEADER_LEN = 36

# Sub-header length within each fragment payload
SUB_HEADER_LEN = 20

# Expected data bytes per fragment (payload minus sub-header)
FRAG_DATA_LEN = 1024

# Magic marker at end of sub-header — first byte must be 0xAA.
# Second byte varies: 0xA8 or 0xAA depending on session/firmware.
SUB_HEADER_MAGIC_FIRST = 0xAA

# Pre-built JPEG header for the Q10's headless JPEG format.
# Key: uses the SAME quantization table (luma base at quality 30) for BOTH
# luma and chroma components. Standard JPEG uses separate tables, which
# produces garbled colors with this drone's encoder.
# SOF0: 1280x720, 3 components, all 1x1 sampling (4:4:4).
# Includes standard Huffman tables + SOS header. 623 bytes.
_Q10_JPEG_HEADER = bytes.fromhex(
    "ffd8ffe000104a46494600010100000100010000"
    "ffdb0043001b12111b28435566141417202b6164"
    "5c17161b28435f735d171c2530559185671e253e"
    "5d71b6ac80283a5c6b87adbc99526b8291accac8"
    "a878999ea3bba7aca5"
    "ffdb0043011b12111b28435566141417202b6164"
    "5c17161b28435f735d171c2530559185671e253e"
    "5d71b6ac80283a5c6b87adbc99526b8291accac8"
    "a878999ea3bba7aca5"
    "ffc000110802d0050003011100021101031101"
    "ffc4001f00000105010101010101000000000000"
    "0000010203040506070809"
    "0a0b"
    "ffc400b5100002010303020403050504040000017d"
    "01020300041105122131410613516107227114"
    "328191a1082342b1c11552d1f024336272820"
    "90a161718191a25262728292a343536373839"
    "3a434445464748494a535455565758595a6364"
    "65666768696a737475767778797a8384858687"
    "88898a92939495969798999aa2a3a4a5a6a7a8"
    "a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8"
    "c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7"
    "e8e9eaf1f2f3f4f5f6f7f8f9fa"
    "ffc4001f01000301010101010101010100000000"
    "0000010203040506070809"
    "0a0b"
    "ffc400b5110002010204040304070504040001"
    "0277000102031104052131061241510761711322"
    "328108144291a1b1c109233352f015627"
    "2d10a162434e125f11718191a262728292a3536"
    "3738393a434445464748494a53545556575859"
    "5a636465666768696a737475767778797a8283"
    "8485868788898a92939495969798999aa2a3a4"
    "a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4"
    "c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4"
    "e5e6e7e8e9eaf2f3f4f5f6f7f8f9fa"
    "ffda000c03010002110311003f00"
)


class FrameAssembler:
    """Collects packet fragments and reassembles complete video frames.

    The drone's sub-header field at bytes 16-17 is NOT a fragment index
    (it's always 1). Instead we accumulate data bytes in arrival order
    and use the frame_size field to know when a frame is complete.
    """

    def __init__(self):
        self._buffer = bytearray()
        self._target_size: int = 0   # expected total frame data bytes
        self._frag_count: int = 0
        self._frags_in_frame: int = 0
        self._last_kf: int = -1
        self.frames_assembled = 0
        self.fragments_received = 0
        self._magic_failures = 0

    def feed(self, payload: bytes) -> Optional[bytes]:
        """Feed a payload (after stripping 36-byte outer header).

        Returns assembled frame bytes when complete, else None.
        """
        if len(payload) < SUB_HEADER_LEN:
            return None

        # Parse 20-byte sub-header
        frag_count = struct.unpack_from('<I', payload, 0)[0]
        frame_size = struct.unpack_from('<I', payload, 4)[0]
        width = struct.unpack_from('<H', payload, 8)[0]
        height = struct.unpack_from('<H', payload, 10)[0]
        codec = payload[12]
        kf = payload[13]
        magic = payload[18:20]

        self.fragments_received += 1

        # Log first few fragments + periodic diagnostics
        if self.fragments_received <= 5:
            log.info("Frag[%d] count=%d size=%d %dx%d codec=0x%02X kf=%d magic=%s",
                     self.fragments_received, frag_count, frame_size,
                     width, height, codec, kf, magic.hex())
        elif self.fragments_received % 100 == 0:
            log.info("Frag[%d] count=%d size=%d kf=%d magic=%s buf=%d/%d frags_in=%d assembled=%d",
                     self.fragments_received, frag_count, frame_size, kf, magic.hex(),
                     len(self._buffer), self._target_size, self._frags_in_frame,
                     self.frames_assembled)

        # Validate fragment using structural checks instead of magic bytes.
        # The magic field (bytes 18-19) varies between sessions: 0xAAAA, 0xAAA8,
        # 0x8AA8, etc. Instead, check that frag_count and frame_size are plausible.
        if frag_count == 0 or frag_count > 200 or frame_size == 0 or frame_size > 500000:
            self._magic_failures += 1
            if self._magic_failures <= 10:
                log.warning("Bad fragment[%d]: count=%d size=%d magic=%s payload_len=%d",
                            self.fragments_received, frag_count, frame_size,
                            magic.hex(), len(payload))
            return None
        frag_data = payload[SUB_HEADER_LEN:]

        # Detect new frame: kf goes from 0→1
        if kf == 1 and self._last_kf == 0:
            # New frame boundary — discard any incomplete previous frame
            if self._buffer and self.frames_assembled < 3:
                log.info("New frame (kf 0→1): discarding %d bytes (%d/%d frags)",
                         len(self._buffer), self._frags_in_frame, self._frag_count)
            self._buffer = bytearray()
            self._frags_in_frame = 0

        # Initialize target on first fragment of a frame
        if self._frags_in_frame == 0:
            self._target_size = frame_size
            self._frag_count = frag_count

        # Accumulate data
        self._buffer.extend(frag_data)
        self._frags_in_frame += 1
        self._last_kf = kf

        # Check if frame is complete (by byte count)
        if self._target_size > 0 and len(self._buffer) >= self._target_size:
            frame_data_out = bytes(self._buffer[:self._target_size])
            # Discard overflow (padding in last fragment)
            self._buffer = bytearray()
            self._frags_in_frame = 0
            self.frames_assembled += 1

            # Log first assembled frames for format analysis
            if self.frames_assembled <= 3:
                log.info("Assembled frame #%d: %d bytes (%d frags), first 32: %s",
                         self.frames_assembled, len(frame_data_out), self._frag_count,
                         frame_data_out[:32].hex(' '))
                self._identify_format(frame_data_out)

            return frame_data_out

        return None

    @staticmethod
    def _identify_format(data: bytes):
        """Log what video format the assembled frame data appears to be."""
        if data[:2] == b'\xff\xd8':
            log.info("  -> JPEG detected!")
        elif data[:4] == b'\x00\x00\x00\x01':
            log.info("  -> H.264 Annex B (4-byte start code)")
        elif data[:3] == b'\x00\x00\x01':
            log.info("  -> H.264 Annex B (3-byte start code)")
        else:
            log.info("  -> Unknown header bytes")
            # Scan deeper for known signatures
            for name, sig in [("JPEG FF D8", b'\xff\xd8'),
                              ("H.264 NAL4", b'\x00\x00\x00\x01'),
                              ("H.264 NAL3", b'\x00\x00\x01')]:
                pos = data.find(sig)
                if pos >= 0:
                    log.info("  -> Found %s at offset %d", name, pos)


class VideoDecoder:
    """Receives 0x93 video packets, decodes frames, outputs BGR numpy arrays."""

    def __init__(self, frame_width: int = FRAME_W, frame_height: int = FRAME_H):
        self.frame_width = frame_width
        self.frame_height = frame_height
        self.frame_bytes = frame_width * frame_height * 3

        self._frame_queue: deque = deque(maxlen=FRAME_QUEUE_SIZE)
        self._frame_lock = threading.Lock()
        self._frame_event = threading.Event()

        self._assembler = FrameAssembler()
        self._stop_event = threading.Event()

        self._decode_mode = 'unknown'

        # Stats
        self.packets_fed = 0
        self.frames_decoded = 0
        self.last_frame_time = 0.0
        self._started = False
        self._dropped = 0

    def start(self):
        """Launch the decoder."""
        if self._started:
            return
        self._stop_event.clear()
        self._dropped = 0
        self.packets_fed = 0
        self.frames_decoded = 0
        self._assembler = FrameAssembler()
        self._decode_mode = 'unknown'
        self._start_time = time.time()
        self._started = True
        log.info("Video decoder started (output %dx%d)", self.frame_width, self.frame_height)

    def stop(self):
        """Shut down decoder."""
        self._stop_event.set()
        self._started = False
        log.info("Video decoder stopped (packets=%d, frames=%d, assembled=%d)",
                 self.packets_fed, self.frames_decoded,
                 self._assembler.frames_assembled)

    def feed_packet(self, data: bytes):
        """Feed a raw 0x93 video packet from the drone.

        Strips the 36-byte outer header, collects fragments, and decodes
        complete frames.
        """
        if not self._started:
            self._dropped += 1
            if self._dropped <= 3 or self._dropped % 200 == 0:
                log.info("feed_packet: DROPPED (started=%s, dropped=%d)",
                         self._started, self._dropped)
            return
        if len(data) <= OUTER_HEADER_LEN:
            return

        payload = data[OUTER_HEADER_LEN:]
        self.packets_fed += 1

        # Feed to assembler
        frame_data = self._assembler.feed(payload)
        if frame_data is None:
            return

        # We have a complete frame — decode it
        self._decode_frame(frame_data)

    def _decode_frame(self, frame_data: bytes):
        """Decode an assembled frame.

        The drone sends headless JPEG: raw entropy-coded scan data without
        the JPEG file header (SOI, DQT, SOF, DHT, SOS markers). We prepend
        the Q10-specific JPEG header (single quant table for all channels)
        and append the EOI marker.
        """
        jpeg = _Q10_JPEG_HEADER + frame_data + b'\xff\xd9'
        frame = self._decode_jpeg(jpeg)
        if frame is not None:
            if self._decode_mode == 'unknown':
                self._decode_mode = 'headless_jpeg_q30_4:4:4_single_qt'
                log.info("Headless JPEG decode OK (single quant table, 1280x720 4:4:4)")
            return self._emit_frame(frame)

        if self._assembler.frames_assembled <= 3:
            log.warning("Failed to decode frame #%d (%d bytes, first 16: %s)",
                        self._assembler.frames_assembled, len(frame_data),
                        frame_data[:16].hex(' '))

    def _emit_frame(self, frame):
        """Push a decoded frame to the queue."""
        if frame.shape[1] != self.frame_width or frame.shape[0] != self.frame_height:
            frame = cv2.resize(frame, (self.frame_width, self.frame_height))

        with self._frame_lock:
            self._frame_queue.append(frame)

        self.frames_decoded += 1
        self.last_frame_time = time.time()
        self._frame_event.set()

        if self.frames_decoded == 1:
            log.info("First video frame decoded! (%dx%d, mode=%s)",
                     frame.shape[1], frame.shape[0], self._decode_mode)
        elif self.frames_decoded % 300 == 0:
            elapsed = time.time() - self._start_time
            avg_fps = self.frames_decoded / elapsed if elapsed > 0 else 0
            log.info("Video: %d frames decoded (avg %.1f fps, mode=%s)",
                     self.frames_decoded, avg_fps, self._decode_mode)

    def _decode_jpeg(self, data: bytes) -> Optional[np.ndarray]:
        """Try to decode data as JPEG."""
        try:
            arr = np.frombuffer(data, dtype=np.uint8)
            frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            return frame  # Returns None if decode fails
        except Exception:
            return None

    def get_frame(self) -> Optional[np.ndarray]:
        """Get the latest decoded frame (non-blocking). Returns None if no frame available."""
        with self._frame_lock:
            if self._frame_queue:
                return self._frame_queue[-1]
        return None

    def wait_frame(self, timeout: float = 1.0) -> Optional[np.ndarray]:
        """Wait for a new frame (blocking up to timeout seconds)."""
        self._frame_event.clear()
        self._frame_event.wait(timeout=timeout)
        return self.get_frame()

    @property
    def fps(self) -> float:
        """Estimated decode FPS based on recent frames."""
        if self.frames_decoded < 2 or self.last_frame_time == 0:
            return 0.0
        elapsed = time.time() - self.last_frame_time
        if elapsed > 2.0:
            return 0.0
        return min(30.0, self.frames_decoded / max(1, time.time() - self._start_time))
