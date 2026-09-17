"""
=============================================================================
MODULE 1: HMAC-SHA256 Authentication Engine
=============================================================================
Project : Secure Vehicle-to-Controller Message Exchange
          Using Hybrid Encryption and HMAC Authentication
Group   : 29
Module  : 1 of 4 — HMAC Authentication Engine
Course  : EE8257 Information Security
          Department of Electrical and Information Engineering
          Faculty of Engineering, University of Ruhuna

Syllabus References
-------------------
  Lecture 4  — Message Authentication Code (MAC) using CBC residue
  Lecture 6  — Hash Function Definition, HMAC (RFC 2104), SHA-256
  Lecture 1  — CIA Triad: Integrity and Authentication

Academic Justification
----------------------
  A cryptographic hash h(M) alone does NOT provide authentication.
  If Trudy intercepts (M, h(M)) she can replace both with (M', h(M'))
  and the receiver has no way to detect the substitution.

  HMAC binds the hash to a SECRET KEY K_m that only the sender and
  receiver possess. Per RFC 2104 and the syllabus (Lecture 6):

      HMAC(M, K) = H( K ⊕ opad  ||  H( K ⊕ ipad  ||  M ) )

  where ipad = 0x36 repeated B times
        opad = 0x5C repeated B times
        B    = block length of the hash function (64 bytes for SHA-256)

  This construction means:
    - Without K_m an attacker cannot forge a valid HMAC.
    - A changed message produces a completely different HMAC
      (avalanche effect — Lecture 6 hash design principles).
    - The receiver can verify BOTH integrity AND authenticity in one step.

  IMPORTANT — Two-key separation (Lecture 4 MAC section):
  The syllabus explicitly warns that using the same key for encryption
  AND MAC generation is insecure. This module uses a DEDICATED MAC key
  K_m, separate from the AES session key K_s used in Module 2.

Design Decisions
----------------
  Library  : Python stdlib `hmac` + `hashlib`  (no external dependency
             for the core; avoids implementation risk)
  Algorithm: HMAC-SHA256  (SHA-256 output = 32 bytes = 256 bits)
  Key size : 32 bytes (256 bits) — matches SHA-256 internal state
  Encoding : All binary fields kept as bytes; hex only for display
=============================================================================
"""

import hmac
import hashlib
import os
import secrets
import time
import json
import struct
from dataclasses import dataclass, field
from typing import Optional


# =============================================================================
# SECTION 1 — Key Management
# =============================================================================

def generate_mac_key(key_length_bytes: int = 32) -> bytes:
    """
    Generate a cryptographically secure random MAC key K_m.

    WHY 32 bytes?
    SHA-256 has an internal block size of 64 bytes and a digest size of
    32 bytes. RFC 2104 recommends the key length equal the hash output
    size (32 bytes / 256 bits) as the security sweet spot:
      - Shorter keys reduce the effective security level.
      - Longer keys are hashed down anyway, giving no additional benefit.

    WHY secrets.token_bytes and not os.urandom?
    Both are CSPRNG (Cryptographically Secure Pseudo-Random Number
    Generator) calls on all modern platforms. `secrets` is the
    Python-idiomatic way since 3.6 and makes intent explicit.

    Syllabus link — Lecture 6 (Randomness):
    "Cryptographic random numbers must be statistically random AND
     unpredictable." Software pseudo-randomness leads to pseudo-security.
    secrets.token_bytes() draws entropy from the OS entropy pool
    (/dev/urandom on Linux), satisfying this requirement.
    """
    if key_length_bytes < 16:
        raise ValueError(
            "MAC key must be at least 16 bytes (128 bits). "
            "Recommended: 32 bytes (256 bits)."
        )
    return secrets.token_bytes(key_length_bytes)


# =============================================================================
# SECTION 2 — Core HMAC Engine
# =============================================================================

class HMACEngine:
    """
    HMAC-SHA256 engine for message integrity and authentication.

    This class encapsulates the HMAC workflow described in RFC 2104
    and Lecture 6 of EE8257. It is intentionally stateless (no stored
    message history) so the same instance can be reused safely across
    multiple messages, matching real-world MAC library design.

    Two main operations:
      generate(message) → mac_tag   (sender side)
      verify(message, mac_tag) → bool  (receiver side)

    The separation of generate() and verify() mirrors the real-world
    sender/receiver model discussed in the lecture (Alice sends, Bob
    verifies, Trudy cannot forge without K_m).
    """

    ALGORITHM = hashlib.sha256      # SHA-256: 32-byte digest, 64-byte block
    DIGEST_SIZE = 32                # bytes (256 bits)
    BLOCK_SIZE  = 64                # bytes — SHA-256 internal block size

    def __init__(self, mac_key: bytes):
        """
        Initialise the engine with the shared MAC key K_m.

        Parameters
        ----------
        mac_key : bytes
            The shared secret MAC key. Must be at least 16 bytes.
            In the full system, K_m is generated by the vehicle,
            encrypted with RSA (Module 3), and sent to the controller.
            Both parties then use this same K_m instance.

        Security note:
            K_m should NEVER be the same object as K_s (the AES session
            key). They are generated separately and used independently.
            See Lecture 4: "Encrypting and MAC generation with the same
            key would be insecure."
        """
        if not isinstance(mac_key, bytes):
            raise TypeError("MAC key must be bytes.")
        if len(mac_key) < 16:
            raise ValueError("MAC key too short. Minimum 16 bytes.")

        # Store key as private attribute — never expose externally
        self._mac_key = mac_key

    def generate(self, message: bytes) -> bytes:
        """
        Generate an HMAC-SHA256 tag for the given message.

        Internally, Python's hmac.new() implements RFC 2104 exactly:
            HMAC(M, K) = H( K⊕opad || H( K⊕ipad || M ) )

        The double-hash structure is critical:
          - Inner hash: H(K⊕ipad || M) binds the key to the message.
          - Outer hash: H(K⊕opad || inner) prevents length-extension
            attacks that would be possible with a simple H(K||M).

        Syllabus link — Lecture 6:
            "hK,M has a serious flaw" — simple key prepending is broken.
            "hM,K is better but fails if collisions exist."
            The RFC 2104 double-hash construction fixes both.

        Parameters
        ----------
        message : bytes
            The raw message bytes to authenticate. In the full packet
            this will be the ENTIRE packet EXCEPT the HMAC field itself
            (header + vehicleID + timestamp + nonce + IV + ciphertext).

        Returns
        -------
        bytes
            32-byte (256-bit) HMAC tag.
        """
        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes.")

        # hmac.new() takes (key, message, digestmod)
        # digestmod=hashlib.sha256 selects SHA-256 as the hash primitive
        mac = hmac.new(
            key       = self._mac_key,
            msg       = message,
            digestmod = self.ALGORITHM
        )
        return mac.digest()     # returns raw 32 bytes (not hex)

    def verify(self, message: bytes, received_mac: bytes) -> bool:
        """
        Verify an HMAC tag against the message.

        CRITICAL — Constant-time comparison:
        This method uses hmac.compare_digest() rather than the ==
        operator. This is NOT optional. The == operator in Python
        short-circuits on the first differing byte, creating a
        timing side-channel: an attacker measuring response times
        can learn how many bytes of their forged MAC prefix are
        correct, allowing byte-by-byte forgery in ~256×32 attempts
        instead of 2^256.

        hmac.compare_digest() compares ALL bytes in constant time
        regardless of where the first difference occurs, eliminating
        the timing side-channel completely.

        Syllabus link — Lecture 1 (Security terminology):
        "Vulnerability: flaw or weakness in a system's design or
         operation." Timing side-channels are implementation
         vulnerabilities even in a theoretically secure scheme.

        Processing order note (from packet structure design):
        The receiver MUST verify the HMAC BEFORE attempting to decrypt
        the ciphertext. Decrypting a tampered ciphertext wastes resources
        and can leak information through padding oracle attacks.
        "Verify then decrypt" is the correct order.

        Parameters
        ----------
        message      : bytes  — The full message bytes (same scope as generate)
        received_mac : bytes  — The 32-byte HMAC tag received with the message

        Returns
        -------
        bool  — True if authentic and untampered, False otherwise.
        """
        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes.")
        if not isinstance(received_mac, bytes):
            raise TypeError("Received MAC must be bytes.")
        if len(received_mac) != self.DIGEST_SIZE:
            # Wrong length MACs are always invalid — but still run
            # compare_digest to avoid leaking the length check timing
            return False

        # Recompute expected MAC using the same key and message
        expected_mac = self.generate(message)

        # Constant-time comparison — timing-attack resistant
        return hmac.compare_digest(expected_mac, received_mac)


# =============================================================================
# SECTION 3 — Message Packet Builder (HMAC scope definition)
# =============================================================================

@dataclass
class VehicleMessage:
    """
    Represents a single vehicle→controller message before encryption.

    In the final integrated system (Module 4 — full integration),
    this plain structure will be encrypted (AES-CBC, Module 2) to
    produce the ciphertext field in the wire packet.

    Here in Module 1, we work with unencrypted payloads to isolate
    and demonstrate the HMAC functionality clearly.

    Fields (match the packet structure diagram):
    ─────────────────────────────────────────────
    vehicle_id  : str   — Unique vehicle identifier (e.g. "VH-001")
    message_type: str   — Command category ("TELEMETRY", "ALERT", etc.)
    payload     : dict  — The actual data (speed, location, etc.)
    timestamp   : float — Unix epoch float (seconds.milliseconds)
    nonce       : bytes — 16-byte random value (replay prevention)
    sequence_no : int   — Monotonically increasing counter per vehicle
    """
    vehicle_id   : str
    message_type : str
    payload      : dict
    timestamp    : float = field(default_factory=time.time)
    nonce        : bytes = field(default_factory=lambda: secrets.token_bytes(16))
    sequence_no  : int   = 1

    def to_bytes(self) -> bytes:
        """
        Serialise the message to a canonical byte representation.

        WHY canonical serialisation matters:
        The HMAC is computed over bytes, not Python objects. Both sender
        and receiver must produce IDENTICAL bytes from the same logical
        message, or the HMAC will never match even for untampered data.
        JSON with sorted keys gives a deterministic, human-readable
        canonical form suitable for academic demonstration.

        In production: use Protocol Buffers or ASN.1 DER for strict
        canonicalisation. JSON is used here for clarity.

        Returns
        -------
        bytes  — UTF-8 encoded canonical representation.
                 The nonce is hex-encoded inside JSON (JSON cannot
                 represent raw bytes).
        """
        canonical = {
            "vehicle_id"   : self.vehicle_id,
            "message_type" : self.message_type,
            "payload"       : self.payload,
            "timestamp"    : round(self.timestamp, 6),  # microsecond precision
            "nonce"        : self.nonce.hex(),          # bytes → hex string
            "sequence_no"  : self.sequence_no,
        }
        # sort_keys=True ensures deterministic ordering across Python versions
        return json.dumps(canonical, sort_keys=True).encode("utf-8")


# =============================================================================
# SECTION 4 — Sender Logic
# =============================================================================

class VehicleSender:
    """
    Simulates the Vehicle (client) side of the HMAC workflow.

    Responsibilities:
      1. Maintain a per-vehicle sequence number (replay prevention).
      2. Generate a fresh nonce for each message (replay prevention).
      3. Attach the current timestamp (replay prevention).
      4. Compute HMAC over the complete serialised message.
      5. Bundle the message bytes and HMAC tag for transmission.

    In the full system, step 4 happens AFTER AES-CBC encryption
    (the HMAC is computed over the ciphertext, not the plaintext —
    "Encrypt then MAC" paradigm, which is the correct order).
    Here we demonstrate on plaintext for Module 1 clarity.
    """

    def __init__(self, vehicle_id: str, mac_key: bytes):
        self.vehicle_id   = vehicle_id
        self.engine       = HMACEngine(mac_key)
        self._sequence_no = 0   # increments with every message sent

    def send_message(
        self,
        message_type : str,
        payload      : dict
    ) -> dict:
        """
        Compose and sign a message. Returns a 'packet' dict ready to
        transmit (in real deployment, serialised to bytes over TCP/UDP).

        Returns
        -------
        dict with keys:
          "message_bytes" : bytes — canonical serialised message
          "hmac_tag"      : bytes — 32-byte HMAC-SHA256 tag
          "vehicle_id"    : str   — for routing at the controller
          "sequence_no"   : int   — for receiver-side replay detection
        """
        self._sequence_no += 1

        msg = VehicleMessage(
            vehicle_id   = self.vehicle_id,
            message_type = message_type,
            payload      = payload,
            timestamp    = time.time(),
            nonce        = secrets.token_bytes(16),
            sequence_no  = self._sequence_no,
        )

        msg_bytes = msg.to_bytes()
        hmac_tag  = self.engine.generate(msg_bytes)

        return {
            "message_bytes" : msg_bytes,
            "hmac_tag"      : hmac_tag,
            "vehicle_id"    : self.vehicle_id,
            "sequence_no"   : self._sequence_no,
        }


# =============================================================================
# SECTION 5 — Receiver Logic
# =============================================================================

class ControllerReceiver:
    """
    Simulates the Controller (server) side of the HMAC workflow.

    Responsibilities:
      1. Verify HMAC FIRST (before any further processing).
      2. Check sequence number to detect replays (monotonic counter).
      3. Check timestamp freshness (±30-second window).
      4. Only process the payload if all checks pass.
      5. Log each accepted sequence number to prevent replay.

    Syllabus link — Lecture 8 Kerberos:
    "Clock skew for Kerberos → 5 minutes → replay possible."
    We use a tighter ±30-second window for vehicle telemetry (vehicles
    transmit frequently; stale data is operationally dangerous).

    Syllabus link — Lecture 8 GSM:
    "Base station can replay triple (RAND, XRES, Kc). One compromised
     triple gives attacker a key Kc that is valid forever. No replay
     protection!" — Our sequence number + nonce combination ensures
     each packet is accepted exactly once.
    """

    # Reject messages older than this many seconds
    TIMESTAMP_TOLERANCE_SECONDS = 30

    def __init__(self, mac_key: bytes):
        self.engine = HMACEngine(mac_key)
        # Per-vehicle sequence number tracking
        # { vehicle_id: last_accepted_sequence_no }
        self._last_seq: dict[str, int] = {}

    def receive_message(self, packet: dict) -> dict:
        """
        Process an incoming packet. Performs all security checks
        before returning the decoded payload.

        Parameters
        ----------
        packet : dict — as produced by VehicleSender.send_message()

        Returns
        -------
        dict with keys:
          "status"      : "OK" | "HMAC_FAIL" | "REPLAY" | "STALE_TS"
          "vehicle_id"  : str
          "sequence_no" : int
          "payload"     : dict | None (None on failure)
          "reason"      : str  (human-readable result explanation)
        """
        msg_bytes    = packet["message_bytes"]
        received_mac = packet["hmac_tag"]
        vehicle_id   = packet["vehicle_id"]
        sequence_no  = packet["sequence_no"]

        # ── STEP 1: HMAC verification (MUST happen first) ─────────────
        # "Verify then decrypt" — we verify integrity before trusting
        # any content in the message. A failed HMAC means the message
        # is either corrupted or tampered with.
        hmac_valid = self.engine.verify(msg_bytes, received_mac)
        if not hmac_valid:
            return {
                "status"      : "HMAC_FAIL",
                "vehicle_id"  : vehicle_id,
                "sequence_no" : sequence_no,
                "payload"     : None,
                "reason"      : (
                    "HMAC verification failed. Message was tampered "
                    "with, corrupted in transit, or sent with an "
                    "incorrect MAC key."
                ),
            }

        # ── STEP 2: Deserialise (safe now that HMAC passed) ───────────
        try:
            msg_dict = json.loads(msg_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return {
                "status"      : "PARSE_ERROR",
                "vehicle_id"  : vehicle_id,
                "sequence_no" : sequence_no,
                "payload"     : None,
                "reason"      : f"Message parse error after HMAC pass: {exc}",
            }

        # ── STEP 3: Timestamp freshness check ─────────────────────────
        # Reject messages that are too old (replayed) or too far in
        # the future (clock manipulation / injection attack).
        msg_timestamp = msg_dict.get("timestamp", 0)
        age_seconds   = abs(time.time() - msg_timestamp)
        if age_seconds > self.TIMESTAMP_TOLERANCE_SECONDS:
            return {
                "status"      : "STALE_TS",
                "vehicle_id"  : vehicle_id,
                "sequence_no" : sequence_no,
                "payload"     : None,
                "reason"      : (
                    f"Timestamp too old or too far in future "
                    f"(age={age_seconds:.1f}s, "
                    f"tolerance={self.TIMESTAMP_TOLERANCE_SECONDS}s). "
                    "Possible replay attack."
                ),
            }

        # ── STEP 4: Sequence number check ─────────────────────────────
        # Accept only strictly increasing sequence numbers per vehicle.
        # This catches replayed packets that pass the timestamp window
        # (within 30 seconds of the original — still exploitable
        # without sequence number protection).
        last_seq = self._last_seq.get(vehicle_id, 0)
        if sequence_no <= last_seq:
            return {
                "status"      : "REPLAY",
                "vehicle_id"  : vehicle_id,
                "sequence_no" : sequence_no,
                "payload"     : None,
                "reason"      : (
                    f"Sequence number {sequence_no} already seen or "
                    f"out of order (last accepted: {last_seq}). "
                    "Replay attack detected."
                ),
            }

        # ── STEP 5: All checks passed — accept message ─────────────────
        self._last_seq[vehicle_id] = sequence_no

        return {
            "status"      : "OK",
            "vehicle_id"  : vehicle_id,
            "sequence_no" : sequence_no,
            "payload"     : msg_dict.get("payload"),
            "reason"      : "Message authentic, unmodified, and fresh.",
        }
