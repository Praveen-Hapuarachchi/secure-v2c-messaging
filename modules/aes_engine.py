"""
=============================================================================
MODULE 2: AES-256-CBC Encryption Engine
=============================================================================
Project : Secure Vehicle-to-Controller Message Exchange
          Using Hybrid Encryption and HMAC Authentication
Group   : 29
Module  : 2 of 4 — AES-256-CBC Encryption Engine
Course  : EE8257 Information Security
          Department of Electrical and Information Engineering
          Faculty of Engineering, University of Ruhuna

Syllabus References
-------------------
  Lecture 4  — Block Ciphers: AES, DES comparison, CBC vs ECB modes
  Lecture 1  — CIA Triad: Confidentiality
  Lecture 6  — HMAC integration (Encrypt-then-MAC ordering)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  WHY AES REPLACED DES — Academic Background (Lecture 4)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  DES (Data Encryption Standard, 1977):
    - 56-bit key → 2^56 ≈ 72 trillion possible keys
    - 1998: EFF "Deep Crack" machine cracked DES in 22 hours for $250,000
    - 1999: Distributed.net + Deep Crack cracked DES in 22 HOURS
    - Conclusion: 56-bit key space is computationally feasible to exhaust

  3DES (Triple-DES) was a stopgap:
    - Applies DES three times: E(D(E(M, K1), K2), K3)
    - Effective 112-bit key — secure but 3× slower than DES
    - Block size still only 64 bits → birthday attacks beyond 32GB data

  AES (Advanced Encryption Standard, 2001 — Rijndael algorithm):
    - NIST ran an open international competition (1997–2001)
    - Rijndael selected: designed by Belgian cryptographers Joan Daemen
      and Vincent Rijmen
    - Key sizes: 128, 192, or 256 bits (we use 256)
    - Block size: 128 bits (16 bytes) — fixed
    - Structure: Substitution-Permutation Network (NOT Feistel like DES)

  AES-256 key space: 2^256 ≈ 1.16 × 10^77
    - The observable universe contains ~10^80 atoms
    - Even with 10^15 decryptions/second it would take 10^51 years
    - Brute force is computationally infeasible for any foreseeable future

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AES INTERNALS — Four Operations Per Round (Lecture 4)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  AES-256 performs 14 rounds. Each round (except the last) applies:

  1. SubBytes  — Non-linear substitution via an S-box (4 S-boxes in
                 the lecture, 1 fixed S-box in AES). Provides confusion:
                 "complex relationship between key and ciphertext" (Shannon)
  2. ShiftRows — Cyclic shift of rows in the 4×4 state matrix.
                 Provides diffusion at byte level.
  3. MixColumns— Matrix multiplication over GF(2^8). Every output byte
                 depends on all 4 input bytes of the column.
                 Provides diffusion at bit level.
  4. AddRoundKey— XOR with 256-bit round key (derived from main key
                 via key schedule). This is the only step where the key
                 enters the computation.

  The combination of SubBytes (confusion) and MixColumns+ShiftRows
  (diffusion) implements Shannon's (1949) two design principles,
  cited explicitly in the Lecture 4 notes.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ECB vs CBC — WHY MODE MATTERS (Lecture 4)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ECB (Electronic Codebook) — NEVER USE:
    - Each 16-byte block encrypted independently with the same key
    - Identical plaintext blocks → identical ciphertext blocks
    - Structural patterns in the plaintext survive into ciphertext
    - The "ECB penguin" — encrypting a bitmap image with ECB produces
      a recognisable silhouette of the original image
    - Cut-and-paste attacks: attacker rearranges ciphertext blocks
      to rearrange plaintext without knowing the key
    - Lecture 4: ECB identified as the insecure mode to avoid

  CBC (Cipher Block Chaining) — CORRECT CHOICE:
    - Before encrypting block i, XOR it with ciphertext block i-1
    - First block is XORed with the Initialisation Vector (IV)
    - Formula:
        C[0] = E( P[0] ⊕ IV,  K )
        C[i] = E( P[i] ⊕ C[i-1],  K )
    - Identical plaintext blocks produce different ciphertext
      (because each block depends on all previous ciphertext)
    - Semantic security: even if the attacker knows P[i] and C[i],
      they learn nothing about P[j] for j ≠ i
    - Error propagation: a 1-bit error in C[i] corrupts blocks i and i+1
      (relevant for integrity design — use HMAC to catch this)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  IV (INITIALISATION VECTOR) — WHY IT EXISTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Without an IV, encrypting the same first block P[0] with the same key
  ALWAYS produces the same C[0]. An attacker watching traffic could
  detect that the same message (or message prefix) is being sent.

  IV requirements:
    - 16 bytes (128 bits) — same as AES block size
    - MUST be random and unpredictable (use CSPRNG)
    - MUST be unique per message (never reuse an IV with the same key)
    - Does NOT need to be secret — transmitted in plaintext alongside
      the ciphertext, but must be authenticated (included in HMAC scope)

  IV reuse catastrophe:
    If IV₁ = IV₂ and both messages share the key K:
        C1[0] = E(P1[0] ⊕ IV, K)
        C2[0] = E(P2[0] ⊕ IV, K)
        C1[0] ⊕ C2[0] = P1[0] ⊕ P2[0]   ← plaintext XOR leaks!
    This is the same vulnerability as OTP key reuse (Lecture 3).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PKCS7 PADDING — WHY IT IS NEEDED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  AES is a BLOCK cipher — it operates on exactly 128-bit (16-byte)
  blocks. Vehicle telemetry messages are variable length. We must pad
  the plaintext to a multiple of 16 bytes before encrypting.

  PKCS7 rule: append N bytes, each with value N.
    Message length 13 → need 3 more bytes → append 0x03 0x03 0x03
    Message length 16 → need a full extra block → append 0x10 ×16
    Message length 20 → need 12 more bytes → append 0x0C ×12

  The last case (full extra block) is mandatory — if you skip padding
  when the message is already block-aligned, the unpadding algorithm
  cannot distinguish padding from data on decryption. PKCS7 always
  adds at least 1 byte, so unpadding is always unambiguous.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ENCRYPT-THEN-MAC — THE CORRECT INTEGRATION ORDER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Three orderings exist. Only one is secure:

  1. Encrypt-then-MAC (EtM) ← THIS PROJECT ← CORRECT
       Sender: C = AES-CBC(P, K_s, IV)
               T = HMAC(IV || C, K_m)        ← MAC over ciphertext
       Receiver: verify T first → then decrypt C
       WHY: The receiver never touches a decryption oracle with
            untrusted input. Padding oracle attacks are impossible.
            TLS 1.3, IPSec ESP all use EtM.

  2. MAC-then-Encrypt (MtE) — used in TLS 1.2, now deprecated
       Sender: T = HMAC(P, K_m)
               C = AES-CBC(P || T, K_s, IV)
       WHY BAD: Decryption must happen before MAC verification.
                This exposes the padding oracle. POODLE attack (2014)
                exploited this exact flaw in SSL 3.0.

  3. Encrypt-and-MAC (E&M) — used in SSH, not recommended
       Sender: C = AES-CBC(P, K_s, IV)
               T = HMAC(P, K_m)          ← MAC over PLAINTEXT
       WHY BAD: The MAC leaks information about the plaintext (HMAC
                output correlates with plaintext structure).

  Our choice: Encrypt-then-MAC. Academically justified, syllabus-
  aligned, and matches modern secure protocol design (TLS 1.3, IPSec).
=============================================================================
"""

import os
import secrets
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as crypto_padding
from cryptography.hazmat.backends import default_backend

# Import Module 1 HMAC engine for Encrypt-then-MAC integration
from modules.hmac_engine import HMACEngine, generate_mac_key


# =============================================================================
# CONSTANTS — AES-256-CBC parameters
# =============================================================================

AES_KEY_SIZE   = 32      # bytes → 256 bits (AES-256)
AES_BLOCK_SIZE = 16      # bytes → 128 bits (AES fixed block size)
IV_SIZE        = 16      # bytes → 128 bits (must equal block size for CBC)
PKCS7_BITS     = 128     # PKCS7 padding block size in bits (= AES_BLOCK_SIZE × 8)


# =============================================================================
# SECTION 1 — Key Generation
# =============================================================================

def generate_aes_key(key_length_bytes: int = AES_KEY_SIZE) -> bytes:
    """
    Generate a cryptographically secure random AES session key K_s.

    Key length options:
      16 bytes → AES-128 (acceptable, 128-bit security)
      24 bytes → AES-192 (rarely used)
      32 bytes → AES-256 (our choice — highest security margin)

    WHY 32 bytes?
    Lecture 4 discusses that DES's 56-bit key was broken by exhaustive
    search. AES-256 provides a 2^256 key space — effectively infinite
    with current and foreseeable computing power, including quantum
    computers (Grover's algorithm halves effective key bits to 128,
    which is still computationally infeasible).

    This key (K_s) is NEVER the same object as the HMAC key (K_m).
    Both are generated independently and transmitted separately inside
    the RSA-encrypted handshake package (Module 3).

    Parameters
    ----------
    key_length_bytes : int
        Must be 16, 24, or 32. Defaults to 32 (AES-256).
    """
    if key_length_bytes not in (16, 24, 32):
        raise ValueError(
            f"Invalid AES key length: {key_length_bytes}. "
            "Must be 16 (AES-128), 24 (AES-192), or 32 (AES-256)."
        )
    return secrets.token_bytes(key_length_bytes)


def generate_iv() -> bytes:
    """
    Generate a fresh cryptographically random 16-byte IV.

    This function is called ONCE PER MESSAGE — never reused.
    The IV is not secret and is transmitted alongside the ciphertext,
    but it MUST be included in the HMAC scope to prevent IV-swapping
    attacks (Lecture 4 CBC chaining discussion).

    IV swapping attack:
      If the IV is not authenticated, Trudy can flip bits in the IV
      to predictably flip bits in the first decrypted plaintext block.
      Including the IV in HMAC(IV || ciphertext) prevents this.

    Returns
    -------
    bytes : 16 cryptographically random bytes.
    """
    return secrets.token_bytes(IV_SIZE)


# =============================================================================
# SECTION 2 — Low-Level AES-CBC Primitives
# =============================================================================

def _pkcs7_pad(data: bytes) -> bytes:
    """
    Apply PKCS7 padding to make data a multiple of 16 bytes.

    PKCS7 rule:
      Let n = 16 - (len(data) % 16)
      Append n bytes each with value n.
      If len(data) is already a multiple of 16, append a full 16-byte
      block of value 0x10 (16).

    Examples:
      data length 13 → n=3  → append b'\\x03\\x03\\x03'
      data length 16 → n=16 → append b'\\x10' × 16
      data length 20 → n=12 → append b'\\x0c' × 12

    The padder from the `cryptography` library implements PKCS7
    correctly, including the mandatory full-block case.
    """
    padder = crypto_padding.PKCS7(PKCS7_BITS).padder()
    return padder.update(data) + padder.finalize()


def _pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS7 padding after decryption.

    Reads the last byte N, then strips the trailing N bytes.
    Raises ValueError if padding is malformed (wrong byte values),
    which indicates either decryption with a wrong key or data
    corruption.

    IMPORTANT: unpadding is called ONLY after HMAC verification passes.
    If an attacker sends malformed ciphertext and we decrypt without
    verifying HMAC first, the padding error response itself becomes
    an oracle (padding oracle attack — POODLE, Lucky13, BEAST).
    The Encrypt-then-MAC design in this module prevents this entirely.
    """
    unpadder = crypto_padding.PKCS7(PKCS7_BITS).unpadder()
    try:
        return unpadder.update(data) + unpadder.finalize()
    except Exception as exc:
        # Re-raise with a project-specific message for clarity
        raise ValueError(
            f"PKCS7 unpadding failed — wrong key, corrupted data, "
            f"or decryption attempted before HMAC verification: {exc}"
        )


def _aes_cbc_encrypt_raw(plaintext_padded: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Raw AES-CBC encryption of pre-padded plaintext.

    The `cryptography` library (PyCA) is used rather than implementing
    AES manually. Reason: implementing AES from scratch introduces
    timing side-channels, cache side-channels (cache-timing attacks
    on S-box lookups), and implementation bugs. Production systems
    always use vetted, audited implementations.

    The Cipher object is created fresh for each message (not reused)
    to ensure the CBC chaining state is always reset. Reusing a Cipher
    object would continue the chain from the previous ciphertext,
    which would break the IV-per-message design.

    Parameters
    ----------
    plaintext_padded : bytes — plaintext after PKCS7 padding
    key              : bytes — 32-byte AES-256 session key K_s
    iv               : bytes — 16-byte random IV for this message

    Returns
    -------
    bytes : raw ciphertext (same length as padded plaintext)
    """
    if len(plaintext_padded) % AES_BLOCK_SIZE != 0:
        raise ValueError(
            "Plaintext must be padded to a 16-byte boundary before "
            "calling _aes_cbc_encrypt_raw. Call _pkcs7_pad() first."
        )
    cipher     = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor  = cipher.encryptor()
    return encryptor.update(plaintext_padded) + encryptor.finalize()


def _aes_cbc_decrypt_raw(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Raw AES-CBC decryption. Returns PKCS7-padded plaintext.

    The caller is responsible for calling _pkcs7_unpad() on the result.
    This separation exists so callers can inspect the padded plaintext
    if needed (e.g., for debugging or logging without stripping padding).

    SECURITY NOTE: This function MUST only be called AFTER HMAC
    verification has passed. The function itself cannot enforce this
    — it is enforced by the AESEngine.decrypt() method, which calls
    HMAC verify before calling this function.
    """
    if len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError(
            f"Ciphertext length {len(ciphertext)} is not a multiple "
            f"of the AES block size (16 bytes). Packet is malformed."
        )
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# =============================================================================
# SECTION 3 — AES Engine (High-Level Interface)
# =============================================================================

@dataclass
class EncryptedPacket:
    """
    Wire-format representation of a single encrypted vehicle message.

    Fields align with the packet structure designed in the architecture
    session. All fields are bytes. The HMAC tag covers all other fields
    combined (Encrypt-then-MAC).

    Layout (matches the packet diagram):
    ┌─────────┬──────────┬────────────┬───────────┬────────────┬──────┐
    │ IV      │ seq_no   │ timestamp  │ vehicle_id│ ciphertext │ hmac │
    │ 16 B    │ 4 B      │ 8 B        │ var.      │ var.       │ 32 B │
    └─────────┴──────────┴────────────┴───────────┴────────────┴──────┘
    HMAC covers: IV + seq_no + timestamp + vehicle_id + ciphertext

    Serialised to bytes using a simple length-prefixed format for
    transmission over the socket layer (Module 4).
    """
    iv           : bytes        # 16 bytes — AES-CBC initialisation vector
    ciphertext   : bytes        # variable — AES-CBC encrypted payload
    hmac_tag     : bytes        # 32 bytes — HMAC-SHA256 over iv+ciphertext+meta
    vehicle_id   : bytes        # variable — UTF-8 encoded vehicle identifier
    sequence_no  : int          # 4 bytes  — monotonic replay counter
    timestamp    : float        # 8 bytes  — Unix epoch for freshness check

    def to_bytes(self) -> bytes:
        """
        Serialise the full packet to a flat byte string for transmission.

        Format (length-prefixed fields):
          [iv_len:2][iv][ct_len:4][ciphertext][mac_len:2][hmac_tag]
          [vid_len:2][vehicle_id][seq_no:4][timestamp:8]

        This is a simplified TLV (Type-Length-Value) encoding.
        In production, use Protocol Buffers or ASN.1 DER.
        """
        import struct
        ts_bytes = struct.pack('>d', self.timestamp)   # big-endian double
        sq_bytes = struct.pack('>I', self.sequence_no) # big-endian uint32

        parts = [
            struct.pack('>H', len(self.iv)),           self.iv,
            struct.pack('>I', len(self.ciphertext)),   self.ciphertext,
            struct.pack('>H', len(self.hmac_tag)),     self.hmac_tag,
            struct.pack('>H', len(self.vehicle_id)),   self.vehicle_id,
            sq_bytes,
            ts_bytes,
        ]
        return b''.join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'EncryptedPacket':
        """Deserialise a packet from its wire-format byte string."""
        import struct
        offset = 0

        def read(n: int) -> bytes:
            nonlocal offset
            chunk = data[offset:offset + n]
            if len(chunk) != n:
                raise ValueError(f"Packet truncated at offset {offset}")
            offset += n
            return chunk

        iv_len    = struct.unpack('>H', read(2))[0]
        iv        = read(iv_len)
        ct_len    = struct.unpack('>I', read(4))[0]
        ct        = read(ct_len)
        mac_len   = struct.unpack('>H', read(2))[0]
        mac       = read(mac_len)
        vid_len   = struct.unpack('>H', read(2))[0]
        vid       = read(vid_len)
        seq_no    = struct.unpack('>I', read(4))[0]
        timestamp = struct.unpack('>d', read(8))[0]

        return cls(
            iv=iv, ciphertext=ct, hmac_tag=mac,
            vehicle_id=vid, sequence_no=seq_no, timestamp=timestamp
        )

    def hmac_scope(self) -> bytes:
        """
        Return the byte string that HMAC covers.

        The HMAC scope is: IV || ciphertext || vehicle_id || seq_no || timestamp
        (everything except the HMAC tag itself).

        WHY include the IV?
        If the IV is not authenticated, an attacker can flip bits in the
        IV to predictably flip bits in the first decrypted plaintext block
        without invalidating the ciphertext HMAC. Including the IV in the
        HMAC scope prevents IV-swap / IV-bit-flip attacks.

        WHY include vehicle_id and seq_no?
        To prevent cross-vehicle packet injection and replay. If these
        fields are not authenticated, an attacker can change them after
        the vehicle signs the packet.
        """
        import struct
        return (
            self.iv
            + self.ciphertext
            + self.vehicle_id
            + struct.pack('>I', self.sequence_no)
            + struct.pack('>d', self.timestamp)
        )


class AESEngine:
    """
    AES-256-CBC encryption engine with integrated HMAC-SHA256
    (Encrypt-then-MAC).

    Design principles:
      • One instance per session (holds K_s and K_m).
      • encrypt() always generates a fresh random IV.
      • decrypt() always verifies HMAC BEFORE attempting decryption.
      • Keys are stored as private attributes; never exposed externally.
      • Stateless regarding message content — state (seq no.) is managed
        by the sender/receiver wrappers below.

    Syllabus alignment:
      Lecture 4: AES-256-CBC with PKCS7 padding.
      Lecture 6: HMAC-SHA256 for integrity and authentication.
      Lecture 1: Confidentiality (AES) + Integrity (HMAC) together
                 satisfy two of the three CIA triad goals.
    """

    def __init__(self, aes_key: bytes, mac_key: bytes):
        """
        Initialise engine with separate encryption and MAC keys.

        Parameters
        ----------
        aes_key : bytes — K_s, the AES-256 session key (32 bytes).
        mac_key : bytes — K_m, the HMAC-SHA256 MAC key (32 bytes).

        KEY SEPARATION RULE (Lecture 4 MAC discussion):
        K_s ≠ K_m. These are generated independently in the vehicle's
        key generation step and transmitted together in the RSA-encrypted
        handshake packet (Module 3). Using the same key for both
        encryption and MAC would allow attacks that leverage relationships
        between the two operations. Strict separation is enforced here
        by type-checking and by the independent generation functions.
        """
        if not isinstance(aes_key, bytes) or len(aes_key) not in (16, 24, 32):
            raise ValueError(
                f"AES key must be 16, 24, or 32 bytes. Got {len(aes_key)}."
            )
        if not isinstance(mac_key, bytes) or len(mac_key) < 16:
            raise ValueError("MAC key must be at least 16 bytes.")
        if aes_key == mac_key:
            raise ValueError(
                "AES key and MAC key MUST be different. "
                "Using the same key for encryption and authentication "
                "is cryptographically insecure. See Lecture 4."
            )

        self._aes_key    = aes_key
        self._hmac_engine = HMACEngine(mac_key)

    # ── PUBLIC INTERFACE ────────────────────────────────────────────────────

    def encrypt(
        self,
        plaintext   : bytes,
        vehicle_id  : str,
        sequence_no : int,
        timestamp   : Optional[float] = None,
    ) -> EncryptedPacket:
        """
        Encrypt a plaintext payload and attach an HMAC tag.

        WORKFLOW (Encrypt-then-MAC):
          1. Generate a fresh random 16-byte IV (never reused).
          2. Apply PKCS7 padding to make plaintext a multiple of 16 B.
          3. AES-CBC encrypt the padded plaintext.
          4. Assemble the EncryptedPacket (without HMAC yet).
          5. Compute HMAC-SHA256 over the packet's HMAC scope.
          6. Attach the HMAC tag to the packet and return.

        The plaintext is NEVER transmitted. Only IV + ciphertext +
        HMAC + metadata cross the network.

        Parameters
        ----------
        plaintext   : bytes — raw message content (typically JSON-encoded
                              VehicleMessage payload from Module 1)
        vehicle_id  : str   — unique vehicle identifier
        sequence_no : int   — monotonically increasing per-vehicle counter
        timestamp   : float — Unix epoch (defaults to now)

        Returns
        -------
        EncryptedPacket — ready for wire transmission
        """
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes.")
        if len(plaintext) == 0:
            raise ValueError("Cannot encrypt empty plaintext.")

        ts = timestamp if timestamp is not None else time.time()

        # ── Step 1: Fresh random IV ────────────────────────────────────
        # Every message gets its own IV. Reusing an IV with the same
        # key leaks plaintext XOR information (demonstrated in demo).
        iv = generate_iv()

        # ── Step 2: PKCS7 padding ──────────────────────────────────────
        padded = _pkcs7_pad(plaintext)

        # ── Step 3: AES-CBC encryption ─────────────────────────────────
        ciphertext = _aes_cbc_encrypt_raw(padded, self._aes_key, iv)

        # ── Step 4: Build packet (HMAC field empty for now) ────────────
        vid_bytes = vehicle_id.encode('utf-8')
        packet = EncryptedPacket(
            iv          = iv,
            ciphertext  = ciphertext,
            hmac_tag    = b'',          # filled in step 5
            vehicle_id  = vid_bytes,
            sequence_no = sequence_no,
            timestamp   = ts,
        )

        # ── Step 5: Compute HMAC over scope (Encrypt-then-MAC) ─────────
        # The HMAC scope = IV || ciphertext || vehicle_id || seq || ts
        # This authenticates the ciphertext AND all metadata fields.
        hmac_tag = self._hmac_engine.generate(packet.hmac_scope())
        packet.hmac_tag = hmac_tag

        return packet

    def decrypt(self, packet: EncryptedPacket) -> bytes:
        """
        Verify HMAC and decrypt an EncryptedPacket.

        WORKFLOW (verify-then-decrypt, EtM):
          1. Verify HMAC over the packet scope. REJECT if invalid.
          2. Validate structural constraints (IV length, ciphertext
             length multiple of block size).
          3. AES-CBC decrypt the ciphertext.
          4. Remove PKCS7 padding.
          5. Return the original plaintext.

        CRITICAL ORDER: HMAC FIRST, DECRYPT SECOND.
        This ordering is non-negotiable. Decrypting before verifying
        exposes the padding oracle attack surface. The POODLE attack
        (2014) exploited exactly this flaw in SSL 3.0 MAC-then-Encrypt.

        Parameters
        ----------
        packet : EncryptedPacket — received from the network

        Returns
        -------
        bytes : original plaintext

        Raises
        ------
        ValueError : if HMAC fails, IV is malformed, ciphertext is
                     malformed, or padding is corrupt.
        """
        # ── Step 1: HMAC verification (MUST be first) ──────────────────
        hmac_valid = self._hmac_engine.verify(
            packet.hmac_scope(),
            packet.hmac_tag
        )
        if not hmac_valid:
            raise ValueError(
                "HMAC verification failed. Message rejected. "
                "Possible causes: tampering, corruption, wrong MAC key, "
                "or IV/metadata modification. DO NOT decrypt."
            )

        # ── Step 2: Structural validation ──────────────────────────────
        if len(packet.iv) != IV_SIZE:
            raise ValueError(
                f"Invalid IV length: {len(packet.iv)} bytes. "
                f"Expected {IV_SIZE} bytes."
            )
        if len(packet.ciphertext) == 0:
            raise ValueError("Ciphertext is empty.")
        if len(packet.ciphertext) % AES_BLOCK_SIZE != 0:
            raise ValueError(
                f"Ciphertext length ({len(packet.ciphertext)}) is not "
                f"a multiple of the AES block size ({AES_BLOCK_SIZE})."
            )

        # ── Step 3: AES-CBC decryption ─────────────────────────────────
        padded_plaintext = _aes_cbc_decrypt_raw(
            packet.ciphertext,
            self._aes_key,
            packet.iv
        )

        # ── Step 4: Remove PKCS7 padding ───────────────────────────────
        plaintext = _pkcs7_unpad(padded_plaintext)

        return plaintext


# =============================================================================
# SECTION 4 — ECB Mode (for comparison demonstration ONLY)
# =============================================================================

class ECBDemoEngine:
    """
    ECB mode encryption — included ONLY for comparison demonstration.

    !!  DO NOT USE ECB IN ANY REAL SYSTEM  !!

    ECB is provided here to demonstrate:
      (a) Identical plaintext blocks → identical ciphertext blocks
      (b) Pattern leakage in structured messages
      (c) Cut-and-paste block rearrangement vulnerability

    This is the insecure mode explicitly discussed in Lecture 4 as
    the mode to AVOID. It is the "textbook wrong answer" to mode
    selection. Including it here allows the demo to visually contrast
    ECB pattern leakage vs CBC confidentiality.
    """

    def __init__(self, aes_key: bytes):
        if len(aes_key) not in (16, 24, 32):
            raise ValueError("Invalid AES key length.")
        self._key = aes_key

    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        """Encrypt using ECB mode — for DEMONSTRATION OF WEAKNESS ONLY."""
        padded    = _pkcs7_pad(plaintext)
        cipher    = Cipher(
            algorithms.AES(self._key),
            modes.ECB(),                     # ← insecure mode
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(padded) + encryptor.finalize()

    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """Decrypt using ECB mode — for DEMONSTRATION ONLY."""
        cipher    = Cipher(
            algorithms.AES(self._key),
            modes.ECB(),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded    = decryptor.update(ciphertext) + decryptor.finalize()
        return _pkcs7_unpad(padded)


# =============================================================================
# SECTION 5 — Sender / Receiver wrappers (integrate Module 1 pattern)
# =============================================================================

class VehicleEncryptor:
    """
    Vehicle-side encrypted message sender.

    Manages the per-vehicle sequence number and delegates encryption
    to AESEngine. Produces EncryptedPacket objects ready for wire
    transmission. Mirrors the VehicleSender design from Module 1 but
    now produces encrypted packets instead of plaintext-with-HMAC.

    In the full system (Module 4), this class's output is serialised
    to bytes and sent over a TCP socket to the controller.
    """

    def __init__(self, vehicle_id: str, aes_key: bytes, mac_key: bytes):
        self.vehicle_id   = vehicle_id
        self._engine      = AESEngine(aes_key, mac_key)
        self._sequence_no = 0

    def send(self, payload: dict) -> EncryptedPacket:
        """
        Encrypt and sign a payload dict, returning a transmission-ready packet.

        Parameters
        ----------
        payload : dict — any JSON-serialisable message data

        Returns
        -------
        EncryptedPacket — encrypted, authenticated, with fresh IV
        """
        self._sequence_no += 1
        plaintext = json.dumps(payload, sort_keys=True).encode('utf-8')
        return self._engine.encrypt(
            plaintext   = plaintext,
            vehicle_id  = self.vehicle_id,
            sequence_no = self._sequence_no,
        )

    @property
    def sequence_no(self) -> int:
        return self._sequence_no


class ControllerDecryptor:
    """
    Controller-side decryption and verification handler.

    Manages per-vehicle sequence number tracking to detect replays.
    Decryption is performed only after HMAC passes AND freshness
    checks (timestamp + sequence number) are satisfied.

    The ±30-second timestamp window and monotonic sequence counter
    replicate the replay protection design from Module 1, now applied
    at the encrypted-packet level.
    """

    TIMESTAMP_TOLERANCE = 30   # seconds (same as Module 1)

    def __init__(self, aes_key: bytes, mac_key: bytes):
        self._engine    = AESEngine(aes_key, mac_key)
        self._last_seq  : dict[str, int] = {}  # { vehicle_id: last_seq }

    def receive(self, packet: EncryptedPacket) -> dict:
        """
        Verify, replay-check, and decrypt an incoming EncryptedPacket.

        Processing order:
          1. HMAC verification (inside AESEngine.decrypt — first thing)
          2. Timestamp freshness check
          3. Sequence number monotonic check
          4. AES-CBC decryption (only if all above pass)
          5. JSON deserialisation of plaintext payload

        Returns
        -------
        dict with:
          "status"  : "OK" | "HMAC_FAIL" | "REPLAY" | "STALE_TS" | "ERROR"
          "payload" : dict | None
          "reason"  : str
        """
        vid = packet.vehicle_id.decode('utf-8', errors='replace')

        # ── Timestamp check ────────────────────────────────────────────
        age = abs(time.time() - packet.timestamp)
        if age > self.TIMESTAMP_TOLERANCE:
            return {
                "status" : "STALE_TS",
                "payload": None,
                "reason" : (
                    f"Packet timestamp too old/future "
                    f"(age={age:.1f}s > {self.TIMESTAMP_TOLERANCE}s). "
                    "Replay or clock-manipulation attack suspected."
                )
            }

        # ── Sequence number check ──────────────────────────────────────
        last = self._last_seq.get(vid, 0)
        if packet.sequence_no <= last:
            return {
                "status" : "REPLAY",
                "payload": None,
                "reason" : (
                    f"Seq {packet.sequence_no} ≤ last accepted "
                    f"{last} for vehicle {vid}. Replay detected."
                )
            }

        # ── HMAC + Decryption (AESEngine enforces EtM order) ──────────
        try:
            plaintext = self._engine.decrypt(packet)
        except ValueError as exc:
            return {
                "status" : "HMAC_FAIL",
                "payload": None,
                "reason" : str(exc),
            }

        # ── Accept ─────────────────────────────────────────────────────
        self._last_seq[vid] = packet.sequence_no
        try:
            payload = json.loads(plaintext.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return {
                "status" : "ERROR",
                "payload": None,
                "reason" : f"Decryption succeeded but JSON parse failed: {exc}"
            }

        return {
            "status" : "OK",
            "payload": payload,
            "reason" : "Decryption and verification successful.",
        }
