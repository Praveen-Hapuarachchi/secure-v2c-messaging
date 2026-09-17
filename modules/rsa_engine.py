"""
=============================================================================
MODULE 3: RSA Handshake & Secure Session Key Exchange Engine
=============================================================================
Project : Secure Vehicle-to-Controller Message Exchange
          Using Hybrid Encryption and HMAC Authentication
Group   : 29  |  Module : 3 of 4  |  Course : EE8257 Information Security

Syllabus References
-------------------
  Lecture 5  — RSA key generation, encryption/decryption, cube root
               attack, OAEP padding, digital signatures, DH MitM attack
  Lecture 2  — Modular arithmetic, Euler's totient phi(N), Extended
               Euclidean Algorithm (basis of RSA private key derivation)
  Lecture 8  — SSL/TLS hybrid model, Kerberos freshness nonces, GSM
               replay prevention
  Lecture 6  — HMAC (consumed after handshake — Module 1)
  Lecture 4  — AES-CBC (consumed after handshake — Module 2)
  Lecture 1  — CIA Triad: all three properties satisfied after handshake

THE KEY DISTRIBUTION PROBLEM
─────────────────────────────
Modules 1 and 2 assume K_s and K_m are already shared. This module
solves the fundamental problem: how do two parties agree on a shared
secret over a network controlled by an adversary?

RSA answer (Lecture 5):
  - Controller holds (RSA_pub, RSA_priv) keypair.
  - RSA_pub is pre-loaded onto vehicles at manufacture. Not a secret.
  - Vehicle generates K_s, K_m per session; encrypts them under RSA_pub.
  - Only the controller can decrypt (holds RSA_priv).
  - Keys never appear in plaintext on the network.

RSA MATHEMATICS (Lecture 5 + Lecture 2)
─────────────────────────────────────────
  Key gen: N = p*q; phi(N) = (p-1)(q-1); e = 65537; d = e^-1 mod phi(N)
  Encrypt: C = M^e mod N   (anyone with public key)
  Decrypt: M = C^d mod N   (only holder of private key)

OAEP PADDING — WHY MANDATORY (Lecture 5 Cube Root Attack)
───────────────────────────────────────────────────────────
  Textbook RSA (C = M^e mod N) with e=3, small M: M^3 < N
  → C = M^3 in integers → attacker computes cube_root(C) = M.
  OAEP prepends a random 32-byte seed before encryption, ensuring:
    (a) Input to raw RSA is always large (cube root attack impossible)
    (b) Same plaintext → different ciphertext each time (IND-CPA secure)

FIVE-MESSAGE PROTOCOL
──────────────────────
  MSG 1  V→C: VehicleID | N_v | ProtocolVersion        [plaintext]
  MSG 2  C→V: SessionID | N_c | RSA_pub                [plaintext]
  MSG 2b C→V: Sign(RSA_priv, N_v || RSA_pub)           [signature]
  MSG 3  V→C: RSA_OAEP{K_s|K_m|N_v|N_c|VehicleID}     [encrypted]
  MSG 4  C→V: AES-CBC{"SESSION_READY"|SessionID|N_c}   [encrypted]
  MSG 5+ V↔C: AES-CBC(payload) | HMAC                  [Modules 1+2]
=============================================================================
"""

import os
import secrets
import struct
import json
import hashlib
import time
import hmac as _hmac
from dataclasses import dataclass, field
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey, RSAPublicKey, generate_private_key
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Modules 1 and 2 — integrated into the post-handshake pipeline
from modules.hmac_engine import HMACEngine, generate_mac_key
from modules.aes_engine  import AESEngine, VehicleEncryptor, ControllerDecryptor, generate_aes_key


# =============================================================================
# CONSTANTS
# =============================================================================

PROTOCOL_VERSION       = "SVCE-v1.0"
RSA_KEY_BITS           = 2048
RSA_PUBLIC_EXP         = 65537       # e = 2^16+1; avoids cube root risk of e=3
SESSION_ID_BYTES       = 16
NONCE_BYTES            = 16
HANDSHAKE_TIMEOUT_SECS = 30
ACK_TOKEN              = b"SESSION_READY"
RSA_OAEP_MAX_PLAIN     = 190         # (2048/8) - 2*32 - 2 = 190 bytes max


# =============================================================================
# SECTION 1 — RSA Keypair Generation and Serialisation
# =============================================================================

def generate_rsa_keypair() -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Generate RSA-2048 keypair for the Controller.

    Process (Lecture 5):
      1. Select two random 1024-bit primes p, q.
      2. N = p * q  (2048-bit modulus).
      3. phi(N) = (p-1)(q-1)  (Euler's totient — Lecture 2).
      4. e = 65537 (public exponent; Fermat prime).
      5. d ≡ e^-1 mod phi(N)  (Extended Euclidean Algorithm — Lecture 2).

    WHY e=65537 not e=3?
    Lecture 5 shows that e=3 with small M means M^3 < N, so the
    attacker recovers M = cube_root(C) trivially. e=65537 = 2^16+1
    is large enough that M^e >> N for any realistic plaintext,
    and OAEP padding provides the definitive fix regardless.

    WHY use the library and not implement RSA from scratch?
    Montgomery multiplication, Miller-Rabin primality testing, and
    CRT-optimised decryption all have timing side-channel risks in
    naive implementations (Kocher 1996). PyCA uses constant-time
    operations and is production-audited.
    """
    priv = generate_private_key(
        public_exponent=RSA_PUBLIC_EXP,
        key_size=RSA_KEY_BITS,
        backend=default_backend()
    )
    return priv, priv.public_key()


def serialize_public_key(pub: RSAPublicKey) -> bytes:
    """DER-encode the public key (SubjectPublicKeyInfo / X.509 format)."""
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(der: bytes) -> RSAPublicKey:
    """Reconstruct RSA public key from DER bytes."""
    return serialization.load_der_public_key(der, backend=default_backend())


def key_fingerprint(pub: RSAPublicKey) -> str:
    """
    SHA-256 fingerprint of the DER-encoded public key.
    Safe to display/log. Format: AB:CD:... (first 8 bytes shown).
    Used to visually verify the pre-loaded key matches the controller's.
    """
    digest = hashlib.sha256(serialize_public_key(pub)).digest()
    return ":".join(f"{b:02X}" for b in digest[:8]) + "..."


# =============================================================================
# SECTION 2 — RSA-OAEP Encryption / Decryption
# =============================================================================

def _oaep() -> asym_padding.OAEP:
    """OAEP padding with SHA-256 for both MGF1 and hash algorithm."""
    return asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )


def rsa_encrypt(plaintext: bytes, pub: RSAPublicKey) -> bytes:
    """
    Encrypt plaintext under RSA_pub using OAEP padding.

    OAEP internal steps:
      1. Generate 32-byte random seed (library does this).
      2. Mask = MGF1-SHA256(seed, len(plaintext)).
      3. Masked_data = plaintext XOR Mask.
      4. Seed_mask = MGF1-SHA256(Masked_data, 32).
      5. Masked_seed = seed XOR Seed_mask.
      6. EM = 0x00 || Masked_seed || Masked_data.
      7. C = EM^e mod N  (raw RSA).

    The random seed means same plaintext → different ciphertext each time.
    This is IND-CPA security (Lecture 5 semantic security discussion).

    Max plaintext: 190 bytes for RSA-2048-OAEP-SHA256.
    Session bundle K_s(32)+K_m(32)+N_v(16)+N_c(16)+vid_len(1)+VID(≤80)
    = 177 bytes max — within limit.
    """
    if len(plaintext) > RSA_OAEP_MAX_PLAIN:
        raise ValueError(
            f"Plaintext {len(plaintext)}B exceeds RSA-OAEP max {RSA_OAEP_MAX_PLAIN}B."
        )
    return pub.encrypt(plaintext, _oaep())


def rsa_decrypt(ciphertext: bytes, priv: RSAPrivateKey) -> bytes:
    """
    Decrypt RSA-OAEP ciphertext with the private key.

    M = C^d mod N (Lecture 5).
    Raises ValueError on any failure — never propagates raw library
    exception which may contain oracle-useful information.
    """
    try:
        return priv.decrypt(ciphertext, _oaep())
    except Exception as exc:
        raise ValueError(
            "RSA-OAEP decryption failed. Wrong key, tampered ciphertext, "
            "or malformed OAEP structure."
        ) from exc


# =============================================================================
# SECTION 3 — RSA-PSS Digital Signature (MSG 2b)
# =============================================================================

def rsa_sign(priv: RSAPrivateKey, message: bytes) -> bytes:
    """
    RSA-PSS signature over message.

    WHY PSS not PKCS#1 v1.5?
    Bleichenbacher (1998) showed chosen-ciphertext attacks against
    PKCS#1 v1.5 signature padding. PSS (RFC 8017) uses a random salt,
    providing provable security. TLS 1.3 mandates PSS.

    The signed message is SHA-256(N_v || RSA_pub_DER).
    Binding N_v means a replayed MSG 2b from a previous session has
    the wrong N_v and fails verification.
    """
    return priv.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def rsa_verify(pub: RSAPublicKey, message: bytes, sig: bytes) -> bool:
    """Verify RSA-PSS signature. Returns True/False; never raises."""
    try:
        pub.verify(
            sig, message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, Exception):
        return False


# =============================================================================
# SECTION 4 — Handshake Message Structures
# =============================================================================

@dataclass
class MSG1_ClientHello:
    """Vehicle → Controller. Phase 1 identity announcement."""
    vehicle_id       : str
    nonce_v          : bytes = field(default_factory=lambda: secrets.token_bytes(NONCE_BYTES))
    protocol_version : str   = PROTOCOL_VERSION
    timestamp        : float = field(default_factory=time.time)

    def to_bytes(self) -> bytes:
        return json.dumps({
            "type"    : "CLIENT_HELLO",
            "vehicle_id": self.vehicle_id,
            "nonce_v" : self.nonce_v.hex(),
            "protocol_version": self.protocol_version,
            "timestamp": round(self.timestamp, 6),
        }, sort_keys=True).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "MSG1_ClientHello":
        d = json.loads(data)
        if d.get("type") != "CLIENT_HELLO":
            raise ValueError("Not a CLIENT_HELLO message.")
        return cls(
            vehicle_id=d["vehicle_id"],
            nonce_v=bytes.fromhex(d["nonce_v"]),
            protocol_version=d["protocol_version"],
            timestamp=d["timestamp"],
        )


@dataclass
class MSG2_ServerHello:
    """Controller → Vehicle. Phase 1 response with RSA_pub and MSG 2b signature."""
    nonce_c     : bytes
    session_id  : bytes
    rsa_pub_der : bytes
    signature   : bytes = b""
    timestamp   : float = field(default_factory=time.time)

    def to_bytes(self) -> bytes:
        return json.dumps({
            "type"      : "SERVER_HELLO",
            "nonce_c"   : self.nonce_c.hex(),
            "session_id": self.session_id.hex(),
            "rsa_pub_der": self.rsa_pub_der.hex(),
            "signature" : self.signature.hex(),
            "timestamp" : round(self.timestamp, 6),
        }, sort_keys=True).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "MSG2_ServerHello":
        d = json.loads(data)
        if d.get("type") != "SERVER_HELLO":
            raise ValueError("Not a SERVER_HELLO message.")
        return cls(
            nonce_c=bytes.fromhex(d["nonce_c"]),
            session_id=bytes.fromhex(d["session_id"]),
            rsa_pub_der=bytes.fromhex(d["rsa_pub_der"]),
            signature=bytes.fromhex(d["signature"]),
            timestamp=d["timestamp"],
        )


@dataclass
class MSG3_KeyPackage:
    """
    Vehicle → Controller. Phase 2 — the critical message.

    RSA_OAEP ciphertext contains:
      K_s (32B) | K_m (32B) | N_v (16B) | N_c (16B) | vid_len(1B) | VehicleID

    N_v and N_c inside the ciphertext are the replay/ordering proof.
    Only the controller (with RSA_priv) can read them.
    """
    rsa_ciphertext : bytes
    vehicle_id     : str
    session_id     : bytes
    timestamp      : float = field(default_factory=time.time)

    def to_bytes(self) -> bytes:
        return json.dumps({
            "type"          : "KEY_PACKAGE",
            "rsa_ciphertext": self.rsa_ciphertext.hex(),
            "vehicle_id"    : self.vehicle_id,
            "session_id"    : self.session_id.hex(),
            "timestamp"     : round(self.timestamp, 6),
        }, sort_keys=True).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "MSG3_KeyPackage":
        d = json.loads(data)
        if d.get("type") != "KEY_PACKAGE":
            raise ValueError("Not a KEY_PACKAGE message.")
        return cls(
            rsa_ciphertext=bytes.fromhex(d["rsa_ciphertext"]),
            vehicle_id=d["vehicle_id"],
            session_id=bytes.fromhex(d["session_id"]),
            timestamp=d["timestamp"],
        )

    @staticmethod
    def build_bundle(k_s, k_m, nonce_v, nonce_c, vehicle_id) -> bytes:
        """Pack the RSA plaintext bundle: K_s|K_m|N_v|N_c|vid_len|VID."""
        vid = vehicle_id.encode()
        if len(vid) > 80:
            raise ValueError("VehicleID too long (max 80 bytes).")
        bundle = k_s + k_m + nonce_v + nonce_c + bytes([len(vid)]) + vid
        if len(bundle) > RSA_OAEP_MAX_PLAIN:
            raise ValueError(f"Bundle {len(bundle)}B exceeds RSA-OAEP limit.")
        return bundle

    @staticmethod
    def parse_bundle(bundle: bytes) -> dict:
        """Unpack decrypted RSA bundle back into its fields."""
        if len(bundle) < 97:
            raise ValueError(f"Bundle too short: {len(bundle)}B (min 97B).")
        vid_len = bundle[96]
        if len(bundle) < 97 + vid_len:
            raise ValueError("Bundle truncated: VehicleID field incomplete.")
        return {
            "k_s"       : bundle[0:32],
            "k_m"       : bundle[32:64],
            "nonce_v"   : bundle[64:80],
            "nonce_c"   : bundle[80:96],
            "vehicle_id": bundle[97:97+vid_len].decode(),
        }


@dataclass
class MSG4_HandshakeACK:
    """
    Controller → Vehicle. Phase 3 confirmation.

    AES-CBC({ACK_TOKEN | SessionID | N_c}, K_s, IV)
    Proves controller recovered K_s from MSG 3.
    N_c binding prevents replay of captured ACK messages.
    """
    iv         : bytes
    ciphertext : bytes
    session_id : bytes
    vehicle_id : str
    timestamp  : float = field(default_factory=time.time)

    def to_bytes(self) -> bytes:
        return json.dumps({
            "type"      : "HANDSHAKE_ACK",
            "iv"        : self.iv.hex(),
            "ciphertext": self.ciphertext.hex(),
            "session_id": self.session_id.hex(),
            "vehicle_id": self.vehicle_id,
            "timestamp" : round(self.timestamp, 6),
        }, sort_keys=True).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "MSG4_HandshakeACK":
        d = json.loads(data)
        if d.get("type") != "HANDSHAKE_ACK":
            raise ValueError("Not a HANDSHAKE_ACK message.")
        return cls(
            iv=bytes.fromhex(d["iv"]),
            ciphertext=bytes.fromhex(d["ciphertext"]),
            session_id=bytes.fromhex(d["session_id"]),
            vehicle_id=d["vehicle_id"],
            timestamp=d["timestamp"],
        )


# =============================================================================
# SECTION 5 — Established Session
# =============================================================================

@dataclass
class EstablishedSession:
    """
    Represents a fully authenticated, key-confirmed session.
    Produced by both HandshakeController and HandshakeVehicle on success.
    Both parties receive instances populated with identical K_s and K_m.
    """
    vehicle_id           : str
    session_id           : bytes
    k_s                  : bytes   # AES-256 key — do NOT log raw value
    k_m                  : bytes   # HMAC key   — do NOT log raw value
    vehicle_encryptor    : Optional[VehicleEncryptor]    = None
    controller_decryptor : Optional[ControllerDecryptor] = None
    established_at       : float = field(default_factory=time.time)

    def session_id_display(self) -> str:
        return self.session_id.hex()[:16] + "..."

    def key_fingerprints(self) -> dict:
        """SHA-256 digests of K_s and K_m — safe for logging."""
        return {
            "k_s_fp": hashlib.sha256(self.k_s).hexdigest()[:16],
            "k_m_fp": hashlib.sha256(self.k_m).hexdigest()[:16],
        }


# =============================================================================
# SECTION 6 — Controller Handshake State Machine
# =============================================================================

class HandshakeController:
    """
    Controller-side handshake handler. One instance per vehicle connection.

    State: IDLE → HELLO_SENT → ESTABLISHED (or FAILED at any step)
    """

    def __init__(self, private_key: RSAPrivateKey, vehicle_id: str):
        self._priv      = private_key
        self._pub       = private_key.public_key()
        self._vid       = vehicle_id
        self._state     = "IDLE"
        self._nonce_v   = None
        self._nonce_c   = None
        self._session_id = None
        self._msg1_ts   = None
        self._session   = None

    def process_client_hello(self, msg1_bytes: bytes) -> bytes:
        """
        Process MSG 1, respond with MSG 2 + MSG 2b signature.

        Steps:
          1. Parse and validate MSG 1.
          2. Generate N_c (fresh 128-bit CSPRNG nonce).
          3. Compute SessionID = SHA-256(N_v || N_c || VehicleID)[:16].
          4. Sign(RSA_priv, N_v || RSA_pub_DER) — MSG 2b signature.
             N_v is bound in the signature so it is session-specific.
          5. Return serialised MSG 2.
        """
        assert self._state == "IDLE", f"Bad state: {self._state}"

        try:
            msg1 = MSG1_ClientHello.from_bytes(msg1_bytes)
        except Exception as e:
            self._state = "FAILED"; raise ValueError(f"Bad MSG 1: {e}")

        if msg1.protocol_version != PROTOCOL_VERSION:
            self._state = "FAILED"
            raise ValueError(f"Unsupported version: {msg1.protocol_version}")

        self._nonce_v = msg1.nonce_v
        self._msg1_ts = time.time()
        self._nonce_c = secrets.token_bytes(NONCE_BYTES)

        # SessionID: unique per session, depends on both parties' nonces
        sid_input        = self._nonce_v + self._nonce_c + msg1.vehicle_id.encode()
        self._session_id = hashlib.sha256(sid_input).digest()[:SESSION_ID_BYTES]

        # MSG 2b: sign (N_v || RSA_pub_DER) to prove we hold RSA_priv
        pub_der   = serialize_public_key(self._pub)
        signature = rsa_sign(self._priv, self._nonce_v + pub_der)

        msg2 = MSG2_ServerHello(
            nonce_c=self._nonce_c,
            session_id=self._session_id,
            rsa_pub_der=pub_der,
            signature=signature,
        )
        self._state = "HELLO_SENT"
        return msg2.to_bytes()

    def process_key_package(self, msg3_bytes: bytes) -> bytes:
        """
        Process MSG 3 (KeyPackage) and generate MSG 4 (HandshakeACK).

        Validation order:
          1. Parse MSG 3 structure.
          2. Handshake timeout check (>30s since MSG 1 → replay risk).
          3. SessionID match (must equal our session_id from MSG 2).
          4. RSA-OAEP decrypt — recovers K_s, K_m, N_v, N_c, VehicleID.
          5. N_v match — proves MSG 3 was generated for THIS session.
             (Kerberos-style freshness check, Lecture 8)
          6. N_c match — proves vehicle incorporated our MSG 2 challenge.
          7. VehicleID match.
          8. K_s ≠ K_m key separation invariant.

        ACK generation:
          AES-CBC(ACK_TOKEN || SessionID || N_c, K_s, fresh_IV)
          Proves K_s was successfully recovered.
        """
        assert self._state == "HELLO_SENT", f"Bad state: {self._state}"

        # ── Timeout ────────────────────────────────────────────────────────
        elapsed = time.time() - self._msg1_ts
        if elapsed > HANDSHAKE_TIMEOUT_SECS:
            self._state = "FAILED"
            raise ValueError(
                f"Handshake timeout: {elapsed:.1f}s > {HANDSHAKE_TIMEOUT_SECS}s limit."
            )

        # ── Parse ──────────────────────────────────────────────────────────
        try:
            msg3 = MSG3_KeyPackage.from_bytes(msg3_bytes)
        except Exception as e:
            self._state = "FAILED"; raise ValueError(f"Bad MSG 3: {e}")

        # ── SessionID match ────────────────────────────────────────────────
        if not _hmac.compare_digest(msg3.session_id, self._session_id):
            self._state = "FAILED"
            raise ValueError("SessionID mismatch in MSG 3 — possible replay.")

        # ── RSA-OAEP decrypt ───────────────────────────────────────────────
        try:
            bundle = rsa_decrypt(msg3.rsa_ciphertext, self._priv)
        except ValueError:
            self._state = "FAILED"; raise

        # ── Parse bundle ───────────────────────────────────────────────────
        try:
            parsed = MSG3_KeyPackage.parse_bundle(bundle)
        except ValueError:
            self._state = "FAILED"; raise

        k_s     = parsed["k_s"]
        k_m     = parsed["k_m"]
        recv_nv = parsed["nonce_v"]
        recv_nc = parsed["nonce_c"]
        recv_vid = parsed["vehicle_id"]

        # ── Nonce N_v: replay prevention (Kerberos/GSM pattern, L8) ───────
        if not _hmac.compare_digest(recv_nv, self._nonce_v):
            self._state = "FAILED"
            raise ValueError("N_v mismatch — MSG 3 appears replayed from another session.")

        # ── Nonce N_c: ordering proof ──────────────────────────────────────
        if not _hmac.compare_digest(recv_nc, self._nonce_c):
            self._state = "FAILED"
            raise ValueError("N_c mismatch — vehicle did not incorporate our MSG 2 challenge.")

        # ── VehicleID ──────────────────────────────────────────────────────
        if recv_vid != self._vid:
            self._state = "FAILED"
            raise ValueError(f"VehicleID mismatch: expected '{self._vid}', got '{recv_vid}'.")

        # ── Key separation invariant ───────────────────────────────────────
        if _hmac.compare_digest(k_s, k_m):
            self._state = "FAILED"
            raise ValueError("K_s == K_m: key separation violation. Session rejected.")

        # ── Build MSG 4: AES-CBC ACK ───────────────────────────────────────
        ack_plain = ACK_TOKEN + self._session_id + self._nonce_c
        padder    = sym_padding.PKCS7(128).padder()
        padded    = padder.update(ack_plain) + padder.finalize()
        iv4       = secrets.token_bytes(16)
        cipher    = Cipher(algorithms.AES(k_s), modes.CBC(iv4), backend=default_backend())
        enc       = cipher.encryptor()
        ack_ct    = enc.update(padded) + enc.finalize()

        msg4 = MSG4_HandshakeACK(
            iv=iv4, ciphertext=ack_ct,
            session_id=self._session_id, vehicle_id=self._vid
        )

        # ── Build session ──────────────────────────────────────────────────
        self._session = EstablishedSession(
            vehicle_id=self._vid,
            session_id=self._session_id,
            k_s=k_s, k_m=k_m,
            vehicle_encryptor=None,
            controller_decryptor=ControllerDecryptor(k_s, k_m),
        )
        self._state = "ESTABLISHED"
        del bundle, parsed
        return msg4.to_bytes()

    def get_session(self) -> EstablishedSession:
        if self._state != "ESTABLISHED":
            raise RuntimeError(f"Session not established (state: {self._state}).")
        return self._session

    @property
    def state(self) -> str:
        return self._state


# =============================================================================
# SECTION 7 — Vehicle Handshake State Machine
# =============================================================================

class HandshakeVehicle:
    """
    Vehicle-side handshake handler.

    State: IDLE → HELLO_SENT → KEYS_SENT → ESTABLISHED (or FAILED)

    Parameters
    ----------
    vehicle_id          : str   — This vehicle's unique identifier.
    trusted_rsa_pub_der : bytes — DER-encoded controller RSA public key,
                                   pre-loaded at manufacturing time.
                                   This is the root of trust for MitM defence.
    require_signature   : bool  — Enforce MSG 2b signature. Default True.
    """

    def __init__(self, vehicle_id: str, trusted_rsa_pub_der: bytes,
                 require_signature: bool = True):
        self._vid           = vehicle_id
        self._trusted_pub   = deserialize_public_key(trusted_rsa_pub_der)
        self._trusted_der   = trusted_rsa_pub_der
        self._require_sig   = require_signature
        self._state         = "IDLE"
        self._nonce_v       = None
        self._nonce_c       = None
        self._session_id    = None
        self._k_s           = None
        self._k_m           = None
        self._session       = None

    def create_client_hello(self) -> bytes:
        """
        Generate MSG 1 with fresh N_v.

        N_v must be fresh per session. A reused N_v lets an attacker
        replay a captured MSG 3 (the controller's N_v binding check
        would match, giving a false-positive acceptance).
        """
        assert self._state == "IDLE", f"Bad state: {self._state}"
        self._nonce_v = secrets.token_bytes(NONCE_BYTES)
        msg1 = MSG1_ClientHello(vehicle_id=self._vid, nonce_v=self._nonce_v)
        self._state = "HELLO_SENT"
        return msg1.to_bytes()

    def process_server_hello_and_create_key_package(self, msg2_bytes: bytes) -> bytes:
        """
        Process MSG 2 (+ optional MSG 2b signature), generate MSG 3.

        Validation:
          1. Parse MSG 2.
          2. Compare received RSA_pub against pre-loaded trusted key.
             Mismatch = MitM key substitution attack detected (Lecture 5).
          3. Verify MSG 2b signature: Sign(RSA_priv, N_v || RSA_pub_DER).
             N_v binds the signature to this session; invalid if replayed.

        Key generation:
          1. K_s = CSPRNG(32 bytes)  — AES-256 key.
          2. K_m = CSPRNG(32 bytes)  — HMAC-SHA256 key, independent of K_s.
             While K_s==K_m is astronomically improbable (2^-256), we
             enforce a runtime check as a defensive coding practice.
          3. Bundle = K_s|K_m|N_v|N_c|VehicleID → RSA-OAEP encrypt.
        """
        assert self._state == "HELLO_SENT", f"Bad state: {self._state}"

        try:
            msg2 = MSG2_ServerHello.from_bytes(msg2_bytes)
        except Exception as e:
            self._state = "FAILED"; raise ValueError(f"Bad MSG 2: {e}")

        # ── MitM detection: pre-loaded key vs received key ─────────────────
        # This is the vehicle's primary defence against key substitution.
        # The comparison uses hmac.compare_digest for constant-time equality.
        if not _hmac.compare_digest(msg2.rsa_pub_der, self._trusted_der):
            self._state = "FAILED"
            raise ValueError(
                "RSA public key mismatch! Received RSA_pub does NOT match "
                "the pre-loaded trusted key. MAN-IN-THE-MIDDLE ATTACK DETECTED."
            )

        # ── Signature verification (MSG 2b) ────────────────────────────────
        has_sig = len(msg2.signature) > 0
        if self._require_sig and not has_sig:
            self._state = "FAILED"
            raise ValueError("MSG 2b signature missing — required for authenticated exchange.")

        if has_sig:
            sign_input = self._nonce_v + msg2.rsa_pub_der
            if not rsa_verify(self._trusted_pub, sign_input, msg2.signature):
                self._state = "FAILED"
                raise ValueError(
                    "MSG 2b signature FAILED. Controller cannot prove RSA_priv "
                    "ownership, or MSG 2 was replayed from another session."
                )

        self._nonce_c    = msg2.nonce_c
        self._session_id = msg2.session_id

        # ── Generate K_s, K_m — fresh per session ─────────────────────────
        self._k_s = generate_aes_key(32)
        self._k_m = generate_mac_key(32)
        # Defensive: enforce K_s != K_m (astronomically improbable but checked)
        while _hmac.compare_digest(self._k_s, self._k_m):
            self._k_m = generate_mac_key(32)

        # ── Build and encrypt bundle ───────────────────────────────────────
        bundle = MSG3_KeyPackage.build_bundle(
            self._k_s, self._k_m, self._nonce_v, self._nonce_c, self._vid
        )
        rsa_ct = rsa_encrypt(bundle, self._trusted_pub)
        del bundle  # release plaintext reference

        msg3 = MSG3_KeyPackage(
            rsa_ciphertext=rsa_ct,
            vehicle_id=self._vid,
            session_id=self._session_id,
        )
        self._state = "KEYS_SENT"
        return msg3.to_bytes()

    def process_handshake_ack(self, msg4_bytes: bytes) -> EstablishedSession:
        """
        Process MSG 4 and complete session establishment.

        Validation:
          1. Parse MSG 4.
          2. AES-CBC decrypt with K_s — proves controller recovered K_s.
          3. Verify ACK_TOKEN prefix — known-value confirmation.
          4. Verify SessionID — prevents cross-session confusion.
          5. Verify N_c — prevents replay of a captured MSG 4
             (Lecture 8: Kerberos replay prevention pattern).

        On success, returns EstablishedSession with VehicleEncryptor
        pre-initialised for immediate first-message transmission.
        """
        assert self._state == "KEYS_SENT", f"Bad state: {self._state}"

        try:
            msg4 = MSG4_HandshakeACK.from_bytes(msg4_bytes)
        except Exception as e:
            self._state = "FAILED"; raise ValueError(f"Bad MSG 4: {e}")

        # ── AES-CBC decrypt ─────────────────────────────────────────────────
        try:
            cipher = Cipher(algorithms.AES(self._k_s), modes.CBC(msg4.iv),
                            backend=default_backend())
            dec    = cipher.decryptor()
            padded = dec.update(msg4.ciphertext) + dec.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            plain    = unpadder.update(padded) + unpadder.finalize()
        except Exception as e:
            self._state = "FAILED"
            raise ValueError(f"MSG 4 AES decryption failed: {e}")

        # ── Token check ────────────────────────────────────────────────────
        tl = len(ACK_TOKEN)
        if not _hmac.compare_digest(plain[:tl], ACK_TOKEN):
            self._state = "FAILED"
            raise ValueError("MSG 4 ACK token mismatch — unexpected content.")

        # ── SessionID check ────────────────────────────────────────────────
        sid = plain[tl:tl+SESSION_ID_BYTES]
        if not _hmac.compare_digest(sid, self._session_id):
            self._state = "FAILED"
            raise ValueError("MSG 4 SessionID mismatch — possible replayed ACK.")

        # ── N_c check ──────────────────────────────────────────────────────
        nc = plain[tl+SESSION_ID_BYTES:tl+SESSION_ID_BYTES+NONCE_BYTES]
        if not _hmac.compare_digest(nc, self._nonce_c):
            self._state = "FAILED"
            raise ValueError("MSG 4 N_c mismatch — possible replayed ACK.")

        # ── Build session ──────────────────────────────────────────────────
        self._session = EstablishedSession(
            vehicle_id=self._vid,
            session_id=self._session_id,
            k_s=self._k_s, k_m=self._k_m,
            vehicle_encryptor=VehicleEncryptor(self._vid, self._k_s, self._k_m),
            controller_decryptor=None,
        )
        self._state = "ESTABLISHED"
        return self._session

    def get_session(self) -> EstablishedSession:
        if self._state != "ESTABLISHED":
            raise RuntimeError(f"Session not established (state: {self._state}).")
        return self._session

    @property
    def state(self) -> str:
        return self._state


# =============================================================================
# SECTION 8 — Convenience Orchestrator
# =============================================================================

def perform_full_handshake(
    vehicle_id        : str,
    private_key       : RSAPrivateKey,
    trusted_pub_der   : bytes,
    require_signature : bool = True,
) -> Tuple[EstablishedSession, EstablishedSession]:
    """
    Simulate the complete 4-message handshake in-process.

    In Module 4 (TCP integration), each message crosses a socket.
    Here messages pass between objects in memory for testing and demo.

    Returns
    -------
    (vehicle_session, controller_session)
        vehicle_session.vehicle_encryptor    — ready for MSG 5+
        controller_session.controller_decryptor — ready for MSG 5+
        Both sessions hold identical K_s and K_m.
    """
    ctrl = HandshakeController(private_key, vehicle_id)
    veh  = HandshakeVehicle(vehicle_id, trusted_pub_der, require_signature)

    msg1 = veh.create_client_hello()
    msg2 = ctrl.process_client_hello(msg1)
    msg3 = veh.process_server_hello_and_create_key_package(msg2)
    msg4 = ctrl.process_key_package(msg3)
    v_session = veh.process_handshake_ack(msg4)
    c_session = ctrl.get_session()

    return v_session, c_session