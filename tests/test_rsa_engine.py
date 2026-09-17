"""
=============================================================================
MODULE 3 — UNIT TEST SUITE
RSA Handshake & Secure Session Key Exchange Engine
=============================================================================
Group 29 | EE8257 Information Security

Run: python -m pytest tests/test_rsa_engine.py -v   (from project root)
     or: python -m pytest test_rsa_engine.py -v     (from module_3_rsa)
=============================================================================
"""

import pytest
import sys, os, json, time, copy, hashlib, hmac as _hmac, secrets

sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), '..', 'modules')
)

from modules.rsa_engine import (
    generate_rsa_keypair, serialize_public_key, deserialize_public_key,
    key_fingerprint, rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify,
    MSG1_ClientHello, MSG2_ServerHello, MSG3_KeyPackage, MSG4_HandshakeACK,
    HandshakeController, HandshakeVehicle, EstablishedSession,
    perform_full_handshake, PROTOCOL_VERSION, ACK_TOKEN,
    RSA_OAEP_MAX_PLAIN, NONCE_BYTES, SESSION_ID_BYTES,
)
from modules.hmac_engine import generate_mac_key
from modules.aes_engine  import generate_aes_key


# ── Module-level fixture: one keypair shared across all tests ──────────────
# RSA key generation is slow (~1s). Generating once and reusing is standard
# practice in test suites. Each test that needs isolation uses per-test keys.

@pytest.fixture(scope="module")
def keypair():
    return generate_rsa_keypair()

@pytest.fixture(scope="module")
def pub_der(keypair):
    return serialize_public_key(keypair[1])

@pytest.fixture
def fresh_handshake(keypair, pub_der):
    """Return a completed (v_session, c_session) pair for a fresh vehicle."""
    vid = f"VH-{secrets.token_hex(4).upper()}"
    return perform_full_handshake(vid, keypair[0], pub_der)


# =============================================================================
# RSA Primitives
# =============================================================================

class TestRSAPrimitives:

    def test_keypair_is_2048_bits(self, keypair):
        priv, pub = keypair
        assert priv.key_size == 2048

    def test_public_exponent_is_65537(self, keypair):
        _, pub = keypair
        assert pub.public_numbers().e == 65537

    def test_serialize_deserialize_round_trip(self, keypair, pub_der):
        _, pub = keypair
        restored = deserialize_public_key(pub_der)
        assert serialize_public_key(pub) == serialize_public_key(restored)

    def test_fingerprint_is_string(self, keypair):
        _, pub = keypair
        fp = key_fingerprint(pub)
        assert isinstance(fp, str)
        assert ":" in fp

    def test_different_keypairs_different_fingerprints(self):
        _, pub1 = generate_rsa_keypair()
        _, pub2 = generate_rsa_keypair()
        assert key_fingerprint(pub1) != key_fingerprint(pub2)

    def test_oaep_encrypt_decrypt_round_trip(self, keypair, pub_der):
        priv, pub = keypair
        plain = b"test session key data 32 bytes!!"
        ct    = rsa_encrypt(plain, pub)
        dec   = rsa_decrypt(ct, priv)
        assert dec == plain

    def test_oaep_ciphertext_is_256_bytes(self, keypair, pub_der):
        _, pub = keypair
        ct = rsa_encrypt(b"hello world", pub)
        assert len(ct) == 256

    def test_oaep_randomness(self, keypair, pub_der):
        """Same plaintext → different ciphertext each call (IND-CPA security)."""
        _, pub = keypair
        plain  = b"same message every time"
        cts    = {rsa_encrypt(plain, pub) for _ in range(5)}
        assert len(cts) == 5, "OAEP must produce unique ciphertext each call"

    def test_oaep_wrong_key_raises(self, keypair):
        _, pub  = keypair
        priv2,_ = generate_rsa_keypair()
        ct = rsa_encrypt(b"secret data here!", pub)
        with pytest.raises(ValueError, match="decryption failed"):
            rsa_decrypt(ct, priv2)

    def test_oaep_tampered_ciphertext_raises(self, keypair):
        priv, pub = keypair
        ct = rsa_encrypt(b"secret", pub)
        tampered = bytearray(ct)
        tampered[50]  ^= 0xFF
        tampered[100] ^= 0xAA
        with pytest.raises(ValueError):
            rsa_decrypt(bytes(tampered), priv)

    def test_oaep_plaintext_too_large_raises(self, keypair):
        _, pub = keypair
        with pytest.raises(ValueError, match="exceeds"):
            rsa_encrypt(b"X" * (RSA_OAEP_MAX_PLAIN + 1), pub)

    def test_pss_sign_verify(self, keypair):
        priv, pub = keypair
        msg = b"hello from controller"
        sig = rsa_sign(priv, msg)
        assert rsa_verify(pub, msg, sig) is True

    def test_pss_tampered_message_fails(self, keypair):
        priv, pub = keypair
        msg = b"original message"
        sig = rsa_sign(priv, msg)
        assert rsa_verify(pub, b"tampered message", sig) is False

    def test_pss_wrong_key_fails(self, keypair):
        priv, pub = keypair
        priv2, pub2 = generate_rsa_keypair()
        msg = b"signed with key 1"
        sig = rsa_sign(priv, msg)
        assert rsa_verify(pub2, msg, sig) is False

    def test_pss_signature_is_256_bytes(self, keypair):
        priv, _ = keypair
        sig = rsa_sign(priv, b"test")
        assert len(sig) == 256


# =============================================================================
# Message Structure Tests
# =============================================================================

class TestMessageStructures:

    def test_msg1_round_trip(self):
        m = MSG1_ClientHello(vehicle_id="VH-001")
        restored = MSG1_ClientHello.from_bytes(m.to_bytes())
        assert restored.vehicle_id == "VH-001"
        assert restored.nonce_v == m.nonce_v
        assert restored.protocol_version == PROTOCOL_VERSION

    def test_msg1_nonce_is_16_bytes(self):
        m = MSG1_ClientHello(vehicle_id="VH-TEST")
        assert len(m.nonce_v) == NONCE_BYTES

    def test_msg1_wrong_type_raises(self):
        bad = json.dumps({"type": "WRONG", "vehicle_id": "VH-X"}).encode()
        with pytest.raises(ValueError, match="CLIENT_HELLO"):
            MSG1_ClientHello.from_bytes(bad)

    def test_msg2_round_trip(self, keypair, pub_der):
        m = MSG2_ServerHello(
            nonce_c=secrets.token_bytes(16),
            session_id=secrets.token_bytes(16),
            rsa_pub_der=pub_der,
            signature=b"",
        )
        restored = MSG2_ServerHello.from_bytes(m.to_bytes())
        assert restored.nonce_c == m.nonce_c
        assert restored.rsa_pub_der == pub_der

    def test_msg3_bundle_build_and_parse(self):
        ks = generate_aes_key(32)
        km = generate_mac_key(32)
        nv = secrets.token_bytes(16)
        nc = secrets.token_bytes(16)
        bundle = MSG3_KeyPackage.build_bundle(ks, km, nv, nc, "VH-BND")
        parsed = MSG3_KeyPackage.parse_bundle(bundle)
        assert parsed["k_s"] == ks
        assert parsed["k_m"] == km
        assert parsed["nonce_v"] == nv
        assert parsed["nonce_c"] == nc
        assert parsed["vehicle_id"] == "VH-BND"

    def test_msg3_bundle_too_long_raises(self):
        ks = generate_aes_key(32); km = generate_mac_key(32)
        nv = secrets.token_bytes(16); nc = secrets.token_bytes(16)
        with pytest.raises(ValueError, match="too long"):
            MSG3_KeyPackage.build_bundle(ks, km, nv, nc, "X" * 81)

    def test_msg3_parse_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            MSG3_KeyPackage.parse_bundle(b"short")

    def test_msg4_round_trip(self):
        m = MSG4_HandshakeACK(
            iv=secrets.token_bytes(16),
            ciphertext=secrets.token_bytes(32),
            session_id=secrets.token_bytes(16),
            vehicle_id="VH-ACK",
        )
        restored = MSG4_HandshakeACK.from_bytes(m.to_bytes())
        assert restored.iv == m.iv
        assert restored.ciphertext == m.ciphertext
        assert restored.vehicle_id == "VH-ACK"


# =============================================================================
# Controller Handshake Handler
# =============================================================================

class TestHandshakeController:

    def test_process_client_hello_returns_bytes(self, keypair, pub_der):
        priv, _ = keypair
        ctrl = HandshakeController(priv, "VH-C1")
        veh  = HandshakeVehicle("VH-C1", pub_der)
        msg1 = veh.create_client_hello()
        msg2 = ctrl.process_client_hello(msg1)
        assert isinstance(msg2, bytes)
        assert ctrl.state == "HELLO_SENT"

    def test_msg2_contains_signature(self, keypair, pub_der):
        priv, _ = keypair
        ctrl = HandshakeController(priv, "VH-C2")
        veh  = HandshakeVehicle("VH-C2", pub_der)
        msg2 = ctrl.process_client_hello(veh.create_client_hello())
        m2   = MSG2_ServerHello.from_bytes(msg2)
        assert len(m2.signature) == 256    # RSA-2048 signature

    def test_msg2_contains_nonce_c(self, keypair, pub_der):
        priv, _ = keypair
        ctrl = HandshakeController(priv, "VH-C3")
        veh  = HandshakeVehicle("VH-C3", pub_der)
        msg2 = ctrl.process_client_hello(veh.create_client_hello())
        m2   = MSG2_ServerHello.from_bytes(msg2)
        assert len(m2.nonce_c) == NONCE_BYTES

    def test_process_key_package_returns_bytes(self, keypair, pub_der):
        priv, _ = keypair
        ctrl = HandshakeController(priv, "VH-C4")
        veh  = HandshakeVehicle("VH-C4", pub_der)
        msg1 = veh.create_client_hello()
        msg2 = ctrl.process_client_hello(msg1)
        msg3 = veh.process_server_hello_and_create_key_package(msg2)
        msg4 = ctrl.process_key_package(msg3)
        assert isinstance(msg4, bytes)
        assert ctrl.state == "ESTABLISHED"

    def test_wrong_protocol_version_rejected(self, keypair, pub_der):
        priv, _ = keypair
        ctrl = HandshakeController(priv, "VH-VER")
        msg1 = MSG1_ClientHello(vehicle_id="VH-VER", protocol_version="WRONG-v9")
        with pytest.raises(ValueError, match="version"):
            ctrl.process_client_hello(msg1.to_bytes())

    def test_nonce_v_mismatch_in_msg3_rejected(self, keypair, pub_der):
        """Replay detection: N_v inside ciphertext doesn't match this session's N_v."""
        priv, _ = keypair
        # Session A
        ctrl_a = HandshakeController(priv, "VH-NV")
        veh_a  = HandshakeVehicle("VH-NV", pub_der)
        msg1_a = veh_a.create_client_hello()
        msg2_a = ctrl_a.process_client_hello(msg1_a)
        msg3_a = veh_a.process_server_hello_and_create_key_package(msg2_a)

        # Session B — use session A's MSG 3 (different N_v inside ciphertext)
        ctrl_b = HandshakeController(priv, "VH-NV")
        veh_b  = HandshakeVehicle("VH-NV", pub_der)
        msg1_b = veh_b.create_client_hello()
        msg2_b = ctrl_b.process_client_hello(msg1_b)

        m3 = json.loads(msg3_a)
        m3["session_id"] = json.loads(msg2_b)["session_id"]
        replayed = json.dumps(m3, sort_keys=True).encode()

        with pytest.raises(ValueError, match="N_v"):
            ctrl_b.process_key_package(replayed)

    def test_vehicleid_mismatch_in_msg3_rejected(self, keypair, pub_der):
        priv, _ = keypair
        ctrl = HandshakeController(priv, "VH-CORRECT")
        veh  = HandshakeVehicle("VH-WRONG", pub_der, require_signature=False)
        msg1_legit = MSG1_ClientHello(vehicle_id="VH-CORRECT").to_bytes()
        msg2 = ctrl.process_client_hello(msg1_legit)
        veh.create_client_hello()
        veh._nonce_v = MSG1_ClientHello.from_bytes(msg1_legit).nonce_v
        msg3 = veh.process_server_hello_and_create_key_package(msg2)
        with pytest.raises(ValueError, match="VehicleID"):
            ctrl.process_key_package(msg3)


# =============================================================================
# Vehicle Handshake Handler
# =============================================================================

class TestHandshakeVehicle:

    def test_create_client_hello_returns_bytes(self, keypair, pub_der):
        veh  = HandshakeVehicle("VH-V1", pub_der)
        msg1 = veh.create_client_hello()
        assert isinstance(msg1, bytes)
        assert veh.state == "HELLO_SENT"

    def test_nonce_v_is_fresh_each_time(self, keypair, pub_der):
        nonces = set()
        for _ in range(20):
            veh = HandshakeVehicle("VH-V2", pub_der)
            m1  = MSG1_ClientHello.from_bytes(veh.create_client_hello())
            nonces.add(m1.nonce_v)
        assert len(nonces) == 20, "Each ClientHello must have a unique nonce"

    def test_mitm_key_substitution_detected(self, keypair, pub_der):
        priv, pub = keypair
        _, trudy_pub = generate_rsa_keypair()

        ctrl = HandshakeController(priv, "VH-MIT")
        veh  = HandshakeVehicle("VH-MIT", pub_der, require_signature=False)
        msg1 = veh.create_client_hello()
        msg2 = ctrl.process_client_hello(msg1)

        # Replace RSA_pub with Trudy's key
        m2 = json.loads(msg2)
        m2["rsa_pub_der"] = serialize_public_key(trudy_pub).hex()
        m2["signature"]   = ""

        with pytest.raises(ValueError, match="mismatch"):
            veh.process_server_hello_and_create_key_package(
                json.dumps(m2, sort_keys=True).encode()
            )

    def test_invalid_signature_rejected(self, keypair, pub_der):
        priv, _ = keypair
        ctrl = HandshakeController(priv, "VH-SIG")
        veh  = HandshakeVehicle("VH-SIG", pub_der, require_signature=True)
        msg1 = veh.create_client_hello()
        msg2 = ctrl.process_client_hello(msg1)

        m2 = json.loads(msg2)
        sig = bytearray(bytes.fromhex(m2["signature"]))
        sig[0] ^= 0xFF
        m2["signature"] = bytes(sig).hex()

        with pytest.raises(ValueError, match="signature"):
            veh.process_server_hello_and_create_key_package(
                json.dumps(m2, sort_keys=True).encode()
            )

    def test_missing_signature_rejected_when_required(self, keypair, pub_der):
        priv, _ = keypair
        ctrl = HandshakeController(priv, "VH-NS")
        veh  = HandshakeVehicle("VH-NS", pub_der, require_signature=True)
        msg2 = ctrl.process_client_hello(veh.create_client_hello())
        m2 = json.loads(msg2); m2["signature"] = ""
        with pytest.raises(ValueError, match="missing"):
            veh.process_server_hello_and_create_key_package(
                json.dumps(m2, sort_keys=True).encode()
            )

    def test_msg4_wrong_token_rejected(self, keypair, pub_der):
        priv, _ = keypair
        ctrl = HandshakeController(priv, "VH-ACK")
        veh  = HandshakeVehicle("VH-ACK", pub_der)
        msg1 = veh.create_client_hello()
        msg2 = ctrl.process_client_hello(msg1)
        msg3 = veh.process_server_hello_and_create_key_package(msg2)
        msg4 = ctrl.process_key_package(msg3)

        # Corrupt the ciphertext in MSG 4
        m4 = json.loads(msg4)
        ct = bytearray(bytes.fromhex(m4["ciphertext"]))
        ct[0] ^= 0xFF
        m4["ciphertext"] = bytes(ct).hex()

        with pytest.raises(ValueError):
            veh.process_handshake_ack(json.dumps(m4, sort_keys=True).encode())


# =============================================================================
# Full Handshake Integration Tests
# =============================================================================

class TestFullHandshake:

    def test_session_keys_are_identical(self, fresh_handshake):
        v, c = fresh_handshake
        assert v.k_s == c.k_s
        assert v.k_m == c.k_m

    def test_session_ids_are_identical(self, fresh_handshake):
        v, c = fresh_handshake
        assert v.session_id == c.session_id

    def test_session_id_is_16_bytes(self, fresh_handshake):
        v, _ = fresh_handshake
        assert len(v.session_id) == SESSION_ID_BYTES

    def test_key_separation_enforced(self, fresh_handshake):
        v, _ = fresh_handshake
        assert v.k_s != v.k_m

    def test_key_sizes_are_correct(self, fresh_handshake):
        v, _ = fresh_handshake
        assert len(v.k_s) == 32   # AES-256
        assert len(v.k_m) == 32   # HMAC-SHA256

    def test_vehicle_encryptor_ready(self, fresh_handshake):
        v, _ = fresh_handshake
        assert v.vehicle_encryptor is not None

    def test_controller_decryptor_ready(self, fresh_handshake):
        _, c = fresh_handshake
        assert c.controller_decryptor is not None

    def test_different_handshakes_produce_different_keys(self, keypair, pub_der):
        priv, _ = keypair
        v1, _ = perform_full_handshake("VH-D1", priv, pub_der)
        v2, _ = perform_full_handshake("VH-D2", priv, pub_der)
        assert v1.k_s != v2.k_s   # Fresh CSPRNG keys per session
        assert v1.k_m != v2.k_m

    def test_post_handshake_aes_hmac_pipeline(self, keypair, pub_der):
        """Vehicle sends encrypted message; controller decrypts and verifies."""
        priv, _ = keypair
        v_sess, c_sess = perform_full_handshake("VH-PIPE", priv, pub_der)

        payload = {"speed": 88.5, "zone": "B2", "status": "MOVING"}
        pkt     = v_sess.vehicle_encryptor.send(payload)
        result  = c_sess.controller_decryptor.receive(pkt)

        assert result["status"] == "OK"
        assert result["payload"]["speed"] == 88.5
        assert result["payload"]["zone"]  == "B2"

    def test_post_handshake_multi_message(self, keypair, pub_der):
        priv, _ = keypair
        v_sess, c_sess = perform_full_handshake("VH-MULTI", priv, pub_der)
        for i in range(5):
            pkt    = v_sess.vehicle_encryptor.send({"seq": i})
            result = c_sess.controller_decryptor.receive(pkt)
            assert result["status"] == "OK"
            assert result["payload"]["seq"] == i

    def test_post_handshake_replay_rejected(self, keypair, pub_der):
        priv, _ = keypair
        v_sess, c_sess = perform_full_handshake("VH-RPL2", priv, pub_der)
        pkt  = v_sess.vehicle_encryptor.send({"action": "unlock"})
        r1   = c_sess.controller_decryptor.receive(pkt)
        r2   = c_sess.controller_decryptor.receive(pkt)
        assert r1["status"] == "OK"
        assert r2["status"] == "REPLAY"

    def test_cross_vehicle_isolation(self, keypair, pub_der):
        priv, _ = keypair
        v1, c1 = perform_full_handshake("VH-ISO1", priv, pub_der)
        v2, c2 = perform_full_handshake("VH-ISO2", priv, pub_der)
        pkt = v1.vehicle_encryptor.send({"data": "secret"})
        assert c2.controller_decryptor.receive(pkt)["status"] == "HMAC_FAIL"