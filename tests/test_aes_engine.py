"""
=============================================================================
MODULE 2 — UNIT TEST SUITE
AES-256-CBC Encryption Engine
=============================================================================
Group 29 | EE8257 Information Security

Run: python3 -m pytest test_aes_engine.py -v
=============================================================================
"""

import pytest
import copy
import json
import time
import struct

from modules.aes_engine import (
    AESEngine,
    ECBDemoEngine,
    EncryptedPacket,
    VehicleEncryptor,
    ControllerDecryptor,
    generate_aes_key,
    generate_iv,
    generate_mac_key,
    _pkcs7_pad,
    _pkcs7_unpad,
    _aes_cbc_encrypt_raw,
    _aes_cbc_decrypt_raw,
    AES_KEY_SIZE,
    AES_BLOCK_SIZE,
    IV_SIZE,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def keys():
    return generate_aes_key(32), generate_mac_key(32)

@pytest.fixture
def engine(keys):
    return AESEngine(*keys)

@pytest.fixture
def enc_dec(keys):
    ks, km = keys
    return VehicleEncryptor("VH-TEST", ks, km), ControllerDecryptor(ks, km)


# ── Key / IV Generation ───────────────────────────────────────────────────────

class TestKeyGeneration:
    def test_aes_key_32_bytes(self):
        assert len(generate_aes_key(32)) == 32

    def test_aes_key_16_bytes(self):
        assert len(generate_aes_key(16)) == 16

    def test_invalid_aes_key_length(self):
        with pytest.raises(ValueError):
            generate_aes_key(31)

    def test_aes_keys_unique(self):
        keys = {generate_aes_key(32) for _ in range(100)}
        assert len(keys) == 100

    def test_iv_is_16_bytes(self):
        assert len(generate_iv()) == IV_SIZE

    def test_ivs_unique(self):
        ivs = {generate_iv() for _ in range(200)}
        assert len(ivs) == 200


# ── PKCS7 Padding ────────────────────────────────────────────────────────────

class TestPKCS7Padding:
    @pytest.mark.parametrize("length,expected_padded", [
        (10, 16),    # pad 6
        (16, 32),    # full extra block
        (20, 32),    # pad 12
        (31, 32),    # pad 1
        (32, 48),    # full extra block again
        (1,  16),    # pad 15
    ])
    def test_padded_length(self, length, expected_padded):
        data   = b'X' * length
        padded = _pkcs7_pad(data)
        assert len(padded) == expected_padded
        assert len(padded) % 16 == 0

    def test_pad_byte_value(self):
        data   = b'A' * 10    # need 6 bytes of padding
        padded = _pkcs7_pad(data)
        assert padded[-1] == 6
        assert padded[-6:] == bytes([6] * 6)

    def test_round_trip(self):
        for length in [1, 7, 15, 16, 17, 31, 32, 100]:
            data = bytes(range(length % 256)) * (length // 256 + 1)
            data = data[:length]
            assert _pkcs7_unpad(_pkcs7_pad(data)) == data

    def test_full_block_padding(self):
        data   = b'B' * 16    # aligned — full extra block must be added
        padded = _pkcs7_pad(data)
        assert len(padded) == 32
        assert padded[-1] == 16

    def test_unpad_malformed_raises(self):
        bad = b'A' * 16 + bytes([5] * 3)   # claims N=3 but only 3 bytes, length mod16 != 0
        with pytest.raises(Exception):
            _pkcs7_unpad(bad)


# ── AES-CBC Raw Primitives ────────────────────────────────────────────────────

class TestAESCBCRaw:
    def test_encrypt_decrypt_round_trip(self):
        key      = generate_aes_key(32)
        iv       = generate_iv()
        pt       = b'Hello Vehicle!' + b'\x02\x02'   # padded to 16 manually
        padded   = _pkcs7_pad(pt)
        ct       = _aes_cbc_encrypt_raw(padded, key, iv)
        dec      = _aes_cbc_decrypt_raw(ct, key, iv)
        assert _pkcs7_unpad(dec) == pt

    def test_ciphertext_length_equals_padded_length(self):
        key     = generate_aes_key(32)
        iv      = generate_iv()
        padded  = _pkcs7_pad(b'A' * 20)
        ct      = _aes_cbc_encrypt_raw(padded, key, iv)
        assert len(ct) == len(padded)
        assert len(ct) % 16 == 0

    def test_different_iv_different_ciphertext(self):
        key   = generate_aes_key(32)
        iv1, iv2 = generate_iv(), generate_iv()
        padded = _pkcs7_pad(b'same message content XY')
        ct1 = _aes_cbc_encrypt_raw(padded, key, iv1)
        ct2 = _aes_cbc_encrypt_raw(padded, key, iv2)
        assert ct1 != ct2

    def test_different_key_different_ciphertext(self):
        k1, k2  = generate_aes_key(32), generate_aes_key(32)
        iv      = generate_iv()
        padded  = _pkcs7_pad(b'message')
        assert _aes_cbc_encrypt_raw(padded, k1, iv) != _aes_cbc_encrypt_raw(padded, k2, iv)

    def test_unpadded_input_raises(self):
        key = generate_aes_key(32)
        iv  = generate_iv()
        with pytest.raises(ValueError):
            _aes_cbc_encrypt_raw(b'not padded', key, iv)   # length 10, not multiple of 16


# ── AESEngine ─────────────────────────────────────────────────────────────────

class TestAESEngine:
    def test_engine_rejects_same_key_for_aes_and_mac(self):
        key = generate_aes_key(32)
        with pytest.raises(ValueError, match="MUST be different"):
            AESEngine(key, key)

    def test_engine_rejects_invalid_aes_key_length(self):
        with pytest.raises(ValueError):
            AESEngine(b'short', generate_mac_key(32))

    def test_encrypt_returns_encrypted_packet(self, engine):
        pkt = engine.encrypt(b'test payload', 'VH-001', 1)
        assert isinstance(pkt, EncryptedPacket)
        assert len(pkt.iv) == IV_SIZE
        assert len(pkt.hmac_tag) == 32
        assert len(pkt.ciphertext) % AES_BLOCK_SIZE == 0

    def test_encrypt_decrypt_round_trip(self, engine):
        pt  = b'{"speed": 87.4, "zone": "B2"}'
        pkt = engine.encrypt(pt, 'VH-002', 1)
        dec = engine.decrypt(pkt)
        assert dec == pt

    def test_tampered_ciphertext_raises(self, engine):
        pkt = engine.encrypt(b'secret command', 'VH-003', 1)
        bad = copy.deepcopy(pkt)
        ct  = bytearray(bad.ciphertext)
        ct[0] ^= 0xFF
        bad.ciphertext = bytes(ct)
        with pytest.raises(ValueError, match="HMAC"):
            engine.decrypt(bad)

    def test_tampered_iv_raises(self, engine):
        pkt = engine.encrypt(b'payload', 'VH-004', 1)
        bad = copy.deepcopy(pkt)
        iv  = bytearray(bad.iv)
        iv[0] ^= 0x01
        bad.iv = bytes(iv)
        with pytest.raises(ValueError, match="HMAC"):
            engine.decrypt(bad)

    def test_different_iv_per_message(self, engine):
        """Same plaintext → different ciphertext → different IV each time."""
        pkts = [engine.encrypt(b'same content repeated', 'VH-005', i) for i in range(1, 11)]
        ivs  = {p.iv for p in pkts}
        cts  = {p.ciphertext for p in pkts}
        assert len(ivs) == 10, "All IVs should be unique"
        assert len(cts) == 10, "All ciphertexts should be unique"

    def test_empty_plaintext_raises(self, engine):
        with pytest.raises(ValueError):
            engine.encrypt(b'', 'VH-006', 1)

    def test_wrong_key_raises(self, keys):
        ks1, km1 = keys
        ks2, km2 = generate_aes_key(32), generate_mac_key(32)
        eng1 = AESEngine(ks1, km1)
        eng2 = AESEngine(ks2, km2)
        pkt  = eng1.encrypt(b'secret data', 'VH-007', 1)
        with pytest.raises(ValueError):
            eng2.decrypt(pkt)

    def test_large_payload(self, engine):
        large = b'X' * 10_000
        pkt   = engine.encrypt(large, 'VH-008', 1)
        dec   = engine.decrypt(pkt)
        assert dec == large


# ── EncryptedPacket Serialisation ─────────────────────────────────────────────

class TestEncryptedPacketSerialisation:
    def test_round_trip_preserves_all_fields(self, engine):
        pkt      = engine.encrypt(b'test payload round trip', 'VH-SERIAL', 42)
        wire     = pkt.to_bytes()
        restored = EncryptedPacket.from_bytes(wire)

        assert restored.iv          == pkt.iv
        assert restored.ciphertext  == pkt.ciphertext
        assert restored.hmac_tag    == pkt.hmac_tag
        assert restored.vehicle_id  == pkt.vehicle_id
        assert restored.sequence_no == pkt.sequence_no
        assert abs(restored.timestamp - pkt.timestamp) < 1e-6

    def test_restored_packet_decrypts(self, engine):
        pt   = b'round trip decryption test'
        pkt  = engine.encrypt(pt, 'VH-RT', 1)
        rest = EncryptedPacket.from_bytes(pkt.to_bytes())
        assert engine.decrypt(rest) == pt

    def test_hmac_scope_excludes_hmac_tag(self, engine):
        pkt1 = engine.encrypt(b'message', 'VH-SCOPE', 1)
        pkt2 = copy.deepcopy(pkt1)
        pkt2.hmac_tag = b'\x00' * 32
        # Scope should be identical (tag not in scope)
        assert pkt1.hmac_scope() == pkt2.hmac_scope()


# ── Sender / Receiver Integration ─────────────────────────────────────────────

class TestVehicleEncryptorDecryptor:
    def test_normal_exchange(self, enc_dec):
        enc, dec = enc_dec
        pkt    = enc.send({"speed": 60.0, "zone": "B1"})
        result = dec.receive(pkt)
        assert result["status"] == "OK"
        assert result["payload"]["speed"] == 60.0
        assert result["payload"]["zone"]  == "B1"

    def test_sequence_numbers_increment(self, enc_dec):
        enc, _ = enc_dec
        pkts = [enc.send({"i": i}) for i in range(5)]
        seqs = [p.sequence_no for p in pkts]
        assert seqs == [1, 2, 3, 4, 5]

    def test_replay_rejected(self, enc_dec):
        enc, dec = enc_dec
        pkt = enc.send({"action": "unlock"})
        r1  = dec.receive(pkt)
        r2  = dec.receive(pkt)    # replay
        assert r1["status"] == "OK"
        assert r2["status"] == "REPLAY"

    def test_stale_timestamp_rejected(self, keys):
        ks, km  = keys
        engine  = AESEngine(ks, km)
        dec     = ControllerDecryptor(ks, km)
        old_ts  = time.time() - 3600
        pkt     = engine.encrypt(b'old message', 'VH-STALE', 1, timestamp=old_ts)
        result  = dec.receive(pkt)
        assert result["status"] == "STALE_TS"

    def test_cross_vehicle_isolation(self, keys):
        ks1, km1 = keys
        ks2, km2 = generate_aes_key(32), generate_mac_key(32)
        enc1 = VehicleEncryptor("VH-A", ks1, km1)
        dec2 = ControllerDecryptor(ks2, km2)
        pkt  = enc1.send({"data": "secret"})
        result = dec2.receive(pkt)
        assert result["status"] == "HMAC_FAIL"

    def test_multi_message_session(self, enc_dec):
        enc, dec = enc_dec
        for i in range(10):
            pkt    = enc.send({"seq": i, "value": float(i)})
            result = dec.receive(pkt)
            assert result["status"] == "OK"
            assert result["payload"]["seq"] == i


# ── ECB Demo Engine ───────────────────────────────────────────────────────────

class TestECBPatternLeakage:
    def test_identical_blocks_produce_identical_ciphertext(self):
        """Core ECB weakness: same input block → same output block."""
        key       = generate_aes_key(32)
        ecb       = ECBDemoEngine(key)
        block     = b'A' * 16               # exactly one block
        msg       = block + block + block   # three identical blocks
        ct        = ecb.encrypt_ecb(msg)
        # ECB: all three encrypted blocks should be identical
        ct_blocks = [ct[i*16:(i+1)*16] for i in range(3)]
        assert ct_blocks[0] == ct_blocks[1] == ct_blocks[2], \
            "ECB should produce identical ciphertext for identical plaintext blocks"

    def test_cbc_does_not_leak_pattern(self, engine):
        """CBC: same input block → different output block due to chaining."""
        block = b'A' * 16
        msg   = block + block + block
        pkt   = engine.encrypt(msg, 'VH-ECB', 1)
        ct    = pkt.ciphertext
        # CBC: all three encrypted blocks should be DIFFERENT
        ct_blocks = [ct[i*16:(i+1)*16] for i in range(3)]
        assert not (ct_blocks[0] == ct_blocks[1] == ct_blocks[2]), \
            "CBC should NOT produce identical blocks for identical plaintext blocks"

    def test_ecb_round_trip(self):
        key  = generate_aes_key(32)
        ecb  = ECBDemoEngine(key)
        msg  = b'Test ECB round-trip message!'
        ct   = ecb.encrypt_ecb(msg)
        dec  = ecb.decrypt_ecb(ct)
        assert dec == msg
