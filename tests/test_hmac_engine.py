"""
=============================================================================
MODULE 1 — UNIT TEST SUITE
HMAC-SHA256 Authentication Engine
=============================================================================
Group 29 | EE8257 Information Security

Run with:  python3 -m pytest test_hmac_engine.py -v
=============================================================================
"""

import pytest
import time
import json
import copy
from modules.hmac_engine import (
    generate_mac_key,
    HMACEngine,
    VehicleMessage,
    VehicleSender,
    ControllerReceiver,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mac_key():
    return generate_mac_key(32)

@pytest.fixture
def engine(mac_key):
    return HMACEngine(mac_key)

@pytest.fixture
def sender_receiver(mac_key):
    sender   = VehicleSender("VH-TEST", mac_key)
    receiver = ControllerReceiver(mac_key)
    return sender, receiver


# ── Key Generation Tests ──────────────────────────────────────────────────────

class TestKeyGeneration:
    def test_key_length_32(self):
        key = generate_mac_key(32)
        assert len(key) == 32

    def test_key_is_bytes(self):
        assert isinstance(generate_mac_key(32), bytes)

    def test_keys_are_unique(self):
        keys = {generate_mac_key(32) for _ in range(100)}
        assert len(keys) == 100, "All keys should be unique (CSPRNG)"

    def test_minimum_key_length(self):
        with pytest.raises(ValueError):
            generate_mac_key(8)   # too short

    def test_exact_minimum(self):
        key = generate_mac_key(16)
        assert len(key) == 16


# ── HMACEngine Core Tests ─────────────────────────────────────────────────────

class TestHMACEngine:
    def test_generate_returns_32_bytes(self, engine):
        tag = engine.generate(b"test message")
        assert len(tag) == 32

    def test_generate_returns_bytes(self, engine):
        assert isinstance(engine.generate(b"msg"), bytes)

    def test_verify_valid_message(self, engine):
        msg = b"speed=87.4 zone=B2"
        tag = engine.generate(msg)
        assert engine.verify(msg, tag) is True

    def test_verify_tampered_message(self, engine):
        msg     = b"speed=87.4 zone=B2"
        tag     = engine.generate(msg)
        tampered = b"speed=99.9 zone=B2"
        assert engine.verify(tampered, tag) is False

    def test_verify_wrong_key(self, mac_key):
        other_key = generate_mac_key(32)
        engine_a  = HMACEngine(mac_key)
        engine_b  = HMACEngine(other_key)
        msg = b"unlock door"
        tag = engine_a.generate(msg)
        assert engine_b.verify(msg, tag) is False

    def test_verify_wrong_length_mac(self, engine):
        msg = b"test"
        assert engine.verify(msg, b"short") is False

    def test_deterministic_output(self, mac_key):
        # Same key + same message = same HMAC (deterministic)
        e1 = HMACEngine(mac_key)
        e2 = HMACEngine(mac_key)
        msg = b"deterministic test"
        assert e1.generate(msg) == e2.generate(msg)

    def test_different_messages_different_macs(self, engine):
        assert engine.generate(b"msg_a") != engine.generate(b"msg_b")

    def test_avalanche_effect(self, engine):
        base    = b"speed=87.4"
        tweaked = b"speed=87.5"   # one character difference
        mac_a   = engine.generate(base)
        mac_b   = engine.generate(tweaked)
        assert mac_a != mac_b
        # Expect roughly 50% bit difference (avalanche)
        xor = int.from_bytes(mac_a, 'big') ^ int.from_bytes(mac_b, 'big')
        diff_bits = bin(xor).count('1')
        assert diff_bits > 64, "Avalanche: expect >25% bit flip"

    def test_empty_message(self, engine):
        # HMAC of empty bytes must still produce valid 32-byte tag
        tag = engine.generate(b"")
        assert len(tag) == 32
        assert engine.verify(b"", tag) is True

    def test_non_bytes_message_raises(self, engine):
        with pytest.raises(TypeError):
            engine.generate("string not bytes")

    def test_non_bytes_mac_raises(self, engine):
        with pytest.raises(TypeError):
            engine.verify(b"msg", "not bytes")

    def test_key_too_short_raises(self):
        with pytest.raises(ValueError):
            HMACEngine(b"short")


# ── VehicleMessage Serialisation Tests ───────────────────────────────────────

class TestVehicleMessage:
    def test_to_bytes_is_bytes(self):
        msg = VehicleMessage("VH-001", "TELEMETRY", {"speed": 55.0})
        assert isinstance(msg.to_bytes(), bytes)

    def test_to_bytes_is_valid_json(self):
        msg = VehicleMessage("VH-001", "TELEMETRY", {"speed": 55.0})
        parsed = json.loads(msg.to_bytes().decode())
        assert parsed["vehicle_id"] == "VH-001"
        assert parsed["message_type"] == "TELEMETRY"

    def test_nonce_is_unique(self):
        msgs = [VehicleMessage("VH-001", "T", {}) for _ in range(50)]
        nonces = {json.loads(m.to_bytes())["nonce"] for m in msgs}
        assert len(nonces) == 50, "Each nonce should be unique"

    def test_canonical_serialisation_consistent(self):
        import secrets as _s
        nonce = _s.token_bytes(16)
        ts    = 1700000000.123456
        msg   = VehicleMessage(
            vehicle_id="VH-001", message_type="T",
            payload={"x": 1}, timestamp=ts, nonce=nonce, sequence_no=5
        )
        # Same object → same bytes
        assert msg.to_bytes() == msg.to_bytes()


# ── Sender / Receiver Integration Tests ──────────────────────────────────────

class TestSenderReceiver:
    def test_normal_exchange_accepted(self, sender_receiver):
        sender, receiver = sender_receiver
        packet = sender.send_message("TELEMETRY", {"speed": 60.0})
        result = receiver.receive_message(packet)
        assert result["status"] == "OK"
        assert result["payload"] == {"speed": 60.0}

    def test_tampered_message_rejected(self, sender_receiver):
        sender, receiver = sender_receiver
        packet = sender.send_message("TELEMETRY", {"speed": 60.0})

        # Tamper with the message bytes
        msg_dict = json.loads(packet["message_bytes"])
        msg_dict["payload"]["speed"] = 200.0
        packet["message_bytes"] = json.dumps(msg_dict, sort_keys=True).encode()

        result = receiver.receive_message(packet)
        assert result["status"] == "HMAC_FAIL"
        assert result["payload"] is None

    def test_wrong_key_rejected(self, mac_key):
        wrong_key = generate_mac_key(32)
        sender    = VehicleSender("VH-X", wrong_key)
        receiver  = ControllerReceiver(mac_key)
        packet    = sender.send_message("T", {})
        result    = receiver.receive_message(packet)
        assert result["status"] == "HMAC_FAIL"

    def test_replay_attack_rejected(self, sender_receiver):
        sender, receiver = sender_receiver
        packet = sender.send_message("COMMAND", {"action": "UNLOCK"})
        r1 = receiver.receive_message(packet)
        r2 = receiver.receive_message(packet)   # replay
        assert r1["status"] == "OK"
        assert r2["status"] == "REPLAY"

    def test_sequence_numbers_increment(self, sender_receiver):
        sender, receiver = sender_receiver
        p1 = sender.send_message("T", {})
        p2 = sender.send_message("T", {})
        p3 = sender.send_message("T", {})
        assert p1["sequence_no"] == 1
        assert p2["sequence_no"] == 2
        assert p3["sequence_no"] == 3

    def test_multiple_vehicles_independent(self, mac_key):
        other_key = generate_mac_key(32)
        s1 = VehicleSender("VH-A", mac_key)
        s2 = VehicleSender("VH-B", other_key)
        r1 = ControllerReceiver(mac_key)
        r2 = ControllerReceiver(other_key)

        p1 = s1.send_message("T", {"v": 1})
        p2 = s2.send_message("T", {"v": 2})

        assert r1.receive_message(p1)["status"] == "OK"
        assert r2.receive_message(p2)["status"] == "OK"
        # Cross: vehicle A's packet rejected by vehicle B's receiver
        assert r2.receive_message(p1)["status"] == "HMAC_FAIL"

    def test_stale_timestamp_rejected(self, mac_key):
        """Simulate a message with a very old timestamp."""
        import secrets as _s
        sender   = VehicleSender("VH-OLD", mac_key)
        receiver = ControllerReceiver(mac_key)

        packet = sender.send_message("T", {"data": "old"})

        # Manually inject an old timestamp into the message bytes
        msg_dict = json.loads(packet["message_bytes"])
        msg_dict["timestamp"] = time.time() - 3600   # 1 hour ago

        # Re-sign with the real key (legitimate but stale sender)
        engine = HMACEngine(mac_key)
        new_bytes = json.dumps(msg_dict, sort_keys=True).encode()
        packet["message_bytes"] = new_bytes
        packet["hmac_tag"] = engine.generate(new_bytes)

        result = receiver.receive_message(packet)
        assert result["status"] == "STALE_TS"
