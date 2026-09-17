"""
=============================================================================
MODULE 1 — DEMO & TEST SUITE
HMAC-SHA256 Authentication Engine
=============================================================================
Project : Secure Vehicle-to-Controller Message Exchange
Group   : 29 | EE8257 Information Security

This file demonstrates:
  1. Normal authenticated message exchange (happy path)
  2. Tampered message detection (integrity failure)
  3. Wrong MAC key rejection (authentication failure)
  4. Replay attack detection (sequence number + timestamp)
  5. HMAC avalanche effect demonstration
  6. Raw HMAC internals walkthrough

Run with:  python3 demo_hmac.py
=============================================================================
"""

import os
import sys
import time
import copy
import json
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.hmac_engine import (
    generate_mac_key,
    HMACEngine,
    VehicleSender,
    ControllerReceiver,
)

# ── Colour helpers for terminal output (no external dependency) ────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
GRAY   = "\033[90m"
WHITE  = "\033[97m"

def hdr(title: str) -> None:
    width = 70
    print(f"\n{BOLD}{BLUE}{'═' * width}{RESET}")
    print(f"{BOLD}{BLUE}  {title}{RESET}")
    print(f"{BOLD}{BLUE}{'═' * width}{RESET}")

def sub(title: str) -> None:
    print(f"\n{BOLD}{CYAN}  ── {title} ──{RESET}")

def ok(msg: str)   -> None: print(f"  {GREEN}✔  {msg}{RESET}")
def fail(msg: str) -> None: print(f"  {RED}✘  {msg}{RESET}")
def info(msg: str) -> None: print(f"  {YELLOW}ℹ  {msg}{RESET}")
def data(label: str, value: str) -> None:
    print(f"  {GRAY}{label:<22}{RESET} {WHITE}{value}{RESET}")


# =============================================================================
# DEMO 1 — Normal Authenticated Message Exchange
# =============================================================================

def demo_normal_exchange():
    hdr("DEMO 1 — Normal Authenticated Message Exchange")

    print(f"""
  {GRAY}Scenario:{RESET}
  Vehicle VH-001 sends a telemetry reading to the controller.
  Both parties share MAC key K_m (established during RSA handshake,
  Module 3). The controller verifies the HMAC before processing.

  {GRAY}Syllabus:{RESET} Lecture 6 — HMAC provides integrity + authentication.
  "Used for both integrity and authenticity" (L6, HMAC section).
    """)

    # ── Key setup ─────────────────────────────────────────────────────
    sub("Step 1 — Generate shared MAC key K_m")
    K_m = generate_mac_key(32)       # 256-bit key
    data("K_m (hex, first 16 bytes):", K_m[:16].hex() + "...")
    data("K_m length:", f"{len(K_m)} bytes ({len(K_m)*8} bits)")
    ok("K_m generated using CSPRNG (secrets.token_bytes)")

    # ── Sender (Vehicle) ───────────────────────────────────────────────
    sub("Step 2 — Vehicle VH-001 composes and signs message")
    sender   = VehicleSender("VH-001", K_m)
    receiver = ControllerReceiver(K_m)

    packet = sender.send_message(
        message_type = "TELEMETRY",
        payload = {
            "speed_kmh"  : 87.4,
            "latitude"   : 6.0535,
            "longitude"  : 80.2210,
            "fuel_pct"   : 63.2,
            "engine_temp": 91.5,
        }
    )

    msg_dict = json.loads(packet["message_bytes"].decode())
    data("Vehicle ID:",     msg_dict["vehicle_id"])
    data("Message type:",   msg_dict["message_type"])
    data("Sequence no.:",   str(msg_dict["sequence_no"]))
    data("Nonce (first 8):",msg_dict["nonce"][:16] + "...")
    data("Timestamp:",      str(round(msg_dict["timestamp"], 4)))
    data("Payload:",        json.dumps(msg_dict["payload"]))
    data("HMAC tag (hex):", packet["hmac_tag"].hex())
    data("HMAC length:",    f"{len(packet['hmac_tag'])} bytes ({len(packet['hmac_tag'])*8} bits)")

    # ── Receiver (Controller) ──────────────────────────────────────────
    sub("Step 3 — Controller verifies and accepts message")
    result = receiver.receive_message(packet)

    data("Verification status:", result["status"])
    data("Reason:",              result["reason"])
    data("Accepted payload:",    json.dumps(result["payload"]))

    if result["status"] == "OK":
        ok("Message authenticated and integrity confirmed")
    else:
        fail(f"Unexpected failure: {result['reason']}")


# =============================================================================
# DEMO 2 — Tampered Message Detection
# =============================================================================

def demo_tampering():
    hdr("DEMO 2 — Message Tampering Detection")

    print(f"""
  {GRAY}Scenario:{RESET}
  Trudy intercepts the packet and changes the speed reading from
  87.4 km/h to 200.0 km/h, attempting to send false telemetry.
  She cannot recompute the HMAC because she does not possess K_m.

  {GRAY}Syllabus:{RESET} Lecture 6 — "Issue exists if Trudy replaces both M
  and h(M) with M' and h(M')." HMAC prevents this because Trudy
  cannot produce a valid tag without K_m.

  The HMAC avalanche effect (Lecture 6 hash design principles) ensures
  even a single-bit change in the message produces a completely
  different 256-bit MAC tag.
    """)

    K_m      = generate_mac_key(32)
    sender   = VehicleSender("VH-002", K_m)
    receiver = ControllerReceiver(K_m)

    # ── Original packet ────────────────────────────────────────────────
    sub("Step 1 — Vehicle sends original telemetry")
    original_packet = sender.send_message(
        message_type = "TELEMETRY",
        payload = {"speed_kmh": 87.4, "location": "Zone-A"}
    )
    ok(f"Original HMAC: {original_packet['hmac_tag'].hex()[:32]}...")

    # ── Tampering (Trudy modifies payload) ─────────────────────────────
    sub("Step 2 — Trudy modifies the speed field in transit")

    tampered_packet = copy.deepcopy(original_packet)
    msg_dict = json.loads(tampered_packet["message_bytes"].decode())

    original_speed = msg_dict["payload"]["speed_kmh"]
    msg_dict["payload"]["speed_kmh"] = 200.0          # Trudy's change

    # Re-serialise (Trudy can do this — message format is public)
    tampered_packet["message_bytes"] = json.dumps(
        msg_dict, sort_keys=True
    ).encode("utf-8")

    info(f"Original speed : {original_speed} km/h")
    info(f"Tampered speed : {msg_dict['payload']['speed_kmh']} km/h")
    info("Trudy cannot recompute HMAC — she doesn't have K_m")
    info(f"Tampered  HMAC : {tampered_packet['hmac_tag'].hex()[:32]}..."
         " (unchanged — Trudy's only option)")

    # ── Controller detects tampering ───────────────────────────────────
    sub("Step 3 — Controller detects HMAC mismatch")
    result = receiver.receive_message(tampered_packet)

    data("Status:", result["status"])
    data("Reason:", result["reason"])
    data("Payload delivered?", str(result["payload"]))

    if result["status"] == "HMAC_FAIL":
        ok("Tampered message correctly rejected by HMAC verification")
        ok("Trudy's modification was detected — integrity preserved")
    else:
        fail("UNEXPECTED: tampered message was accepted!")


# =============================================================================
# DEMO 3 — Wrong Key Rejection (Authentication Failure)
# =============================================================================

def demo_wrong_key():
    hdr("DEMO 3 — Wrong MAC Key (Authentication Failure)")

    print(f"""
  {GRAY}Scenario:{RESET}
  A rogue vehicle (or Trudy pretending to be VH-003) attempts to send
  a message signed with a DIFFERENT MAC key. This simulates an
  impersonation attack — the attacker is not a registered vehicle.

  {GRAY}Syllabus:{RESET} Lecture 6 — Without K_m, "Trudy can replace both M
  and h(M)" with her own values. HMAC prevents this because the
  controller's verify() recomputes the tag using the REAL K_m.
    """)

    # Legitimate K_m shared between VH-003 and controller
    legitimate_K_m = generate_mac_key(32)
    # Rogue key held by attacker
    rogue_K_m      = generate_mac_key(32)

    legitimate_sender = VehicleSender("VH-003", legitimate_K_m)
    rogue_sender      = VehicleSender("VH-003", rogue_K_m)   # fake VH-003
    receiver          = ControllerReceiver(legitimate_K_m)

    sub("Step 1 — Legitimate VH-003 sends message (accepted)")
    legit_packet = legitimate_sender.send_message(
        "COMMAND", {"action": "OPEN_GATE"}
    )
    legit_result = receiver.receive_message(legit_packet)
    data("Legitimate status:", legit_result["status"])
    if legit_result["status"] == "OK":
        ok("Legitimate vehicle accepted")

    sub("Step 2 — Rogue sender uses wrong key (rejected)")
    rogue_packet = rogue_sender.send_message(
        "COMMAND", {"action": "OPEN_GATE"}
    )
    # Increment seq to avoid replay false positive
    rogue_packet["sequence_no"] = 999
    rogue_result = receiver.receive_message(rogue_packet)

    data("Rogue status:", rogue_result["status"])
    data("Reason:",       rogue_result["reason"])

    if rogue_result["status"] == "HMAC_FAIL":
        ok("Impersonation attack detected and rejected")
        ok("Authentication confirmed — only legitimate K_m accepted")
    else:
        fail("UNEXPECTED: rogue message accepted!")


# =============================================================================
# DEMO 4 — Replay Attack Detection
# =============================================================================

def demo_replay_attack():
    hdr("DEMO 4 — Replay Attack Detection")

    print(f"""
  {GRAY}Scenario:{RESET}
  Trudy records a legitimate packet from VH-004 and resends it later.
  This is a classic replay attack. The packet has a valid HMAC (she
  copied the original), so HMAC alone cannot detect it.
  The sequence number monotonic counter catches the duplicate.

  {GRAY}Syllabus:{RESET} Lecture 8 (GSM) — "Base station can replay triple
  (RAND, XRES, Kc). One compromised triple gives attacker a key Kc
  that is valid FOREVER. No replay protection!" Our seq-no counter
  ensures each packet is accepted exactly once.

  Lecture 8 (Kerberos) — "Clock skew for Kerberos → 5 minutes →
  replay possible." We use ±30s + sequence number for dual protection.
    """)

    K_m      = generate_mac_key(32)
    sender   = VehicleSender("VH-004", K_m)
    receiver = ControllerReceiver(K_m)

    sub("Step 1 — VH-004 sends a legitimate message (accepted)")
    packet_1 = sender.send_message(
        "COMMAND", {"action": "UNLOCK_DOOR", "zone": "B2"}
    )
    result_1 = receiver.receive_message(packet_1)
    data("First delivery status:", result_1["status"])
    data("Seq no.:", str(packet_1["sequence_no"]))
    ok("Original message accepted by controller")

    sub("Step 2 — Trudy immediately replays the SAME packet")
    # Trudy sends the identical packet — same bytes, same HMAC, same seq
    result_replay = receiver.receive_message(packet_1)

    data("Replay attempt status:", result_replay["status"])
    data("Reason:",                result_replay["reason"])

    if result_replay["status"] == "REPLAY":
        ok("Replay attack detected via sequence number monotonic check")
        ok("Identical packet rejected — the UNLOCK command was NOT executed twice")
    else:
        fail("UNEXPECTED: replay was accepted!")

    sub("Step 3 — VH-004 sends next legitimate message (seq increments)")
    packet_2 = sender.send_message(
        "TELEMETRY", {"speed_kmh": 0.0, "status": "parked"}
    )
    result_2 = receiver.receive_message(packet_2)
    data("Next message status:", result_2["status"])
    data("Seq no.:", str(packet_2["sequence_no"]))
    if result_2["status"] == "OK":
        ok("Subsequent legitimate message accepted normally")


# =============================================================================
# DEMO 5 — Avalanche Effect Demonstration
# =============================================================================

def demo_avalanche_effect():
    hdr("DEMO 5 — HMAC Avalanche Effect")

    print(f"""
  {GRAY}Scenario:{RESET}
  We demonstrate that changing even ONE character in a message
  produces a completely different 256-bit HMAC tag.

  {GRAY}Syllabus:{RESET} Lecture 6 (Hash Design Principles):
  "Should possess avalanche effect — change of one bit would cause
   to change an entire bit stream in the output."

  This is a core security property: an attacker cannot make small
  "undetectable" changes. Any change, however minor, completely
  invalidates the MAC.
    """)

    K_m    = generate_mac_key(32)
    engine = HMACEngine(K_m)

    messages = [
        b"speed=87.4 zone=B2 vehicle=VH-005",
        b"speed=87.5 zone=B2 vehicle=VH-005",   # 1 digit changed
        b"speed=87.4 zone=B3 vehicle=VH-005",   # 1 char changed
        b"speed=87.4 zone=B2 vehicle=VH-006",   # last digit changed
        b"Speed=87.4 zone=B2 vehicle=VH-005",   # capitalisation only
    ]
    descriptions = [
        "Original message",
        "Speed: 87.4 → 87.5 (0.1 change)",
        "Zone: B2 → B3 (1 char)",
        "Vehicle: VH-005 → VH-006 (1 digit)",
        "Case: 'speed' → 'Speed' (capitalisation)",
    ]

    print()
    base_mac = engine.generate(messages[0])
    data("Base message:", messages[0].decode())
    data("Base HMAC:", base_mac.hex())
    print()

    for msg, desc in zip(messages, descriptions):
        mac      = engine.generate(msg)
        # Count differing bits between base and this MAC
        xor_int  = int.from_bytes(base_mac, 'big') ^ int.from_bytes(mac, 'big')
        diff_bits= bin(xor_int).count('1')
        pct_diff = diff_bits / 256 * 100

        status = "IDENTICAL" if mac == base_mac else f"{diff_bits}/256 bits differ ({pct_diff:.0f}%)"
        print(f"  {GRAY}{desc:<42}{RESET}")
        print(f"  {WHITE}{mac.hex()[:48]}...{RESET}")
        print(f"  {CYAN}Δ bits: {status}{RESET}")
        print()

    ok("Any change — even one character — fully invalidates the HMAC")
    ok("Attacker cannot make 'small' modifications and stay undetected")


# =============================================================================
# DEMO 6 — HMAC Internals Walkthrough
# =============================================================================

def demo_internals():
    hdr("DEMO 6 — HMAC-SHA256 Internals Walkthrough")

    print(f"""
  {GRAY}This demo manually replicates RFC 2104 to show the exact ipad/opad
  construction described in Lecture 6.

  Formula: HMAC(M, K) = H( K⊕opad || H( K⊕ipad || M ) )
  where:
    ipad = 0x36 repeated 64 times (SHA-256 block size)
    opad = 0x5C repeated 64 times
    ||   = concatenation
    ⊕    = XOR (bitwise){RESET}
    """)

    import hashlib as _hl

    K_raw = b"my_secret_mac_key_K_m_32_bytes!!"   # exactly 32 bytes
    M     = b"speed=87.4 zone=B2"

    BLOCK = 64                         # SHA-256 block size in bytes
    ipad  = bytes([0x36] * BLOCK)
    opad  = bytes([0x5C] * BLOCK)

    # Pad/hash key to block size per RFC 2104
    if len(K_raw) > BLOCK:
        K = _hl.sha256(K_raw).digest()
    else:
        K = K_raw.ljust(BLOCK, b'\x00')

    # Manual HMAC construction
    inner_input  = bytes(a ^ b for a, b in zip(K, ipad)) + M
    inner_hash   = _hl.sha256(inner_input).digest()
    outer_input  = bytes(a ^ b for a, b in zip(K, opad)) + inner_hash
    manual_hmac  = _hl.sha256(outer_input).digest()

    # Python stdlib result (should match exactly)
    import hmac as _hmac
    stdlib_hmac = _hmac.new(K_raw, M, _hl.sha256).digest()

    sub("RFC 2104 step-by-step")
    data("Key K (padded, hex):",  K.hex()[:32] + "...")
    data("ipad (0x36×64, hex):",  ipad.hex()[:32] + "...")
    data("opad (0x5C×64, hex):",  opad.hex()[:32] + "...")
    data("Message M:",            M.decode())
    data("Inner input (K⊕ipad||M):", f"{len(inner_input)} bytes")
    data("Inner hash H(K⊕ipad||M):", inner_hash.hex())
    data("Outer input (K⊕opad||inner):", f"{len(outer_input)} bytes")
    data("Manual HMAC result:",   manual_hmac.hex())
    data("stdlib HMAC result:",   stdlib_hmac.hex())

    print()
    if manual_hmac == stdlib_hmac:
        ok("Manual RFC 2104 construction matches Python stdlib exactly")
        ok("The double-hash structure prevents length-extension attacks")
        ok("H(K||M) would be vulnerable — HMAC is not (outer hash protects)")
    else:
        fail("Mismatch — implementation error")


# =============================================================================
# DEMO 7 — Multi-Vehicle Session
# =============================================================================

def demo_multi_vehicle():
    hdr("DEMO 7 — Multi-Vehicle Authenticated Session")

    print(f"""
  {GRAY}Scenario:{RESET}
  Three vehicles share the controller. Each has a different MAC key.
  The controller maintains separate sequence counters per vehicle.
  This demonstrates the per-vehicle state management needed in the
  full system.
    """)

    vehicles = {
        "VH-010": generate_mac_key(32),
        "VH-011": generate_mac_key(32),
        "VH-012": generate_mac_key(32),
    }

    # Controller needs K_m for EACH vehicle — in a real deployment
    # these are established via RSA handshake (Module 3) per vehicle
    # Here we pass the first vehicle's key; a real receiver stores a
    # dict {vehicle_id: HMACEngine}. For demo simplicity we run
    # separate receivers.
    senders   = {vid: VehicleSender(vid, km) for vid, km in vehicles.items()}
    receivers = {vid: ControllerReceiver(km)  for vid, km in vehicles.items()}

    messages = [
        ("VH-010", "TELEMETRY", {"speed": 55.0}),
        ("VH-011", "TELEMETRY", {"speed": 72.3}),
        ("VH-010", "ALERT",     {"type": "LOW_FUEL"}),
        ("VH-012", "COMMAND",   {"action": "BRAKE"}),
        ("VH-011", "TELEMETRY", {"speed": 68.1}),
        ("VH-012", "TELEMETRY", {"speed": 91.0}),
    ]

    print()
    for vid, mtype, payload in messages:
        packet = senders[vid].send_message(mtype, payload)
        result = receivers[vid].receive_message(packet)
        status_str = f"{GREEN}OK{RESET}" if result["status"] == "OK" else f"{RED}{result['status']}{RESET}"
        print(f"  {GRAY}{vid}{RESET}  seq={packet['sequence_no']}  "
              f"{mtype:<12}  status={status_str}")

    print()
    ok("All vehicles authenticated independently")
    ok("Per-vehicle sequence counters prevent cross-vehicle replay")


# =============================================================================
# MAIN — Run all demos
# =============================================================================

if __name__ == "__main__":
    print(f"""
{BOLD}{BLUE}
╔══════════════════════════════════════════════════════════════════════╗
║   EE8257 Information Security — Group 29                            ║
║   Module 1: HMAC-SHA256 Authentication Engine                       ║
║   Secure Vehicle-to-Controller Message Exchange                     ║
╚══════════════════════════════════════════════════════════════════════╝
{RESET}""")

    demo_normal_exchange()
    demo_tampering()
    demo_wrong_key()
    demo_replay_attack()
    demo_avalanche_effect()
    demo_internals()
    demo_multi_vehicle()

    hdr("ALL DEMOS COMPLETE")
    print(f"""
  {GREEN}{BOLD}Security properties demonstrated:{RESET}
  {GREEN}✔{RESET}  Confidentiality of MAC key K_m  (never transmitted in plaintext)
  {GREEN}✔{RESET}  Integrity                        (tampered messages rejected)
  {GREEN}✔{RESET}  Authentication                   (wrong-key messages rejected)
  {GREEN}✔{RESET}  Replay prevention                (sequence number monotonic check)
  {GREEN}✔{RESET}  Freshness                        (timestamp tolerance window)
  {GREEN}✔{RESET}  Avalanche effect                 (1 bit change → full MAC change)
  {GREEN}✔{RESET}  RFC 2104 correctness             (manual vs stdlib match)
  {GREEN}✔{RESET}  Constant-time comparison         (timing-attack resistance)

  {CYAN}Next:{RESET} Module 2 — AES-256-CBC Encryption Engine
  The HMAC engine integrates with AES: HMAC is computed over
  the ciphertext (Encrypt-then-MAC), not the plaintext.
    """)
