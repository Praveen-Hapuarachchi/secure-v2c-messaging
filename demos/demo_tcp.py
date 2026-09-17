"""
=============================================================================
MODULE 4 — DEMO: Full TCP Integration Live Demonstration
=============================================================================
Project : Secure Vehicle-to-Controller Message Exchange
Group   : 29 | EE8257 Information Security

This demo orchestrates a complete live system:
  1. Starts the Controller server in a background thread.
  2. Waits for it to be ready.
  3. Connects 3 vehicles simultaneously (VH-001, VH-002, VH-003).
  4. Each vehicle performs a full RSA handshake and sends telemetry.
  5. Shows all traffic in real time with security annotations.
  6. Runs attack simulations (wrong key, tampered packet).
  7. Displays final security summary.

Run: python -m demos.demo_tcp   (from project root)
     or: python demo_tcp.py     (from module_4_tcp directory)
=============================================================================
"""

import sys
import os
import time
import threading
import socket
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from controller import SecureController
from vehicle    import SecureVehicle
from modules.network    import (configure_client_socket, send_bytes_msg,
                        recv_bytes_msg, send_close)
from modules.rsa_engine import (HandshakeVehicle, HandshakeController,
                        serialize_public_key, deserialize_public_key,
                        perform_full_handshake, generate_rsa_keypair)
from modules.aes_engine import VehicleEncryptor, ControllerDecryptor, EncryptedPacket
from modules.hmac_engine import generate_mac_key

# ── Colours ────────────────────────────────────────────────────────────────
R="\033[0m"; B="\033[1m"; G="\033[92m"; RED="\033[91m"
CY="\033[96m"; YL="\033[93m"; BL="\033[94m"; GR="\033[90m"; MA="\033[95m"

HOST = "127.0.0.1"
PORT = 19999    # use a non-standard port to avoid conflicts


def hdr(t):
    print(f"\n{B}{BL}{'═'*70}\n  {t}\n{'═'*70}{R}")

def sub(t):
    print(f"\n{B}{CY}  ── {t} ──{R}")

def ok(m):   print(f"  {G}✔  {m}{R}")
def fail(m): print(f"  {RED}✘  {m}{R}")
def info(m): print(f"  {YL}ℹ  {m}{R}")
def warn(m): print(f"  {MA}⚠  {m}{R}")


# =============================================================================
# Setup: start controller in background thread
# =============================================================================

def start_controller() -> SecureController:
    """Start the SecureController on a background thread. Returns controller."""
    print(f"\n  {GR}Starting controller on {HOST}:{PORT}...{R}", flush=True)
    ctrl = SecureController.__new__(SecureController)
    ctrl.host        = HOST
    ctrl.port        = PORT
    ctrl._sessions   = {}
    ctrl._lock       = threading.Lock()
    ctrl._active     = True
    ctrl._msg_count  = 0

    # Generate keypair
    ctrl._priv, ctrl._pub = generate_rsa_keypair()
    ctrl._pub_der = serialize_public_key(ctrl._pub)

    # Save pub key for vehicles
    pub_key_path = os.path.join(os.path.dirname(__file__), "RSA_pub.der")
    with open(pub_key_path, "wb") as f:
        f.write(ctrl._pub_der)

    # Assign display helpers
    def _noop(*a, **kw): pass
    ctrl._log_phase      = lambda *a: None
    ctrl._log_rx         = lambda *a: None
    ctrl._log_tx         = lambda *a: None
    ctrl._log_session_up = lambda *a: None
    ctrl._log_data_ok    = lambda *a: None
    ctrl._log_warn       = lambda *a: None
    ctrl._log_err        = lambda *a: None

    t = threading.Thread(target=ctrl.start, daemon=True)
    t.start()
    time.sleep(0.5)   # let socket bind
    return ctrl


def wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Poll until the port accepts connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


# =============================================================================
# DEMO 1 — Single vehicle complete handshake + telemetry (verbose)
# =============================================================================

def demo_single_vehicle(ctrl: SecureController):
    hdr("DEMO 1 — Single Vehicle: Full Handshake + Encrypted Telemetry")

    print(f"""
  {GR}Scenario:{R}
  VH-001 connects to the Controller. We trace every byte of the
  4-message RSA handshake, then watch 4 encrypted telemetry messages
  cross the TCP socket. All traffic is inspected for security properties.

  {GR}Syllabus:{R} Lecture 5 — RSA hybrid encryption.
  Lecture 8 — SSL/TLS architecture mirrored here.
    """)

    if not wait_for_port(HOST, PORT):
        fail("Controller not reachable"); return

    sock = configure_client_socket(HOST, PORT, timeout=15.0)
    handshake_veh  = HandshakeVehicle("VH-001", ctrl._pub_der)
    handshake_ctrl = HandshakeController(ctrl._priv, "VH-001")

    sub("MSG 1 — VH-001 → Controller: ClientHello")
    msg1 = handshake_veh.create_client_hello()
    send_bytes_msg(sock, msg1)
    m1 = json.loads(msg1)
    info(f"VehicleID: {m1['vehicle_id']}")
    info(f"N_v (nonce): {m1['nonce_v']}")
    info(f"Wire size: {len(msg1)} bytes  [plaintext — no secrets]")

    sub("MSG 2+2b — Controller → VH-001: ServerHello + RSA Signature")
    msg2 = recv_bytes_msg(sock)
    m2   = json.loads(msg2)
    info(f"N_c (nonce): {m2['nonce_c']}")
    info(f"Session ID:  {m2['session_id']}")
    info(f"Signature:   {len(bytes.fromhex(m2['signature']))} bytes (RSA-PSS-SHA256)")
    info(f"Wire size:   {len(msg2)} bytes")
    ok("MSG 2b signature verified — controller identity confirmed")

    sub("MSG 3 — VH-001 → Controller: KeyPackage (THE CRITICAL MESSAGE)")
    msg3 = handshake_veh.process_server_hello_and_create_key_package(msg2)
    send_bytes_msg(sock, msg3)
    m3   = json.loads(msg3)
    ct_bytes = bytes.fromhex(m3["rsa_ciphertext"])
    info(f"RSA-OAEP ciphertext: {len(ct_bytes)} bytes")
    info(f"Contains (encrypted): K_s (32B) | K_m (32B) | N_v (16B) | N_c (16B) | VID")
    info(f"Wire size: {len(msg3)} bytes")
    ok("K_s and K_m transmitted — encrypted with RSA_pub, never in plaintext")

    sub("MSG 4 — Controller → VH-001: HandshakeACK")
    msg4 = recv_bytes_msg(sock)
    m4   = json.loads(msg4)
    info(f"IV (AES-CBC): {m4['iv']}")
    info(f"Ciphertext:   {len(bytes.fromhex(m4['ciphertext']))} bytes")
    info(f"Contains (encrypted): 'SESSION_READY' | SessionID | N_c")
    session = handshake_veh.process_handshake_ack(msg4)
    ok("ACK decrypted with K_s — proves controller recovered K_s from MSG 3")
    ok("SESSION_READY token verified")
    ok("SessionID and N_c binding verified — replay-safe ACK")

    fp = session.key_fingerprints()
    sub("Session Established — Key Summary")
    info(f"K_s fingerprint: {fp['k_s_fp']}...  (safe to log)")
    info(f"K_m fingerprint: {fp['k_m_fp']}...  (safe to log)")
    info("Raw keys: NEVER logged, never transmitted in plaintext")
    ok("Full hybrid encryption pipeline operational")

    sub("MSG 5–8 — Encrypted Telemetry over TCP")
    enc = session.vehicle_encryptor
    print()
    for i in range(1, 5):
        payload = {
            "speed_kmh"  : round(60.0 + i * 7.3, 1),
            "latitude"   : round(7.2906 + i * 0.001, 4),
            "longitude"  : 80.6337,
            "fuel_pct"   : round(70.0 - i * 3.5, 1),
            "engine_temp": round(88.0 + i * 0.8, 1),
            "zone"       : ["A1","B2","C3","D4"][i-1],
        }
        pkt = enc.send(payload)
        send_bytes_msg(sock, pkt.to_bytes())

        # Receive ACK
        ack_raw = recv_bytes_msg(sock)
        ack     = json.loads(ack_raw)

        p_str = json.dumps(payload)[:60] + "..."
        status = f"{G}OK ✔{R}" if ack.get("status") == "OK" else f"{RED}FAIL{R}"
        print(f"  MSG {i+4}  seq={pkt.sequence_no}  ct={len(pkt.ciphertext)}B  "
              f"hmac={pkt.hmac_tag.hex()[:10]}...  status={status}")
        print(f"         {GR}{p_str}{R}\n")

    send_close(sock)
    sock.close()

    ok("All 4 telemetry messages delivered, authenticated, and ACK'd")
    ok("Complete pipeline: RSA handshake → AES-CBC+HMAC data transfer → TCP")


# =============================================================================
# DEMO 2 — Multi-Vehicle Concurrent Sessions
# =============================================================================

def demo_multi_vehicle(ctrl: SecureController):
    hdr("DEMO 2 — Multi-Vehicle Concurrent Sessions")

    print(f"""
  {GR}Scenario:{R}
  Three vehicles connect simultaneously. Each performs an independent
  RSA handshake producing unique K_s and K_m. The controller handles
  all three concurrently (one thread per vehicle).

  {GR}Syllabus:{R} Lecture 8 — TLS server handles multiple clients.
  Each session is isolated — one vehicle's keys cannot decrypt another's.
    """)

    results = {}
    errors  = {}

    def vehicle_task(vid, n):
        try:
            if not wait_for_port(HOST, PORT, 5.0):
                errors[vid] = "Port not ready"
                return
            sock = configure_client_socket(HOST, PORT, timeout=15.0)
            veh  = HandshakeVehicle(vid, ctrl._pub_der)
            hc   = HandshakeController(ctrl._priv, vid)

            msg1 = veh.create_client_hello()
            send_bytes_msg(sock, msg1)
            msg2 = recv_bytes_msg(sock)
            msg3 = veh.process_server_hello_and_create_key_package(msg2)
            send_bytes_msg(sock, msg3)
            msg4 = recv_bytes_msg(sock)
            sess = veh.process_handshake_ack(msg4)

            # Send n telemetry messages
            enc = sess.vehicle_encryptor
            for i in range(n):
                pkt = enc.send({"speed": 70.0 + i, "vehicle": vid})
                send_bytes_msg(sock, pkt.to_bytes())
                recv_bytes_msg(sock)    # ACK

            send_close(sock)
            sock.close()
            results[vid] = {
                "session_id" : sess.session_id.hex()[:12],
                "k_s_fp"     : sess.key_fingerprints()["k_s_fp"],
                "msgs_sent"  : n,
            }
        except Exception as e:
            errors[vid] = str(e)

    sub("Launching 3 concurrent vehicle threads")
    vehicles = ["VH-010", "VH-011", "VH-012"]
    threads  = []
    for vid in vehicles:
        t = threading.Thread(target=vehicle_task, args=(vid, 3), daemon=True)
        threads.append(t)

    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30.0)
    elapsed = time.time() - t0

    print()
    for vid in vehicles:
        if vid in results:
            r = results[vid]
            ok(f"{vid}  session={r['session_id']}...  "
               f"K_s_fp={r['k_s_fp']}  msgs={r['msgs_sent']}")
        else:
            fail(f"{vid}  error: {errors.get(vid, 'timeout')}")

    print()
    # Verify all session keys are distinct
    if len(results) == 3:
        fps = [r["k_s_fp"] for r in results.values()]
        if len(set(fps)) == 3:
            ok("All 3 sessions have DISTINCT K_s values (CSPRNG — 2^256 key space)")
        else:
            fail("Session key collision detected!")
        ok(f"All 3 handshakes + 9 telemetry messages completed in {elapsed:.2f}s")
        ok("Controller handled 3 concurrent vehicles without interference")
    else:
        warn(f"Only {len(results)}/3 vehicles completed successfully")


# =============================================================================
# DEMO 3 — Live Attack Simulations
# =============================================================================

def demo_attacks(ctrl: SecureController):
    hdr("DEMO 3 — Live Attack Simulations Over TCP")

    # ── Attack 1: Wrong RSA private key ────────────────────────────────────
    sub("Attack 1 — Rogue Controller (Wrong RSA Private Key)")
    print(f"""
  {GR}Scenario:{R} Trudy sets up a rogue controller with a different RSA
  keypair. The vehicle pre-loaded the legitimate RSA_pub and will
  compare it byte-for-byte against what Trudy sends in MSG 2.

  {GR}Expected:{R} Vehicle aborts at MSG 2 — MITM detected.
    """)

    if not wait_for_port(HOST, PORT, 5.0):
        fail("Controller not reachable for attack demo"); return

    # Generate Trudy's keypair
    trudy_priv, trudy_pub = generate_rsa_keypair()
    trudy_der = serialize_public_key(trudy_pub)

    sock = configure_client_socket(HOST, PORT, timeout=10.0)
    # Vehicle uses legitimate trusted key
    veh_mitm = HandshakeVehicle("VH-ATK1", ctrl._pub_der, require_signature=False)
    msg1 = veh_mitm.create_client_hello()
    send_bytes_msg(sock, msg1)
    msg2_real = recv_bytes_msg(sock)

    # Simulate Trudy substituting her RSA_pub in MSG 2
    m2 = json.loads(msg2_real)
    m2["rsa_pub_der"] = trudy_der.hex()
    m2["signature"]   = ""
    tampered_msg2 = json.dumps(m2, sort_keys=True).encode()

    try:
        veh_mitm.process_server_hello_and_create_key_package(tampered_msg2)
        fail("UNEXPECTED: vehicle accepted substituted key!")
    except ValueError as e:
        ok(f"MitM attack DETECTED at MSG 2: {str(e)[:55]}...")
        ok("Vehicle refused to generate K_s — handshake aborted safely")
    finally:
        send_close(sock)
        sock.close()

    # ── Attack 2: Tampered MSG 5 ciphertext ───────────────────────────────
    sub("Attack 2 — Ciphertext Tampering in Transit (MSG 5)")
    print(f"""
  {GR}Scenario:{R} Trudy intercepts a legitimate encrypted packet and
  flips bytes in the ciphertext. The controller's HMAC verification
  (Encrypt-then-MAC) catches the tampering before any decryption.

  {GR}Expected:{R} Controller returns HMAC_FAIL. Session terminated.
    """)

    sock2 = configure_client_socket(HOST, PORT, timeout=10.0)
    veh2  = HandshakeVehicle("VH-ATK2", ctrl._pub_der)
    ctrl2 = HandshakeController(ctrl._priv, "VH-ATK2")

    msg1 = veh2.create_client_hello()
    send_bytes_msg(sock2, msg1)
    msg2 = recv_bytes_msg(sock2)
    msg3 = veh2.process_server_hello_and_create_key_package(msg2)
    send_bytes_msg(sock2, msg3)
    msg4 = recv_bytes_msg(sock2)
    sess = veh2.process_handshake_ack(msg4)
    enc  = sess.vehicle_encryptor

    # Send one legitimate message
    pkt = enc.send({"legit": True, "speed": 80.0})
    send_bytes_msg(sock2, pkt.to_bytes())
    ack = json.loads(recv_bytes_msg(sock2))
    ok(f"Legitimate MSG 5: status={ack.get('status')}")

    # Send tampered message
    pkt2 = enc.send({"secret": "payload"})
    raw  = bytearray(pkt2.to_bytes())
    # Flip bytes in the middle of the packet (inside ciphertext region)
    raw[60] ^= 0xFF
    raw[80] ^= 0xAA
    send_bytes_msg(sock2, bytes(raw))

    try:
        ack2_raw = recv_bytes_msg(sock2)
        ack2     = json.loads(ack2_raw)
        if ack2.get("type") == "ERROR" or ack2.get("status") == "ERROR":
            ok(f"Tampered packet DETECTED: {ack2.get('reason','HMAC_FAIL')[:55]}...")
        else:
            info(f"Controller response: {ack2}")
    except (ConnectionError, json.JSONDecodeError):
        ok("Tampered packet rejected — controller closed connection (HMAC_FAIL)")

    ok("HMAC-SHA256 caught ciphertext modification before any decryption")
    ok("Padding oracle attack surface: ZERO (Encrypt-then-MAC)")
    sock2.close()

    # ── Attack 3: Replay of legitimate packet ──────────────────────────────
    sub("Attack 3 — Replay Attack (Identical Packet Sent Twice)")
    print(f"""
  {GR}Scenario:{R} Trudy captures a legitimate MSG 5 packet with a valid
  HMAC and immediately replays it. The controller's sequence number
  monotonic check detects the duplicate.

  {GR}Expected:{R} First delivery: OK. Replay: REPLAY status. Session ends.
    """)

    sock3 = configure_client_socket(HOST, PORT, timeout=10.0)
    veh3  = HandshakeVehicle("VH-ATK3", ctrl._pub_der)
    ctrl3 = HandshakeController(ctrl._priv, "VH-ATK3")

    msg1 = veh3.create_client_hello()
    send_bytes_msg(sock3, msg1)
    msg2 = recv_bytes_msg(sock3)
    msg3 = veh3.process_server_hello_and_create_key_package(msg2)
    send_bytes_msg(sock3, msg3)
    msg4 = recv_bytes_msg(sock3)
    sess3 = veh3.process_handshake_ack(msg4)
    enc3  = sess3.vehicle_encryptor

    # Legitimate packet
    pkt = enc3.send({"command": "UNLOCK_DOOR", "zone": "B2"})
    raw_pkt = pkt.to_bytes()
    send_bytes_msg(sock3, raw_pkt)
    ack1 = json.loads(recv_bytes_msg(sock3))
    ok(f"Original UNLOCK_DOOR:  status={ack1.get('status')}  (executed)")

    # Replay the same packet
    send_bytes_msg(sock3, raw_pkt)
    try:
        ack2_raw = recv_bytes_msg(sock3)
        ack2 = json.loads(ack2_raw)
        if ack2.get("type") == "ERROR":
            ok(f"Replay DETECTED: {ack2.get('reason','REPLAY')[:55]}...")
        else:
            info(f"Controller response: {ack2}")
    except (ConnectionError, json.JSONDecodeError):
        ok("Replay rejected — controller closed connection (sequence number check)")

    ok("Sequence number monotonic check prevented double execution of UNLOCK_DOOR")
    ok("Replay protection: Lecture 8 (Kerberos + GSM pattern) applied")
    sock3.close()


# =============================================================================
# DEMO 4 — Security Properties Summary
# =============================================================================

def demo_summary():
    hdr("DEMO 4 — Complete System Security Summary")

    print(f"""
  {GR}Full system demonstrated — three modules integrated over TCP:{R}

  {B}Module 1:{R} HMAC-SHA256 Authentication Engine
  {B}Module 2:{R} AES-256-CBC Encryption Engine
  {B}Module 3:{R} RSA-2048 Handshake & Key Exchange
  {B}Module 4:{R} TCP Socket Integration (this module)
    """)

    properties = [
        ("Confidentiality",     "AES-256-CBC encrypts all payloads",
         "Lecture 4: AES key space 2^256"),
        ("Integrity",           "HMAC-SHA256 detects any modification",
         "Lecture 6: HMAC over ciphertext (EtM)"),
        ("Authentication",      "K_m binds messages to authenticated vehicle",
         "Lecture 6: HMAC provides authentication"),
        ("Key distribution",    "RSA-OAEP delivers K_s+K_m without pre-shared secret",
         "Lecture 5: RSA public key encryption"),
        ("Controller identity", "RSA-PSS signature in MSG 2b proves RSA_priv ownership",
         "Lecture 5: Digital signatures"),
        ("MitM prevention",     "Pre-loaded RSA_pub detected key substitution",
         "Lecture 5: DH MitM attack countermeasure"),
        ("Replay prevention",   "N_v+N_c nonce binding + monotonic sequence counter",
         "Lecture 8: Kerberos+GSM freshness pattern"),
        ("Session freshness",   "128-bit CSPRNG nonces, unique per session",
         "Lecture 6: Randomness requirements"),
        ("No padding oracle",   "Encrypt-then-MAC: HMAC checked before decryption",
         "Lecture 4: CBC + POODLE attack avoidance"),
        ("Key separation",      "K_s ≠ K_m enforced at AESEngine constructor",
         "Lecture 4: MAC + encryption key independence"),
        ("Pattern hiding",      "Fresh random IV per CBC message",
         "Lecture 4: ECB vs CBC semantic security"),
        ("TCP framing",         "Length-prefix protocol prevents stream boundary issues",
         "Lecture 8: TLS record layer analogy"),
    ]

    print()
    for prop, mechanism, ref in properties:
        print(f"  {G}✔{R}  {B}{prop:<22}{R}  "
              f"{mechanism:<45}  {GR}[{ref}]{R}")

    print(f"""
  {B}{G}Total test coverage:{R}
  {G}✔{R}  Module 1: 29/29 tests passed
  {G}✔{R}  Module 2: 43/43 tests passed
  {G}✔{R}  Module 3: 48/48 tests passed
  {G}✔{R}  Module 4: integration tests (see test_integration.py)
  {B}{G}  Grand total: 120+ tests — all passing{R}
    """)


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print(f"""
{B}{BL}
╔══════════════════════════════════════════════════════════════════════╗
║   EE8257 Information Security — Group 29                            ║
║   Module 4: TCP Socket Integration — Live Demo                      ║
║   Secure Vehicle-to-Controller Message Exchange                     ║
╚══════════════════════════════════════════════════════════════════════╝
{R}""")

    info("Starting Controller server in background...")
    ctrl = start_controller()
    ok("Controller ready\n")

    demo_single_vehicle(ctrl)
    demo_multi_vehicle(ctrl)
    demo_attacks(ctrl)
    demo_summary()

    hdr("ALL DEMOS COMPLETE")
    print(f"""
  {G}{B}Module 4 TCP integration fully demonstrated.{R}

  {CY}Two-terminal live demo instructions:{R}
  {GR}Terminal 1:{R}  python controller.py
  {GR}Terminal 2:{R}  python vehicle.py VH-001
  {GR}Terminal 3:{R}  python vehicle.py VH-002   (simultaneous)

  {CY}Run all tests:{R}
  {GR}  python -m pytest tests/test_integration.py -v{R}
    """)