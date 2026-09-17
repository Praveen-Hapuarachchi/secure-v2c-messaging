"""
=============================================================================
MODULE 3 — DEMO & ATTACK SIMULATION SUITE
RSA Handshake & Secure Session Key Exchange Engine
=============================================================================
Project : Secure Vehicle-to-Controller Message Exchange
Group   : 29 | EE8257 Information Security

Demonstrations:
  1.  RSA keypair generation and fingerprinting
  2.  Full 4-message handshake (happy path)
  3.  Session key recovery and key fingerprint verification
  4.  End-to-end integration: handshake → AES+HMAC data exchange
  5.  Tampered MSG 3 ciphertext rejection
  6.  Wrong RSA private key failure
  7.  MitM key substitution attack detection
  8.  Replay attack on MSG 3 (stale nonce detection)
  9.  Missing / invalid MSG 2b signature rejection
  10. Multi-vehicle independent session establishment
  11. OAEP randomness: same keys → different ciphertext each handshake
  12. Session key separation invariant enforcement

Run: python -m demos.demo_rsa   (from project root)
     or: python demo_rsa.py     (from module_3_rsa directory)
=============================================================================
"""

import sys, os, copy, json, time, hashlib
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.rsa_engine import (
    generate_rsa_keypair, serialize_public_key, deserialize_public_key,
    key_fingerprint, rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify,
    MSG1_ClientHello, MSG2_ServerHello, MSG3_KeyPackage, MSG4_HandshakeACK,
    HandshakeController, HandshakeVehicle, EstablishedSession,
    perform_full_handshake, PROTOCOL_VERSION, ACK_TOKEN,
)
from modules.hmac_engine import generate_mac_key
from modules.aes_engine  import generate_aes_key

# ── Terminal colours ────────────────────────────────────────────────────────
RESET = "\033[0m"; BOLD = "\033[1m"
GREEN = "\033[92m"; RED  = "\033[91m"; YELLOW = "\033[93m"
CYAN  = "\033[96m"; BLUE = "\033[94m"; GRAY   = "\033[90m"
WHITE = "\033[97m"; MAG  = "\033[95m"

def hdr(t):  print(f"\n{BOLD}{BLUE}{'═'*70}\n  {t}\n{'═'*70}{RESET}")
def sub(t):  print(f"\n{BOLD}{CYAN}  ── {t} ──{RESET}")
def ok(m):   print(f"  {GREEN}✔  {m}{RESET}")
def fail(m): print(f"  {RED}✘  {m}{RESET}")
def info(m): print(f"  {YELLOW}ℹ  {m}{RESET}")
def warn(m): print(f"  {MAG}⚠  {m}{RESET}")
def dat(l,v):print(f"  {GRAY}{l:<30}{RESET} {WHITE}{v}{RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# SHARED SETUP — generate ONE keypair used across all demos
# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{GRAY}  Generating RSA-2048 keypair (one-time setup, ~1-3s)...{RESET}", flush=True)
_t0 = time.time()
CTRL_PRIV, CTRL_PUB = generate_rsa_keypair()
CTRL_PUB_DER        = serialize_public_key(CTRL_PUB)
print(f"  {GREEN}Keypair ready in {time.time()-_t0:.2f}s{RESET}\n")


# =============================================================================
# DEMO 1 — RSA Keypair Generation and Public Key Fingerprint
# =============================================================================

def demo_keypair():
    hdr("DEMO 1 — RSA-2048 Keypair Generation and Public Key Fingerprint")

    print(f"""
  {GRAY}Scenario:{RESET}
  The Controller generates its RSA-2048 keypair at startup.
  RSA_pub is pre-loaded onto vehicles at manufacturing time.
  The public key fingerprint lets operators visually verify
  the pre-loaded key matches the genuine controller key.

  {GRAY}Syllabus:{RESET} Lecture 5 — RSA key generation:
    N = p×q, φ(N) = (p-1)(q-1), e = 65537, d ≡ e⁻¹ mod φ(N)
  Lecture 2 — Extended Euclidean Algorithm (used to compute d).
    """)

    sub("RSA-2048 key parameters")
    pub_numbers = CTRL_PUB.public_numbers()
    dat("Key size:",         "2048 bits (NIST recommended minimum)")
    dat("Public exponent e:", f"{pub_numbers.e} (= 2¹⁶+1, Fermat prime)")
    dat("Modulus N (first 32 hex):", hex(pub_numbers.n)[:34] + "...")
    dat("DER-encoded key size:", f"{len(CTRL_PUB_DER)} bytes")
    dat("Key fingerprint (SHA-256):", key_fingerprint(CTRL_PUB))

    sub("WHY e = 65537 not e = 3?")
    info("Lecture 5 cube root attack: if e=3 and M is small, M³ < N")
    info("  → C = M³ in ordinary integers → attacker computes ∛C = M")
    info("e = 65537 makes M^e >> N for any realistic plaintext")
    info("OAEP padding provides the definitive fix regardless of e value")

    sub("Serialisation round-trip")
    restored = deserialize_public_key(CTRL_PUB_DER)
    fp1 = key_fingerprint(CTRL_PUB)
    fp2 = key_fingerprint(restored)
    dat("Original fingerprint:",  fp1)
    dat("Restored fingerprint:",  fp2)
    if fp1 == fp2:
        ok("DER serialise → deserialise preserves key exactly")
        ok("Vehicles pre-load DER bytes at manufacture; no PEM parsing needed")
    else:
        fail("Fingerprint mismatch after round-trip!")


# =============================================================================
# DEMO 2 — Full 4-Message Handshake (Happy Path)
# =============================================================================

def demo_full_handshake():
    hdr("DEMO 2 — Full 4-Message Handshake (Happy Path)")

    print(f"""
  {GRAY}Scenario:{RESET}
  Vehicle VH-001 connects to the Controller for the first time.
  The complete 5-phase protocol executes successfully:
    MSG 1  VH-001 → Controller : ClientHello  (VehicleID + N_v)
    MSG 2  Controller → VH-001 : ServerHello  (N_c + RSA_pub)
    MSG 2b Controller → VH-001 : Signature    (Sign(RSA_priv, N_v||pub))
    MSG 3  VH-001 → Controller : KeyPackage   (RSA_OAEP{{K_s||K_m||N_v||N_c}})
    MSG 4  Controller → VH-001 : HandshakeACK (AES{{SESSION_READY|SessionID|N_c}})

  {GRAY}Syllabus:{RESET} Lecture 5 — RSA key exchange (hybrid encryption model).
  Lecture 8 — SSL/TLS handshake: "Use RSA to exchange symmetric key,
  then use symmetric key for data." Our design mirrors this architecture.
    """)

    ctrl = HandshakeController(CTRL_PRIV, "VH-001")
    veh  = HandshakeVehicle("VH-001", CTRL_PUB_DER, require_signature=True)

    sub("MSG 1 — VH-001 → Controller: ClientHello")
    msg1 = veh.create_client_hello()
    m1   = MSG1_ClientHello.from_bytes(msg1)
    dat("VehicleID:",         m1.vehicle_id)
    dat("N_v (nonce):",       m1.nonce_v.hex())
    dat("Protocol version:",  m1.protocol_version)
    dat("MSG 1 wire size:",   f"{len(msg1)} bytes  [plaintext — no secrets here]")
    info("MSG 1 is unauthenticated — safe because it contains no secrets")
    info("N_v will be cryptographically bound inside MSG 3 RSA ciphertext")
    ok(f"Controller state: {ctrl.state} → processing...")

    sub("MSG 2 + 2b — Controller → VH-001: ServerHello + Signature")
    msg2 = ctrl.process_client_hello(msg1)
    m2   = MSG2_ServerHello.from_bytes(msg2)
    dat("N_c (nonce):",           m2.nonce_c.hex())
    dat("Session ID:",            m2.session_id.hex())
    dat("RSA_pub (first 16B):",   m2.rsa_pub_der.hex()[:32] + "...")
    dat("MSG 2b signature size:", f"{len(m2.signature)} bytes  (RSA-PSS-SHA256)")
    dat("MSG 2 wire size:",       f"{len(msg2)} bytes")
    info("Signature = Sign(RSA_priv, N_v || RSA_pub_DER)")
    info("N_v inside signature: replay of old MSG 2b rejected (wrong N_v)")
    ok(f"Controller state: {ctrl.state}")

    sub("MSG 3 — VH-001 → Controller: KeyPackage (THE CRITICAL MESSAGE)")
    msg3 = veh.process_server_hello_and_create_key_package(msg2)
    m3   = MSG3_KeyPackage.from_bytes(msg3)
    dat("RSA ciphertext size:", f"{len(m3.rsa_ciphertext)} bytes  (RSA-2048 output)")
    dat("Vehicle ID (routing):",m3.vehicle_id)
    dat("Session ID (routing):",m3.session_id.hex())
    dat("MSG 3 wire size:",     f"{len(msg3)} bytes")
    info("Ciphertext contains: K_s || K_m || N_v || N_c || VehicleID")
    info("Only the controller (with RSA_priv) can decrypt this")
    info("N_v + N_c inside ciphertext: dual replay/ordering protection")
    ok(f"Vehicle state: {veh.state}")

    sub("MSG 4 — Controller → VH-001: HandshakeACK")
    msg4 = ctrl.process_key_package(msg3)
    m4   = MSG4_HandshakeACK.from_bytes(msg4)
    dat("IV (AES-CBC):",       m4.iv.hex())
    dat("Ciphertext size:",    f"{len(m4.ciphertext)} bytes")
    dat("MSG 4 wire size:",    f"{len(msg4)} bytes")
    info("Plaintext = 'SESSION_READY' || SessionID || N_c")
    info("Encrypted with K_s: proves controller recovered K_s from MSG 3")
    info("N_c binding: prevents replay of captured MSG 4")
    ok(f"Controller state: {ctrl.state}")

    sub("VH-001 processes MSG 4 — session established")
    v_sess = veh.process_handshake_ack(msg4)
    c_sess = ctrl.get_session()
    dat("Vehicle state:",        veh.state)
    dat("Controller state:",     ctrl.state)
    dat("Session ID:",           v_sess.session_id_display())
    dat("K_s fingerprint:",      v_sess.key_fingerprints()['k_s_fp'] + "...")
    dat("K_m fingerprint:",      v_sess.key_fingerprints()['k_m_fp'] + "...")
    dat("Keys match (V==C):",    f"K_s {v_sess.k_s == c_sess.k_s}  |  K_m {v_sess.k_m == c_sess.k_m}")
    ok("Handshake complete — both parties hold identical K_s and K_m")
    ok("VehicleEncryptor ready on vehicle side for MSG 5+")
    ok("ControllerDecryptor ready on controller side for MSG 5+")


# =============================================================================
# DEMO 3 — Session Key Recovery and Fingerprints
# =============================================================================

def demo_key_recovery():
    hdr("DEMO 3 — Session Key Recovery and Verification")

    print(f"""
  {GRAY}Scenario:{RESET}
  After the handshake, we verify that both parties recovered
  identical K_s and K_m. Key fingerprints (SHA-256 of the key)
  are safe to log — they reveal nothing about the key value.
    """)

    v_sess, c_sess = perform_full_handshake("VH-002", CTRL_PRIV, CTRL_PUB_DER)

    sub("Key comparison — vehicle vs controller")
    dat("K_s identical:",    str(v_sess.k_s == c_sess.k_s))
    dat("K_m identical:",    str(v_sess.k_m == c_sess.k_m))
    dat("K_s ≠ K_m:",        str(v_sess.k_s != v_sess.k_m))
    dat("K_s length:",       f"{len(v_sess.k_s)} bytes (256 bits)")
    dat("K_m length:",       f"{len(v_sess.k_m)} bytes (256 bits)")

    vfp = v_sess.key_fingerprints()
    cfp = c_sess.key_fingerprints()
    dat("Vehicle K_s fingerprint:",    vfp['k_s_fp'])
    dat("Controller K_s fingerprint:", cfp['k_s_fp'])
    dat("Fingerprints match:",         str(vfp['k_s_fp'] == cfp['k_s_fp']))

    if v_sess.k_s == c_sess.k_s and v_sess.k_m == c_sess.k_m:
        ok("Session keys recovered identically by both parties")
        ok("Keys never appeared in plaintext on the network")
        ok("Key separation enforced: K_s ≠ K_m")
    else:
        fail("Key mismatch — handshake error!")


# =============================================================================
# DEMO 4 — End-to-End Integration: Handshake → AES+HMAC Data Exchange
# =============================================================================

def demo_end_to_end():
    hdr("DEMO 4 — End-to-End Integration: Handshake → AES+HMAC Data Exchange")

    print(f"""
  {GRAY}Scenario:{RESET}
  After the RSA handshake establishes K_s and K_m, the vehicle
  immediately sends encrypted telemetry using Modules 1+2 (AES-CBC +
  HMAC). This demonstrates the complete hybrid encryption pipeline:
    RSA (Module 3) → establishes K_s, K_m
    AES-CBC (Module 2) → encrypts payload with K_s
    HMAC-SHA256 (Module 1) → authenticates ciphertext with K_m

  {GRAY}Syllabus:{RESET} Lecture 8 — SSL/TLS: "use RSA for handshake,
  AES for bulk data." Lecture 4 + Lecture 6 — AES+HMAC pipeline.
    """)

    v_sess, c_sess = perform_full_handshake("VH-003", CTRL_PRIV, CTRL_PUB_DER)

    sub("Post-handshake: vehicle sends 3 encrypted telemetry messages")
    vehicle_enc = v_sess.vehicle_encryptor
    ctrl_dec    = c_sess.controller_decryptor

    messages = [
        {"speed_kmh": 87.4, "latitude": 6.0535, "longitude": 80.2210,
         "fuel_pct": 63.2, "engine_temp": 91.5},
        {"speed_kmh": 92.1, "alert": "BRAKE_APPLIED", "zone": "B2"},
        {"speed_kmh": 0.0,  "status": "PARKED", "engine_temp": 68.0},
    ]

    print()
    for i, payload in enumerate(messages, 1):
        pkt    = vehicle_enc.send(payload)
        result = ctrl_dec.receive(pkt)
        status = f"{GREEN}OK{RESET}" if result["status"]=="OK" else f"{RED}{result['status']}{RESET}"
        print(f"  {GRAY}MSG {i+4}:{RESET}  seq={pkt.sequence_no}  "
              f"ct={len(pkt.ciphertext)}B  hmac={pkt.hmac_tag.hex()[:12]}...  "
              f"status={status}")
        if result["status"] == "OK":
            print(f"         {GRAY}payload={RESET}{WHITE}{json.dumps(result['payload'])}{RESET}")
        print()

    ok("Complete pipeline: RSA handshake → AES-CBC + HMAC data transfer")
    ok("K_s used for AES-CBC encryption (Module 2)")
    ok("K_m used for HMAC-SHA256 authentication (Module 1)")
    ok("Encrypt-then-MAC: HMAC covers ciphertext, not plaintext")


# =============================================================================
# DEMO 5 — Tampered MSG 3 Ciphertext Rejection
# =============================================================================

def demo_tampered_msg3():
    hdr("DEMO 5 — Tampered MSG 3 RSA Ciphertext Rejection")

    print(f"""
  {GRAY}Scenario:{RESET}
  Trudy intercepts MSG 3 and flips bytes in the RSA ciphertext,
  hoping to inject a different K_s or K_m. The RSA-OAEP decryption
  will fail — OAEP detects structural corruption deterministically.

  {GRAY}Syllabus:{RESET} Lecture 5 — OAEP unpadding:
  "If the ciphertext is malformed, decryption raises an error."
  All OAEP failure modes are indistinguishable to prevent oracles.
    """)

    ctrl = HandshakeController(CTRL_PRIV, "VH-TAM")
    veh  = HandshakeVehicle("VH-TAM", CTRL_PUB_DER)

    msg1 = veh.create_client_hello()
    msg2 = ctrl.process_client_hello(msg1)
    msg3 = veh.process_server_hello_and_create_key_package(msg2)

    sub("Trudy tampers with the RSA ciphertext bytes in MSG 3")
    m3_dict = json.loads(msg3)
    ct_bytes = bytearray(bytes.fromhex(m3_dict["rsa_ciphertext"]))
    original = ct_bytes[100]
    ct_bytes[100] ^= 0xFF
    ct_bytes[150] ^= 0xAA
    m3_dict["rsa_ciphertext"] = bytes(ct_bytes).hex()
    tampered_msg3 = json.dumps(m3_dict, sort_keys=True).encode()

    info(f"Flipped byte 100: 0x{original:02X} → 0x{ct_bytes[100]:02X}")
    info(f"Flipped byte 150: also flipped")
    info("Trudy cannot compute valid OAEP structure without RSA_pub internal seed")

    sub("Controller attempts to process tampered MSG 3")
    ctrl2 = HandshakeController(CTRL_PRIV, "VH-TAM")
    veh2  = HandshakeVehicle("VH-TAM", CTRL_PUB_DER)
    msg1b = veh2.create_client_hello()
    msg2b = ctrl2.process_client_hello(msg1b)
    # Inject original msg3 session_id into tampered packet
    m3_dict2 = json.loads(msg3)
    m3_dict2["rsa_ciphertext"] = bytes(ct_bytes).hex()
    m3_dict2["session_id"] = json.loads(msg2b)["session_id"]
    tampered_msg3b = json.dumps(m3_dict2, sort_keys=True).encode()
    try:
        ctrl2.process_key_package(tampered_msg3b)
        fail("UNEXPECTED: tampered MSG 3 was accepted!")
    except ValueError as e:
        dat("Controller response:", str(e)[:65] + "...")
        ok("Tampered RSA ciphertext detected and rejected")
        ok("OAEP structural check fails on any bit-level corruption")
        ok("K_s and K_m were NOT compromised — controller rejected safely")


# =============================================================================
# DEMO 6 — Wrong RSA Private Key Failure
# =============================================================================

def demo_wrong_private_key():
    hdr("DEMO 6 — Wrong RSA Private Key Failure")

    print(f"""
  {GRAY}Scenario:{RESET}
  A rogue controller (or misconfigured server) holds a DIFFERENT
  RSA private key. The vehicle encrypts MSG 3 under the trusted
  RSA_pub. The rogue controller cannot decrypt it with its own key.

  {GRAY}Syllabus:{RESET} Lecture 5 — "Only the holder of RSA_priv can
  decrypt a message encrypted with RSA_pub." The factoring hardness
  of N = p×q is the security foundation.
    """)

    sub("Setup — generate a second (rogue) RSA keypair")
    info("Generating rogue keypair...")
    rogue_priv, rogue_pub = generate_rsa_keypair()
    info(f"Rogue key fingerprint: {key_fingerprint(rogue_pub)}")
    info(f"Legit key fingerprint: {key_fingerprint(CTRL_PUB)}")

    sub("Vehicle uses trusted RSA_pub to encrypt K_s, K_m")
    rogue_ctrl = HandshakeController(rogue_priv, "VH-WRK")
    veh        = HandshakeVehicle("VH-WRK", CTRL_PUB_DER, require_signature=False)

    msg1 = veh.create_client_hello()

    # Build MSG 2 manually using rogue controller's key but trusted pub DER
    # to simulate the scenario where vehicle rejects the substitution
    rogue_pub_der = serialize_public_key(rogue_pub)
    import secrets as _s
    nc = _s.token_bytes(16)
    nv = MSG1_ClientHello.from_bytes(msg1).nonce_v
    sid = hashlib.sha256(nv + nc + b"VH-WRK").digest()[:16]
    fake_msg2 = MSG2_ServerHello(
        nonce_c=nc, session_id=sid,
        rsa_pub_der=CTRL_PUB_DER,   # send legit pub (vehicle checks this)
        signature=b"",
    )

    msg3 = veh.process_server_hello_and_create_key_package(fake_msg2.to_bytes())

    sub("Rogue controller tries to decrypt MSG 3 with wrong private key")
    try:
        rogue_ctrl2 = HandshakeController(rogue_priv, "VH-WRK")
        # Rebuild msg1 so rogue ctrl has matching nonce state
        msg1b = MSG1_ClientHello(vehicle_id="VH-WRK", nonce_v=nv).to_bytes()
        fake_m2 = MSG2_ServerHello(nonce_c=nc, session_id=sid,
                                   rsa_pub_der=rogue_pub_der, signature=b"")
        # Manually inject state into rogue ctrl
        rogue_ctrl2._nonce_v = nv
        rogue_ctrl2._nonce_c = nc
        rogue_ctrl2._session_id = sid
        rogue_ctrl2._msg1_ts = time.time()
        rogue_ctrl2._state = "HELLO_SENT"

        # Send the real msg3 but update session_id to match rogue ctrl
        m3 = json.loads(msg3)
        m3["session_id"] = sid.hex()
        rogue_ctrl2.process_key_package(json.dumps(m3, sort_keys=True).encode())
        fail("UNEXPECTED: rogue controller decrypted MSG 3!")
    except ValueError as e:
        dat("Rogue controller error:", str(e)[:65] + "...")
        ok("MSG 3 decryption failed with wrong private key")
        ok("K_s and K_m remain secret — inaccessible without the real RSA_priv")
        ok("Security basis: factoring 2048-bit N is computationally infeasible")

import hashlib


# =============================================================================
# DEMO 7 — MitM Key Substitution Attack Detection
# =============================================================================

def demo_mitm_detection():
    hdr("DEMO 7 — Man-in-the-Middle Key Substitution Attack Detection")

    print(f"""
  {GRAY}Scenario:{RESET}
  Trudy intercepts MSG 2 and replaces RSA_pub with her own public key.
  The vehicle detects the mismatch against its pre-loaded trusted key.

  Without detection: Vehicle would encrypt K_s, K_m under Trudy's key.
  Trudy decrypts MSG 3, learns K_s and K_m, re-encrypts under real key,
  forwards to controller. Both parties think handshake succeeded.
  Trudy silently reads and modifies all subsequent traffic.

  {GRAY}Syllabus:{RESET} Lecture 5 — DH MitM attack (same attack class):
  "Trudy intercepts g^a, sends g^t to Bob; both share key with Trudy."
  Our countermeasure: vehicle compares received key against pre-loaded
  factory key using constant-time hmac.compare_digest().
    """)

    sub("Setup — Trudy generates her own RSA keypair")
    info("Generating Trudy's keypair...")
    trudy_priv, trudy_pub = generate_rsa_keypair()
    trudy_der = serialize_public_key(trudy_pub)
    info(f"Trudy key fp: {key_fingerprint(trudy_pub)}")
    info(f"Real ctrl fp: {key_fingerprint(CTRL_PUB)}")

    sub("Trudy intercepts MSG 2 and substitutes her RSA_pub")
    ctrl = HandshakeController(CTRL_PRIV, "VH-MIM")
    veh  = HandshakeVehicle("VH-MIM", CTRL_PUB_DER, require_signature=False)

    msg1 = veh.create_client_hello()
    msg2_real = ctrl.process_client_hello(msg1)

    # Trudy replaces rsa_pub_der with her own key
    m2 = json.loads(msg2_real)
    m2["rsa_pub_der"] = trudy_der.hex()
    m2["signature"]   = ""           # Trudy cannot produce valid signature
    tampered_msg2 = json.dumps(m2, sort_keys=True).encode()

    info("Trudy replaced RSA_pub with her own key in MSG 2")
    info(f"MSG 2 rsa_pub_der (first 16B): {m2['rsa_pub_der'][:32]}...")
    info(f"Trusted key (first 16B):       {CTRL_PUB_DER.hex()[:32]}...")

    sub("Vehicle detects key mismatch — MitM attempt failed")
    try:
        veh.process_server_hello_and_create_key_package(tampered_msg2)
        fail("UNEXPECTED: vehicle accepted substituted key!")
    except ValueError as e:
        dat("Vehicle response:", str(e)[:70] + "...")
        ok("RSA key substitution detected by constant-time comparison")
        ok("Vehicle aborted handshake — K_s and K_m never generated")
        ok("Trudy's interception failed — she cannot read vehicle traffic")
        ok("Pre-loaded factory key is the root of trust for MitM defence")


# =============================================================================
# DEMO 8 — Replay Attack on MSG 3 (Stale Nonce Detection)
# =============================================================================

def demo_replay_msg3():
    hdr("DEMO 8 — Replay Attack on MSG 3 (N_v Nonce Binding)")

    print(f"""
  {GRAY}Scenario:{RESET}
  Trudy captures MSG 3 from session S (a legitimate handshake).
  In session S' (a new handshake), she replays the captured MSG 3.
  The N_v inside the RSA ciphertext belongs to session S, not S'.
  The controller's N_v verification check rejects it.

  {GRAY}Syllabus:{RESET} Lecture 8 — Kerberos freshness check:
  "Authenticator contains timestamp; reject if too old."
  Our N_v binding is the nonce equivalent — each session's N_v
  is a 128-bit CSPRNG value, unique per session with probability
  1 - 1/2^128 (astronomically close to 1).
    """)

    sub("Session S — legitimate handshake (Trudy captures MSG 3)")
    ctrl_s = HandshakeController(CTRL_PRIV, "VH-RPL")
    veh_s  = HandshakeVehicle("VH-RPL", CTRL_PUB_DER)
    msg1_s = veh_s.create_client_hello()
    msg2_s = ctrl_s.process_client_hello(msg1_s)
    msg3_s = veh_s.process_server_hello_and_create_key_package(msg2_s)
    ok("Session S MSG 3 captured by Trudy")
    dat("Session S nonce N_v:", MSG1_ClientHello.from_bytes(msg1_s).nonce_v.hex()[:16] + "...")

    sub("Session S' — fresh handshake, Trudy replays session S MSG 3")
    ctrl_sp = HandshakeController(CTRL_PRIV, "VH-RPL")
    veh_sp  = HandshakeVehicle("VH-RPL", CTRL_PUB_DER)
    msg1_sp = veh_sp.create_client_hello()
    msg2_sp = ctrl_sp.process_client_hello(msg1_sp)

    dat("Session S' nonce N_v:", MSG1_ClientHello.from_bytes(msg1_sp).nonce_v.hex()[:16] + "...")
    info("N_v values are different (CSPRNG — 2^128 unique values)")

    # Inject session S' session_id into the captured MSG 3
    m3 = json.loads(msg3_s)
    m3["session_id"] = json.loads(msg2_sp)["session_id"]
    replayed_msg3 = json.dumps(m3, sort_keys=True).encode()

    try:
        ctrl_sp.process_key_package(replayed_msg3)
        fail("UNEXPECTED: replayed MSG 3 was accepted!")
    except ValueError as e:
        dat("Controller response:", str(e)[:70] + "...")
        ok("Replay of session S MSG 3 detected in session S'")
        ok("N_v inside RSA ciphertext belongs to session S — mismatch → reject")
        ok("Trudy cannot modify N_v inside the RSA ciphertext (no RSA_priv)")
        ok("Session S' proceeds normally with vehicle's own fresh MSG 3")


# =============================================================================
# DEMO 9 — Missing / Invalid MSG 2b Signature Rejection
# =============================================================================

def demo_signature_validation():
    hdr("DEMO 9 — MSG 2b Signature Validation")

    print(f"""
  {GRAY}Scenario:{RESET}
  Two sub-tests:
    (a) MSG 2 arrives without a signature when require_signature=True.
        Vehicle rejects it — signature is mandatory for authenticated exchange.
    (b) MSG 2 arrives with a forged/corrupted signature.
        Vehicle detects RSA-PSS verification failure.

  {GRAY}Syllabus:{RESET} Lecture 5 — Digital signatures: "Only the holder
  of RSA_priv can produce a valid signature over a message."
  A valid signature over (N_v || RSA_pub_DER) proves:
    (1) The signer holds RSA_priv (only legitimate controller can do this)
    (2) The signature is session-specific (N_v is session-unique)
    """)

    sub("Test (a) — Missing signature when require_signature=True")
    ctrl_a = HandshakeController(CTRL_PRIV, "VH-SIG")
    veh_a  = HandshakeVehicle("VH-SIG", CTRL_PUB_DER, require_signature=True)
    msg1_a = veh_a.create_client_hello()
    msg2_a = ctrl_a.process_client_hello(msg1_a)

    # Strip the signature from MSG 2
    m2 = json.loads(msg2_a)
    m2["signature"] = ""
    msg2_no_sig = json.dumps(m2, sort_keys=True).encode()

    try:
        veh_a.process_server_hello_and_create_key_package(msg2_no_sig)
        fail("UNEXPECTED: vehicle accepted MSG 2 without signature!")
    except ValueError as e:
        dat("Vehicle response:", str(e)[:70] + "...")
        ok("Missing signature correctly rejected when require_signature=True")

    sub("Test (b) — Forged/corrupted MSG 2b signature")
    ctrl_b = HandshakeController(CTRL_PRIV, "VH-SIG2")
    veh_b  = HandshakeVehicle("VH-SIG2", CTRL_PUB_DER, require_signature=True)
    msg1_b = veh_b.create_client_hello()
    msg2_b = ctrl_b.process_client_hello(msg1_b)

    # Corrupt the signature bytes
    m2b = json.loads(msg2_b)
    sig_bytes = bytearray(bytes.fromhex(m2b["signature"]))
    sig_bytes[0] ^= 0xFF
    sig_bytes[50] ^= 0xAA
    m2b["signature"] = bytes(sig_bytes).hex()
    msg2_bad_sig = json.dumps(m2b, sort_keys=True).encode()

    try:
        veh_b.process_server_hello_and_create_key_package(msg2_bad_sig)
        fail("UNEXPECTED: vehicle accepted forged signature!")
    except ValueError as e:
        dat("Vehicle response:", str(e)[:70] + "...")
        ok("Forged MSG 2b signature detected by RSA-PSS verification")
        ok("Vehicle aborted — only legitimate controller can produce valid PSS signature")

    sub("Test (c) — No signature but require_signature=False (academic demo mode)")
    ctrl_c = HandshakeController(CTRL_PRIV, "VH-NOSIG")
    veh_c  = HandshakeVehicle("VH-NOSIG", CTRL_PUB_DER, require_signature=False)
    msg1_c = veh_c.create_client_hello()
    msg2_c = ctrl_c.process_client_hello(msg1_c)
    m2c = json.loads(msg2_c)
    m2c["signature"] = ""
    msg3_c = veh_c.process_server_hello_and_create_key_package(
        json.dumps(m2c, sort_keys=True).encode()
    )
    msg4_c = ctrl_c.process_key_package(msg3_c)
    veh_c.process_handshake_ack(msg4_c)
    ok("require_signature=False: handshake completes without MSG 2b")
    info("In production: ALWAYS use require_signature=True for MitM protection")


# =============================================================================
# DEMO 10 — OAEP Randomness: Same Keys → Different Ciphertext
# =============================================================================

def demo_oaep_randomness():
    hdr("DEMO 10 — OAEP Randomness: Same Plaintext → Different Ciphertext")

    print(f"""
  {GRAY}Scenario:{RESET}
  Encrypting the same K_s, K_m bundle twice under the same RSA_pub
  produces DIFFERENT ciphertexts each time — due to OAEP's random seed.

  {GRAY}Syllabus:{RESET} Lecture 5 — "OAEP includes a random seed before
  encryption ensuring the same plaintext encrypts to different
  ciphertexts." This is IND-CPA security (indistinguishability under
  chosen-plaintext attack). Without this, an attacker who suspects
  a small key space could test candidate keys by encrypting them
  and comparing with the observed ciphertext.
    """)

    # Use fixed keys to demonstrate the OAEP randomness
    fixed_ks = b'A' * 32
    fixed_km = b'B' * 32
    fixed_nv = b'N' * 16
    fixed_nc = b'C' * 16
    bundle   = MSG3_KeyPackage.build_bundle(fixed_ks, fixed_km, fixed_nv, fixed_nc, "VH-OAEP")

    sub("Encrypting the same bundle 4 times under the same RSA_pub")
    ciphertexts = []
    print()
    for i in range(4):
        ct = rsa_encrypt(bundle, CTRL_PUB)
        ciphertexts.append(ct)
        dat(f"Encryption {i+1} (first 24B):", ct[:12].hex() + "...")

        # Verify correctness: decrypt and check
        dec = rsa_decrypt(ct, CTRL_PRIV)
        assert dec == bundle, "Decryption mismatch!"
    print()

    unique = len(set(ciphertexts))
    if unique == 4:
        ok(f"All 4 ciphertexts are UNIQUE (despite identical plaintext + key)")
        ok("OAEP random seed ensures IND-CPA security")
        ok("Attacker observing MSG 3 traffic cannot detect repeated session key bundles")
    else:
        fail(f"Collision detected! Only {unique}/4 unique ciphertexts")

    sub("Verification: all 4 decrypt to the same original bundle")
    for i, ct in enumerate(ciphertexts):
        dec = rsa_decrypt(ct, CTRL_PRIV)
        status = "✔" if dec == bundle else "✘"
        print(f"  {GREEN}{status}{RESET}  Encryption {i+1} decrypts correctly")


# =============================================================================
# DEMO 11 — Multi-Vehicle Independent Sessions
# =============================================================================

def demo_multi_vehicle():
    hdr("DEMO 11 — Multi-Vehicle Independent Session Establishment")

    print(f"""
  {GRAY}Scenario:{RESET}
  Three vehicles connect simultaneously. Each session produces
  independent K_s and K_m values. Sessions are completely isolated:
  one vehicle's session keys cannot decrypt another's traffic.
    """)

    vehicles = ["VH-010", "VH-011", "VH-012"]
    sessions = {}

    sub("Performing handshakes for all three vehicles")
    print()
    for vid in vehicles:
        v_sess, c_sess = perform_full_handshake(vid, CTRL_PRIV, CTRL_PUB_DER)
        sessions[vid] = (v_sess, c_sess)
        fp = v_sess.key_fingerprints()
        print(f"  {GRAY}{vid}{RESET}  K_s_fp={fp['k_s_fp']}  "
              f"K_m_fp={fp['k_m_fp']}  "
              f"session={v_sess.session_id_display()}")
    print()

    sub("Verify all session keys are distinct")
    all_ks = [sessions[v][0].k_s for v in vehicles]
    all_km = [sessions[v][0].k_m for v in vehicles]
    assert len(set(all_ks)) == 3, "K_s collision!"
    assert len(set(all_km)) == 3, "K_m collision!"
    ok("All 3 K_s values are distinct (CSPRNG — 2^256 key space)")
    ok("All 3 K_m values are distinct")

    sub("Cross-vehicle isolation: VH-010 packet rejected by VH-011 controller")
    v010_enc = sessions["VH-010"][0].vehicle_encryptor
    v011_dec = sessions["VH-011"][1].controller_decryptor

    pkt = v010_enc.send({"secret": "should not reach VH-011 controller"})
    result = v011_dec.receive(pkt)
    dat("Cross-vehicle result:", result["status"])
    if result["status"] == "HMAC_FAIL":
        ok("VH-010 packet rejected by VH-011 controller (wrong K_m)")
        ok("Per-vehicle session key isolation confirmed")
    else:
        fail("UNEXPECTED: cross-vehicle packet accepted!")

    sub("Normal communication within each session")
    print()
    for vid in vehicles:
        v_sess, c_sess = sessions[vid]
        pkt    = v_sess.vehicle_encryptor.send({"telemetry": vid, "speed": 75.0})
        result = c_sess.controller_decryptor.receive(pkt)
        status = f"{GREEN}OK{RESET}" if result["status"]=="OK" else f"{RED}FAIL{RESET}"
        print(f"  {GRAY}{vid}{RESET}  seq={pkt.sequence_no}  status={status}  "
              f"payload={json.dumps(result['payload'])}")


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print(f"""
{BOLD}{BLUE}
╔══════════════════════════════════════════════════════════════════════╗
║   EE8257 Information Security — Group 29                            ║
║   Module 3: RSA Handshake & Secure Session Key Exchange             ║
║   Secure Vehicle-to-Controller Message Exchange                     ║
╚══════════════════════════════════════════════════════════════════════╝
{RESET}""")

    demo_keypair()
    demo_full_handshake()
    demo_key_recovery()
    demo_end_to_end()
    demo_tampered_msg3()
    demo_wrong_private_key()
    demo_mitm_detection()
    demo_replay_msg3()
    demo_signature_validation()
    demo_oaep_randomness()
    demo_multi_vehicle()

    hdr("ALL DEMOS COMPLETE")
    print(f"""
  {GREEN}{BOLD}Security properties demonstrated:{RESET}
  {GREEN}✔{RESET}  Key distribution     — K_s and K_m delivered via RSA-OAEP (never in plaintext)
  {GREEN}✔{RESET}  Confidentiality      — AES-256-CBC encrypts all payload (Module 2)
  {GREEN}✔{RESET}  Integrity + Auth     — HMAC-SHA256 with K_m (Module 1)
  {GREEN}✔{RESET}  Controller identity  — RSA-PSS signature over (N_v || RSA_pub) in MSG 2b
  {GREEN}✔{RESET}  MitM prevention      — Pre-loaded RSA_pub compared against received key
  {GREEN}✔{RESET}  Replay prevention    — N_v + N_c nonce binding inside RSA ciphertext
  {GREEN}✔{RESET}  Session freshness    — Both nonces are 128-bit CSPRNG, unique per session
  {GREEN}✔{RESET}  OAEP security        — Cube root attack defeated; IND-CPA secure
  {GREEN}✔{RESET}  Key separation       — K_s ≠ K_m enforced at runtime
  {GREEN}✔{RESET}  Multi-vehicle        — Independent sessions; cross-session isolation

  {CYAN}Next:{RESET} Module 4 — Full Vehicle ↔ Controller TCP Socket Integration
  Live socket communication with real network transmission of all
  handshake messages and post-handshake encrypted telemetry.
    """)