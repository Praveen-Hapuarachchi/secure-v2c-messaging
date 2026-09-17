# Secure Vehicle-to-Controller Message Exchange
## Using Hybrid Encryption and HMAC Authentication

**EE8257 — Information Security | Group 29**
Faculty of Engineering, University of Ruhuna

| Member | Registration |
|--------|-------------|
| H.P.L. Hapuarachchi | EG/2020/3953 |
| W.M.U.N. Bandara | EG/2020/3850 |
| G.M.L.D. Senarathna | EG/2020/4202 |
| W.S. Chathumal | EG/2020/3867 |

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [The Security Problem We Solve](#2-the-security-problem-we-solve)
3. [System Architecture](#3-system-architecture)
4. [Cryptographic Design](#4-cryptographic-design)
   - 4.1 [Module 1 — HMAC-SHA256](#41-module-1--hmac-sha256-authentication-engine)
   - 4.2 [Module 2 — AES-256-CBC](#42-module-2--aes-256-cbc-encryption-engine)
   - 4.3 [Module 3 — RSA Handshake](#43-module-3--rsa-2048-handshake--key-exchange)
   - 4.4 [Module 4 — TCP Integration](#44-module-4--tcp-socket-integration)
5. [The Five-Message Protocol](#5-the-five-message-protocol)
6. [Attack Mitigations](#6-attack-mitigations)
7. [Syllabus Mapping](#7-syllabus-mapping)
8. [Project File Structure](#8-project-file-structure)
9. [Installation and Dependencies](#9-installation-and-dependencies)
10. [How to Run the Project](#10-how-to-run-the-project)
    - 10.1 [Step 1 — Unit Tests (Automated Proof)](#101-step-1--unit-tests-automated-proof)
    - 10.2 [Step 2 — Module Demonstrations](#102-step-2--module-demonstrations)
    - 10.3 [Step 3 — Live Two-Terminal Demo](#103-step-3--live-two-terminal-demo)
    - 10.4 [Step 4 — Integration Tests](#104-step-4--integration-tests)
    - 10.5 [Step 5 — Full Test Suite](#105-step-5--full-test-suite)
11. [Expected Outputs](#11-expected-outputs)
12. [Security Guarantees](#12-security-guarantees)
13. [Viva Preparation — Common Questions](#13-viva-preparation--common-questions)

---

## 1. Project Overview

This project implements a **complete, production-quality secure communication system** between vehicles and a central controller. Every message a vehicle sends is:

- **Encrypted** with AES-256-CBC so no eavesdropper can read the payload
- **Authenticated** with HMAC-SHA256 so any tampering is immediately detected
- **Protected against replay** using nonce binding and monotonic sequence numbers
- **Key-exchanged** using RSA-2048 with OAEP padding so session keys are never transmitted in plaintext

The system mirrors the architecture of TLS (Transport Layer Security) as described in Lecture 8 of the EE8257 syllabus: RSA is used once per session to securely deliver symmetric keys, and AES + HMAC handle all subsequent data exchange.

---

## 2. The Security Problem We Solve

Vehicles transmit sensitive telemetry — speed, location, fuel levels, engine alerts — to a central controller over an untrusted network (4G cellular, WiFi, etc.). An adversary on that network can:

| Threat | Description |
|--------|-------------|
| **Eavesdropping** | Read plaintext sensor data |
| **Tampering** | Modify speed or command values in transit |
| **Replay attack** | Capture a legitimate UNLOCK command and re-send it later |
| **Impersonation** | Pretend to be a legitimate vehicle |
| **Man-in-the-Middle** | Intercept key exchange and substitute their own key |

Our system defeats all five threats using layered cryptographic mechanisms grounded in the EE8257 syllabus.

---

## 3. System Architecture

```
┌─────────────────────┐        Untrusted Network         ┌─────────────────────┐
│      VEHICLE         │  ──────────────────────────────  │     CONTROLLER       │
│                      │                                   │                      │
│  ┌────────────────┐  │   MSG 1: ClientHello (plaintext)  │  ┌────────────────┐  │
│  │ RSA Handshake  │  │  ─────────────────────────────►  │  │ RSA Handshake  │  │
│  │  (Module 3)    │  │                                   │  │  (Module 3)    │  │
│  └────────────────┘  │  ◄─────────────────────────────  │  └────────────────┘  │
│                      │   MSG 2: ServerHello + Signature  │                      │
│  ┌────────────────┐  │                                   │  ┌────────────────┐  │
│  │ AES-CBC Engine │  │   MSG 3: RSA_OAEP{K_s, K_m}      │  │ AES-CBC Engine │  │
│  │  (Module 2)    │  │  ─────────────────────────────►  │  │  (Module 2)    │  │
│  └────────────────┘  │                                   │  └────────────────┘  │
│                      │  ◄─────────────────────────────  │                      │
│  ┌────────────────┐  │   MSG 4: AES{SESSION_READY}       │  ┌────────────────┐  │
│  │ HMAC Engine    │  │                                   │  │ HMAC Engine    │  │
│  │  (Module 1)    │  │   MSG 5+: AES-CBC(payload)+HMAC   │  │  (Module 1)    │  │
│  └────────────────┘  │  ─────────────────────────────►  │  └────────────────┘  │
│                      │                                   │                      │
│  ┌────────────────┐  │   ACK: encrypted confirmation     │  ┌────────────────┐  │
│  │ TCP Framing    │  │  ◄─────────────────────────────  │  │ TCP Framing    │  │
│  │  (Module 4)    │  │                                   │  │  (Module 4)    │  │
│  └────────────────┘  │                                   │  └────────────────┘  │
└─────────────────────┘                                   └─────────────────────┘
```

The system is divided into four independent modules that stack on top of each other:

- **Module 1** (HMAC) depends on nothing
- **Module 2** (AES) imports Module 1
- **Module 3** (RSA) imports Modules 1 and 2
- **Module 4** (TCP) imports Modules 1, 2, and 3

---

## 4. Cryptographic Design

### 4.1 Module 1 — HMAC-SHA256 Authentication Engine

**File:** `modules/hmac_engine.py`

**Purpose:** Proves that a message was sent by a party holding the secret MAC key K_m, and that the message was not modified in transit.

**Algorithm:** HMAC-SHA256 as specified in RFC 2104 and described in Lecture 6.

The RFC 2104 formula:

```
HMAC(M, K) = H( K ⊕ opad  ||  H( K ⊕ ipad  ||  M ) )

where:
  ipad = 0x36 repeated 64 times (SHA-256 block size)
  opad = 0x5C repeated 64 times
  H    = SHA-256
  ||   = concatenation
  ⊕    = XOR
```

**Why not a plain SHA-256 hash?**
A bare hash h(M) provides no authentication. Trudy can replace message M with M' and compute h(M') herself — the receiver cannot detect the substitution. HMAC binds the hash to the secret key K_m. Without K_m, Trudy cannot produce a valid tag for any message.

**Key security features implemented:**
- `hmac.compare_digest()` for constant-time comparison (defeats timing side-channel attacks)
- Separate K_m from K_s — the MAC key is never the same as the encryption key
- 128-bit nonce + Unix timestamp + monotonic sequence number for three-layer replay protection

---

### 4.2 Module 2 — AES-256-CBC Encryption Engine

**File:** `modules/aes_engine.py`

**Purpose:** Encrypts all vehicle payloads so no eavesdropper can read the content.

**Algorithm:** AES-256 in CBC (Cipher Block Chaining) mode with PKCS7 padding, as described in Lecture 4.

**Why AES replaced DES (Lecture 4):**

| Property | DES | AES-256 |
|----------|-----|---------|
| Key size | 56 bits | 256 bits |
| Key space | 2⁵⁶ ≈ 72 trillion | 2²⁵⁶ ≈ 10⁷⁷ |
| Broken? | Yes (1998, 22 hours) | No known attack |
| Block size | 64 bits | 128 bits |

**Why CBC instead of ECB (Lecture 4):**

ECB (Electronic Codebook) encrypts each 16-byte block independently. Identical plaintext blocks produce identical ciphertext blocks — structural patterns survive. The "ECB penguin" demonstration shows this vividly: encrypting an image with ECB still reveals the outline.

CBC (Cipher Block Chaining) XORs each plaintext block with the previous ciphertext block before encrypting:

```
C[0] = E( P[0] ⊕ IV,      K_s )
C[i] = E( P[i] ⊕ C[i-1],  K_s )
```

Identical plaintext blocks always produce different ciphertext because each block depends on all previous ciphertext. A fresh random 16-byte IV is generated for every single message.

**Encrypt-then-MAC (not MAC-then-Encrypt):**

Three orderings exist. Only Encrypt-then-MAC is secure:

```
✔ Encrypt-then-MAC (this project — TLS 1.3, IPSec ESP):
    C    = AES-CBC(payload, K_s, IV)
    TAG  = HMAC(IV || C, K_m)
    Receiver: verify TAG first → then decrypt
    → No padding oracle attack possible

✘ MAC-then-Encrypt (TLS 1.2, SSL 3.0 — deprecated):
    TAG  = HMAC(payload, K_m)
    C    = AES-CBC(payload || TAG, K_s, IV)
    Receiver must decrypt before verifying → POODLE attack (2014)

✘ Encrypt-and-MAC (SSH default):
    TAG  = HMAC(payload, K_m)   ← MAC over plaintext — leaks information
    C    = AES-CBC(payload, K_s, IV)
```

---

### 4.3 Module 3 — RSA-2048 Handshake & Key Exchange

**File:** `modules/rsa_engine.py`

**Purpose:** Securely delivers K_s and K_m to the controller without ever transmitting them in plaintext.

**The Key Distribution Problem:**
Modules 1 and 2 assume K_s and K_m are already shared. But how do two parties who have never met agree on a secret key over a network controlled by an adversary? This is the fundamental key distribution problem. RSA solves it asymmetrically.

**RSA Mathematics (Lecture 5 + Lecture 2):**

```
Key generation:
  1. Choose large primes p, q  (each ~1024 bits)
  2. N = p × q                 (2048-bit modulus)
  3. φ(N) = (p-1)(q-1)         (Euler's totient — Lecture 2)
  4. e = 65537                 (public exponent; = 2¹⁶+1)
  5. d ≡ e⁻¹ mod φ(N)         (Extended Euclidean — Lecture 2)

Public key:  (N, e)  — safe to publish
Private key: (N, d)  — controller keeps secret

Encryption (anyone):    C = M^e mod N
Decryption (controller): M = C^d mod N
```

Security basis: factoring N = p × q when N is 2048 bits requires astronomical computation with all known algorithms (best: General Number Field Sieve, sub-exponential but infeasible at 2048 bits).

**Why OAEP padding is mandatory (Lecture 5 — cube root attack):**

Textbook RSA (C = M^e mod N) with e = 3 and small M: M³ < N, so C = M³ as an ordinary integer. The attacker computes ∛C = M — no key required. OAEP prepends a random 32-byte seed before encryption, ensuring the effective input to raw RSA is always large. The same plaintext encrypted twice produces different ciphertexts (IND-CPA security).

**Why e = 65537 not e = 3:**
e = 65537 = 2¹⁶ + 1 is a Fermat prime. It makes M^e >> N for any realistic plaintext, eliminating the cube root attack. It requires only 17 squarings in the square-and-multiply algorithm — nearly as efficient as e = 3.

---

### 4.4 Module 4 — TCP Socket Integration

**File:** `modules/network.py`, `controller.py`, `vehicle.py`

**Purpose:** Transmits all handshake messages and encrypted telemetry over real TCP sockets.

**Why a framing layer is needed:**
TCP is a stream protocol, not a message protocol. It guarantees bytes arrive in order but makes no guarantee about where message boundaries fall. A 300-byte message may arrive as three separate 100-byte TCP segments. Without framing, the receiver cannot tell where one message ends and the next begins.

**Length-prefix framing (mirrors TLS record layer, Lecture 8):**

```
Wire format: [4-byte big-endian uint32 length N][N bytes payload]

Sender:   header = struct.pack('>I', len(payload))
          socket.sendall(header + payload)

Receiver: header = recv_exactly(4 bytes)
          n      = struct.unpack('>I', header)[0]
          data   = recv_exactly(n bytes)
```

`sendall()` is used on the sender side — it loops internally until all bytes are delivered to the kernel send buffer. `recv_exactly()` loops until the full requested byte count is accumulated, handling TCP segmentation correctly.

---

## 5. The Five-Message Protocol

```
Vehicle (V)                    Untrusted Network              Controller (C)
    │                                                               │
    │──── MSG 1: ClientHello ────────────────────────────────────► │
    │     VehicleID | N_v | ProtocolVersion   [plaintext]          │
    │                                                               │
    │ ◄─── MSG 2: ServerHello ──────────────────────────────────── │
    │      N_c | SessionID | RSA_pub           [plaintext]         │
    │                                                               │
    │ ◄─── MSG 2b: Signature ───────────────────────────────────── │
    │      Sign(RSA_priv, N_v || RSA_pub)      [signature]         │
    │                                                               │
    │──── MSG 3: KeyPackage ─────────────────────────────────────► │
    │     RSA_OAEP{ K_s | K_m | N_v | N_c | VehicleID }           │
    │                                                               │
    │ ◄─── MSG 4: HandshakeACK ─────────────────────────────────── │
    │      AES-CBC{"SESSION_READY" | SessionID | N_c}, K_s         │
    │                                                               │
    │════ SESSION ESTABLISHED — K_s and K_m shared ════════════════│
    │                                                               │
    │──── MSG 5+: AES-CBC(payload, K_s, IV) | HMAC(K_m) ─────────► │
    │ ◄─── ACK: AES-CBC("OK" | seq, K_s) ─────────────────────── │
    │──── MSG 6+  ...                                               │
```

**What each nonce does:**

- **N_v** (vehicle nonce, 128 bits): Bound inside the RSA ciphertext of MSG 3. If Trudy replays MSG 3 from a previous session, the controller finds N_v ≠ current session's N_v and rejects it.
- **N_c** (controller nonce, 128 bits): Also bound inside MSG 3. Proves the vehicle received MSG 2 before generating MSG 3 — prevents precomputed-MSG3 attacks.
- **SessionID** = SHA-256(N_v || N_c || VehicleID)[:16]: Uniquely identifies this session. Derived from both parties' randomness so neither can control it alone.

---

## 6. Attack Mitigations

| Attack | How it works | Our countermeasure | Syllabus |
|--------|-------------|-------------------|---------|
| **Eavesdropping** | Passive interception of network traffic | AES-256-CBC encryption — ciphertext reveals nothing | L4: AES key space 2²⁵⁶ |
| **Message tampering** | Flip bytes in ciphertext | HMAC-SHA256 detects any modification (HMAC_FAIL) | L6: HMAC integrity |
| **Impersonation** | Send messages with wrong K_m | HMAC verification fails — no K_m, no valid tag | L6: HMAC authentication |
| **Replay attack** | Resend a captured valid packet | Monotonic sequence counter rejects duplicates | L8: Kerberos + GSM pattern |
| **Man-in-the-Middle** | Replace RSA_pub in MSG 2 | Vehicle compares against pre-loaded factory key | L5: DH MitM discussion |
| **RSA cube root attack** | Small e, small M: M³ < N | OAEP padding defeats this completely | L5: Cube root attack |
| **Handshake replay** | Replay old MSG 3 | N_v + N_c nonces bound inside RSA ciphertext | L8: Kerberos nonce binding |
| **IV reuse (OTP attack)** | Reuse IV → XOR leaks plaintext | Fresh CSPRNG IV generated per message | L3: OTP depth attack |
| **ECB pattern analysis** | Identify repeated messages | CBC mode — identical blocks produce different CT | L4: ECB vs CBC |
| **Padding oracle (POODLE)** | Decrypt before MAC → error oracle | Encrypt-then-MAC: HMAC checked before decrypt | L4: CBC + POODLE |
| **Session fixation** | Force known SessionID | SessionID derived from both nonces — unpredictable | L8: Kerberos session |
| **Timing side-channel** | Measure response time to forge MAC | `hmac.compare_digest()` — constant-time comparison | L1: Implementation vulnerabilities |

---

## 7. Syllabus Mapping

Every design decision is directly grounded in EE8257 lecture material:

| Lecture | Topic | Where used in project |
|---------|-------|----------------------|
| **L1** — CIA Triad | Confidentiality, Integrity, Availability | All three provided: AES (C), HMAC (I), ACK (A) |
| **L2** — Number Theory | φ(N), Extended Euclidean Algorithm | RSA key generation (d = e⁻¹ mod φ(N)) |
| **L3** — Classical Crypto | OTP depth attack (two-time pad) | IV reuse demo shows same vulnerability |
| **L4** — Block Ciphers | AES, DES comparison, ECB vs CBC, padding | Module 2 entirely; ECB penguin demo |
| **L5** — Asymmetric Crypto | RSA, OAEP, cube root attack, DH MitM | Module 3 entirely; MitM demo |
| **L6** — Hash Functions | HMAC (RFC 2104), SHA-256, avalanche effect | Module 1 entirely; internals demo |
| **L7** — Access Control | Authentication factors | VehicleID + HMAC as authentication |
| **L8** — Security Protocols | SSL/TLS hybrid model, Kerberos, GSM | Module 4 architecture; nonce design |

---

## 8. Project File Structure

```
project/
│
├── modules/                    ← Core cryptographic libraries
│   ├── hmac_engine.py          ← Module 1: HMAC-SHA256 engine
│   ├── aes_engine.py           ← Module 2: AES-256-CBC engine
│   ├── rsa_engine.py           ← Module 3: RSA-2048 handshake engine
│   └── network.py              ← Module 4: TCP length-prefix framing
│
├── demos/                      ← Visual demonstrations (run for viva)
│   ├── demo_hmac.py            ← 7 HMAC demonstrations + attack sims
│   ├── demo_aes.py             ← 10 AES demonstrations + attack sims
│   ├── demo_rsa.py             ← 11 RSA demonstrations + attack sims
│   └── demo_tcp.py             ← Full live system demo (all 4 modules)
│
├── tests/                      ← Automated test suites
│   ├── test_hmac_engine.py     ← 29 unit tests for Module 1
│   ├── test_aes_engine.py      ← 43 unit tests for Module 2
│   ├── test_rsa_engine.py      ← 48 unit tests for Module 3
│   └── test_integration.py     ← TCP socket integration tests
│
├── controller.py               ← Live TCP server (run in Terminal 1)
└── vehicle.py                  ← Live TCP client (run in Terminal 2/3)
```

**Dependency chain:**

```
hmac_engine.py
    ↓ imported by
aes_engine.py
    ↓ imported by
rsa_engine.py
    ↓ imported by
network.py, controller.py, vehicle.py, all demos, all tests
```

---

## 9. Installation and Dependencies

**Python version required:** Python 3.10 or higher

Check your Python version:

```
python --version
```

**Install required packages:**

```
pip install cryptography pytest
```

The `cryptography` library (by PyCA) provides RSA, AES, and hashing primitives. All HMAC and SHA-256 operations use Python's built-in `hmac` and `hashlib` standard library modules — no external dependency needed for Module 1.

**Verify installation:**

```
python -c "from cryptography.hazmat.primitives.asymmetric import rsa; print('OK')"
```

---

## 10. How to Run the Project

> **Important:** Run all commands from the project root directory:
> ```
> cd "C:\Users\hapup\OneDrive\Desktop\7th sem\EC7201 Information Security\Project"
> ```

---

### 10.1 Step 1 — Unit Tests (Automated Proof)

Run the unit tests **first**. They prove every individual component works correctly before combining them. If any test fails here, fix it before proceeding.

**Test Module 1 — HMAC Engine (29 tests)**

```
python -m pytest tests/test_hmac_engine.py -v
```

Expected: `29 passed`

What these tests verify: key generation randomness, HMAC generation and verification, message tampering detection, wrong key rejection, replay attack via sequence counter, stale timestamp rejection, avalanche effect (1-bit change → ~50% bit difference in output), RFC 2104 manual construction matches stdlib, multi-vehicle isolation.

---

**Test Module 2 — AES Engine (43 tests)**

```
python -m pytest tests/test_aes_engine.py -v
```

Expected: `43 passed`

What these tests verify: PKCS7 padding correctness for 6 different input lengths, raw CBC encrypt/decrypt round-trip, IV uniqueness (200 IVs all different), same-key rejection (K_s ≠ K_m enforced), ciphertext tampering raises ValueError, IV tampering raises ValueError, 10 consecutive messages all have unique IVs, wire serialisation (to_bytes/from_bytes round-trip), ECB produces identical blocks for identical input (pattern leakage proven), CBC produces unique blocks for identical input (semantic security proven).

---

**Test Module 3 — RSA Engine (48 tests)**

```
python -m pytest tests/test_rsa_engine.py -v
```

Expected: `48 passed` (takes ~1 second — RSA keypair generated once)

What these tests verify: keypair is 2048 bits, public exponent is 65537, OAEP produces different ciphertext each call (randomness), OAEP fails on tampered ciphertext, PSS signature verifies correctly, PSS rejects tampered messages, all 4 handshake message types parse correctly, full 4-message handshake produces identical K_s and K_m on both sides, MitM key substitution detected, missing signature rejected, wrong protocol version rejected, nonce mismatch detected (replay prevention), post-handshake AES+HMAC pipeline works, replay rejected after handshake.

---

**Run all three unit test suites together:**

```
python -m pytest tests/test_hmac_engine.py tests/test_aes_engine.py tests/test_rsa_engine.py -v
```

Expected: `120 passed`

This is your primary proof statement for the viva. Screenshot this output.

---

### 10.2 Step 2 — Module Demonstrations

Run these to visually show what each module does. Each demo runs completely standalone — no server needed, no setup required. Run them **after** the unit tests pass.

**Demo Module 1 — HMAC:**

```
python -m demos.demo_hmac
```

Duration: ~2 seconds. Shows 7 demonstrations including normal message exchange, tampering detection, wrong key rejection, replay attack detection, avalanche effect (every message shows bit-difference percentage ~50%), RFC 2104 manual construction matching stdlib exactly, multi-vehicle independent sessions.

---

**Demo Module 2 — AES:**

```
python -m demos.demo_aes
```

Duration: ~3 seconds. Shows 10 demonstrations including normal encryption/decryption, IV randomness (4 identical plaintexts → 4 completely different ciphertexts), tampered ciphertext detection, IV-swap attack prevention, ECB pattern leakage vs CBC confidentiality (side-by-side comparison showing identical ECB blocks and unique CBC blocks), IV reuse attack (shows XOR recovery of secret message when IV is reused — the OTP depth attack from Lecture 3), PKCS7 padding internals, Encrypt-then-MAC vs alternatives comparison.

---

**Demo Module 3 — RSA:**

```
python -m demos.demo_rsa
```

Duration: ~8 seconds (generates 3 RSA keypairs for attack demos). Shows 11 demonstrations including key generation and fingerprint, full 4-message handshake with every field printed, session key recovery verification, end-to-end pipeline (RSA → AES+HMAC), tampered MSG 3 RSA ciphertext rejection, wrong private key failure, MitM key substitution detection (vehicle rejects substituted key), replay of MSG 3 from previous session rejected (nonce mismatch), signature validation tests, OAEP randomness (same bundle → 4 different ciphertexts), multi-vehicle independent sessions with cross-vehicle isolation.

---

**Demo Module 4 — Full TCP Integration:**

```
python -m demos.demo_tcp
```

Duration: ~15 seconds. Starts a controller server automatically in a background thread, then runs 4 demonstrations: single vehicle full handshake traced byte-by-byte over a real TCP socket, 3 vehicles connecting simultaneously with independent sessions, live attack simulations over TCP (MitM, ciphertext tampering, replay), final security summary table with all 12 security properties and their syllabus references.

---

### 10.3 Step 3 — Live Two-Terminal Demo

This is the most visually impressive demonstration for the viva. You run the controller and vehicle as separate processes communicating over a real TCP connection.

**You need two terminal windows open simultaneously.**

---

**Terminal 1 — Start the Controller FIRST:**

```
python controller.py
```

You will see:

```
════════════════════════════════════════════════════════════════
  EE8257 Information Security — Group 29
  Module 4: Controller TCP Server
════════════════════════════════════════════════════════════════

  Generating RSA-2048 keypair...
  ✔  Keypair ready in 0.06s
  Fingerprint: 6B:E6:A5:F3:4E:62:D7:9C...
  ✔  RSA_pub.der saved — distribute to vehicles

  Controller listening on 127.0.0.1:9999
  Waiting for vehicles...
```

**Why you run this first:** The controller generates the RSA keypair and saves `RSA_pub.der` to disk. The vehicle needs this file to load the trusted public key. If you run the vehicle before the controller, the file does not exist and the vehicle exits with an error.

**Leave this terminal running.**

---

**Terminal 2 — Connect Vehicle VH-001:**

```
python vehicle.py VH-001
```

You will see the complete handshake and 8 encrypted telemetry messages:

```
  ✔  RSA_pub.der loaded
    Fingerprint: 6B:E6:A5:F3:4E:62:D7:9C...     ← matches controller
  Connecting to 127.0.0.1:9999...
  ✔  TCP connection established

  ── Phase 1–3: RSA Handshake
  →  VH-001  MSG 1  ClientHello  N_v=373adfcc...
  ←  Controller  MSG 2  ServerHello  N_c=...  sig=256B
  →  VH-001  MSG 3  KeyPackage   RSA_ciphertext=256B
  ←  Controller  MSG 4  HandshakeACK SESSION_READY ✔

  ✔  SESSION ESTABLISHED
     Session ID: 103be0a2a03a2e77...
     K_s fp:     b53bc1b1f4f5c871...   ← fingerprint: safe to display
     K_m fp:     cb75581bebac0451...   ← raw key: never shown
     Keys never transmitted in plaintext.

  ── Phase 4: Secure Data Exchange
  →  VH-001  seq=1  ct=160B  hmac=f0fa65c716...
  ←  Controller  ACK seq=1  ✔
  ...
```

Simultaneously in Terminal 1 (Controller) you see:

```
  ←  VH-001  MSG 1  ClientHello  (N_v=373adfcc...)
  →  VH-001  MSG 2  ServerHello + RSA_pub + Signature
  ←  VH-001  MSG 3  KeyPackage  (662B RSA-OAEP ciphertext)
  →  VH-001  MSG 4  HandshakeACK (AES-encrypted SESSION_READY)

  ✔  SESSION ESTABLISHED
     Vehicle:    VH-001
     Session ID: 103be0a2a03a2e77...
     K_s fp:     b53bc1b1f4f5c871...

  ✔  VH-001  seq=1  ct=160B  payload={...}
  ✔  VH-001  seq=2  ct=160B  payload={...}
  ...
```

**Key observation:** The fingerprints match on both sides. The same Session ID appears in both terminals. The K_s and K_m fingerprints are identical — proving the keys were successfully exchanged via RSA without ever being transmitted in plaintext.

---

**Optional — Terminal 3 — Second vehicle simultaneously:**

```
python vehicle.py VH-002
```

The controller handles both VH-001 and VH-002 concurrently in separate threads. Each gets completely independent session keys — VH-001's K_s and K_m are different from VH-002's K_s and K_m.

---

**Command line options for vehicle.py:**

```
python vehicle.py <VehicleID> [host] [port] [n_messages]

python vehicle.py VH-001                    # default: 127.0.0.1:9999, 8 messages
python vehicle.py VH-001 127.0.0.1 9999    # explicit host and port
python vehicle.py VH-001 127.0.0.1 9999 20 # send 20 messages
```

**Command line options for controller.py:**

```
python controller.py                        # default: 127.0.0.1:9999
python controller.py 0.0.0.0 9999          # listen on all interfaces
python controller.py 127.0.0.1 8888        # custom port
```

---

### 10.4 Step 4 — Integration Tests

Run the integration tests **after** the live demo works. These automatically spin up real TCP sockets and verify the full system in 40 automated tests.

```
python -m pytest tests/test_integration.py -v
```

What these tests cover:

- `TestNetworkFraming` (7 tests): TCP length-prefix framing works for small, empty, and 32KB messages; multiple sequential messages on one connection; JSON helpers; oversized message raises ValueError; dropped connection raises ConnectionError.

- `TestHandshakeOverTCP` (7 tests): Full handshake over loopback sockets; K_s and K_m match on both sides; session ID is 16 bytes; MSG 2b signature is 256 bytes; MSG 3 ciphertext is 256 bytes; different handshakes produce different keys.

- `TestSecureDataExchange` (7 tests): Single message decrypts correctly; 5 messages all pass HMAC; sequence numbers increment 1,2,3; payload survives encryption round-trip exactly; same plaintext produces different ciphertext (IV randomness); HMAC tags differ per message; ACK contains correct sequence number.

- `TestAttackDetectionOverTCP` (7 tests): Ciphertext tampering → HMAC_FAIL; replay → REPLAY; MitM key substitution detected; wrong RSA private key fails; invalid SessionID rejected; wrong protocol version rejected; stale timestamp rejected.

- `TestMultiVehicleTCP` (3 tests): Two concurrent vehicles both complete successfully; cross-vehicle key isolation (VH-A packet rejected by VH-B's decryptor); three handshakes produce three distinct K_s fingerprints.

- `TestSessionLifecycle` (3 tests): CLOSE message received correctly; vehicle reconnects after disconnect; sequential sessions have different keys.

- `TestSecurityProperties` (6 tests): Plaintext bytes not found in ciphertext; all HMAC tags are exactly 32 bytes; all IVs are 16 bytes and unique; RSA_pub fingerprint matches over TCP; nonces are 128 bits; SESSION_READY token present in MSG 4.

---

### 10.5 Step 5 — Full Test Suite

Run all tests together to get the final count:

```
python -m pytest tests/ -v
```

Expected final result:

```
160+ passed
```

---

## 11. Expected Outputs

**What you should see from each command:**

| Command | Expected | Time |
|---------|----------|------|
| `pytest tests/test_hmac_engine.py -v` | `29 passed` | 0.1s |
| `pytest tests/test_aes_engine.py -v` | `43 passed` | 0.2s |
| `pytest tests/test_rsa_engine.py -v` | `48 passed` | 1.0s |
| `pytest tests/test_hmac_engine.py tests/test_aes_engine.py tests/test_rsa_engine.py -v` | `120 passed` | 1.0s |
| `python -m demos.demo_hmac` | 7 demos, all `✔` | 2s |
| `python -m demos.demo_aes` | 10 demos, all `✔` | 3s |
| `python -m demos.demo_rsa` | 11 demos, all `✔` | 8s |
| `python -m demos.demo_tcp` | 4 demos, all `✔` | 15s |
| `python controller.py` | Server listening, then handles vehicles | — |
| `python vehicle.py VH-001` | 8 messages sent and ACK'd | 8s |
| `pytest tests/test_integration.py -v` | 33-40 passed | 35s |

---

## 12. Security Guarantees

After a successful handshake and during all subsequent data exchange, the system provides:

| Property | Mechanism | Proof |
|----------|-----------|-------|
| **Confidentiality** | AES-256-CBC — key space 2²⁵⁶ | Plaintext not in ciphertext (test_integration) |
| **Integrity** | HMAC-SHA256 over ciphertext | Tampered ciphertext → HMAC_FAIL (demo_aes Demo 3) |
| **Authentication** | K_m binds messages to key holder | Wrong key → HMAC_FAIL (demo_hmac Demo 3) |
| **Key confidentiality** | RSA-OAEP — only RSA_priv decrypts | Wrong private key fails (demo_rsa Demo 6) |
| **Controller identity** | RSA-PSS signature over (N_v \|\| RSA_pub) | Forged signature rejected (demo_rsa Demo 9) |
| **MitM prevention** | Pre-loaded RSA_pub vs received key | Substituted key detected (demo_rsa Demo 7) |
| **Replay prevention** | N_v+N_c nonce + sequence counter | Replay → REPLAY (demo_hmac Demo 4, demo_rsa Demo 8) |
| **Session freshness** | 128-bit CSPRNG nonces per session | Nonces unique across 200 samples (test_rsa) |
| **Semantic security** | Fresh random IV per message | Identical plaintext → different CT (demo_aes Demo 2) |
| **No padding oracle** | Encrypt-then-MAC: verify before decrypt | ValueError at HMAC line, AES never runs (demo_aes Demo 8) |
| **Key separation** | K_s ≠ K_m enforced at runtime | Same-key ValueError (test_aes TestAESEngine) |
| **TCP correctness** | Length-prefix framing | 32KB messages intact (test_integration TestNetworkFraming) |

---

## 13. Viva Preparation — Common Questions

**Q: Why is RSA used only for key exchange and not for every message?**

A: RSA-2048 encryption produces 256 bytes of ciphertext regardless of input size (13:1 expansion for a 20-byte message). It takes ~3ms per operation and has a 190-byte maximum plaintext limit. AES-CBC on the same 20-byte message produces 32 bytes in under 1 microsecond with no size limit. RSA is used once per session to solve the key distribution problem. All subsequent messages use AES for its performance and flexibility.

**Q: What happens if Trudy intercepts MSG 3 and replays it?**

A: MSG 3 contains N_v (vehicle nonce) and N_c (controller nonce) inside the RSA ciphertext. In a new session S', the controller generates a fresh N_v'. When it decrypts the replayed MSG 3, the N_v inside the ciphertext belongs to session S, not S'. The controller rejects it with "N_v mismatch — MSG 3 appears replayed." Trudy cannot modify N_v inside the ciphertext because she does not hold RSA_priv.

**Q: Why use HMAC instead of a plain SHA-256 hash?**

A: A bare hash h(M) provides integrity but not authentication. Trudy can replace M with M' and compute h(M') herself — the receiver cannot distinguish. HMAC(M, K_m) requires the secret key K_m. Without K_m, Trudy cannot produce a valid tag for any message. The RFC 2104 double-hash construction H(K⊕opad || H(K⊕ipad || M)) also prevents length-extension attacks that would be possible with H(K || M).

**Q: Why Encrypt-then-MAC and not MAC-then-Encrypt?**

A: MAC-then-Encrypt requires decryption before MAC verification. The POODLE attack (2014) exploited this in SSL 3.0 — the receiver's error response to bad PKCS7 padding became an oracle allowing byte-by-byte plaintext recovery. Encrypt-then-MAC verifies the HMAC before any decryption attempt. If verification fails, `ValueError` is raised immediately. The padding oracle attack surface does not exist.

**Q: What is the avalanche effect and how does your system use it?**

A: The avalanche effect (Lecture 6) is the property that changing one bit in a hash input changes approximately 50% of the output bits. Our HMAC-SHA256 demonstrations show that changing a single character (e.g., "speed=87.4" → "speed=87.5") produces an output differing by ~120-130 of 256 bits. This means an attacker cannot make "small" or "undetectable" changes — any modification completely invalidates the HMAC tag.

**Q: How does your system compare to TLS?**

A: Our system mirrors TLS architecture closely. TLS also uses RSA (or ECDHE) for key exchange in the handshake, then AES-CBC (or AES-GCM in TLS 1.3) for data transfer. Our five-message protocol corresponds to the TLS ClientHello/ServerHello/Certificate/ClientKeyExchange/Finished sequence. Our Encrypt-then-MAC pattern matches TLS 1.3's requirement. The differences are that TLS includes a full certificate chain (we use a single pre-trusted key), TLS 1.3 provides perfect forward secrecy via ECDHE (we use static RSA), and TLS supports session resumption (we do not).

---

*EE8257 Information Security — Group 29 — Faculty of Engineering, University of Ruhuna*