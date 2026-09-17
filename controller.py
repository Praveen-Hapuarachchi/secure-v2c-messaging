"""
=============================================================================
MODULE 4: Controller — TCP Server
=============================================================================
Project : Secure Vehicle-to-Controller Message Exchange
Group   : 29  |  Module : 4 of 4  |  Course : EE8257 Information Security

Run:  python controller.py              (default: 127.0.0.1:9999)
      python controller.py 0.0.0.0 9999 (listen on all interfaces)

The Controller:
  1. Generates RSA-2048 keypair at startup (once).
  2. Saves RSA_pub.der for vehicles to pre-load.
  3. Listens for incoming TCP connections.
  4. For each vehicle, spawns a thread to handle the full handshake:
       MSG 1 → MSG 2+2b → MSG 3 → MSG 4
  5. After handshake: receives AES-CBC+HMAC encrypted telemetry.
  6. Logs all received messages with verification status.
  7. Sends encrypted ACK back to the vehicle after each message.
  8. Handles multiple vehicles concurrently (one thread per vehicle).

Syllabus: Lecture 8 — SSL/TLS server architecture mirrors this design.
"Server holds private key; clients authenticate using the server
certificate." Our design uses a pre-distributed RSA_pub rather than
a full CA chain, appropriate for a closed vehicle fleet deployment.
=============================================================================
"""

import socket
import threading
import sys
import os
import json
import time
import logging
import struct

# Add module directory to path
sys.path.insert(0, os.path.dirname(__file__))

from modules.rsa_engine import (
    generate_rsa_keypair, serialize_public_key, HandshakeController,
    key_fingerprint, PROTOCOL_VERSION
)
from modules.aes_engine import ControllerDecryptor, EncryptedPacket
from modules.hmac_engine import generate_mac_key
from modules.network     import (
    configure_server_socket, send_bytes_msg, recv_bytes_msg,
    send_json, recv_json, send_error, send_close,
    TYPE_DATA, TYPE_CLOSE, TYPE_ERROR,
)


# =============================================================================
# Logging setup
# =============================================================================

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt= "%H:%M:%S",
)
log = logging.getLogger("Controller")

# ── Colour helpers (terminal output only) ─────────────────────────────────
R="\033[0m"; B="\033[1m"; G="\033[92m"; RED="\033[91m"
CY="\033[96m"; YL="\033[93m"; BL="\033[94m"; GR="\033[90m"


# =============================================================================
# Controller Server
# =============================================================================

class SecureController:
    """
    Multi-vehicle TCP controller server.

    One RSA keypair is generated at startup and shared by all sessions.
    Each incoming connection gets its own HandshakeController instance
    (one per session), ensuring K_s and K_m are completely independent
    across vehicles and sessions — as required by Lecture 4 (per-session
    key generation) and the Module 3 design document.

    Thread safety:
      - Each vehicle connection runs in its own daemon thread.
      - The _sessions dict is protected by _lock.
      - RSA private key is read-only after __init__; no lock needed.
    """

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 9999
    PUB_KEY_FILE = "RSA_pub.der"

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port

        # ── Generate RSA keypair (once at startup) ─────────────────────────
        print(f"\n{B}{BL}{'═'*64}{R}")
        print(f"{B}{BL}  EE8257 Information Security — Group 29{R}")
        print(f"{B}{BL}  Module 4: Controller TCP Server{R}")
        print(f"{B}{BL}{'═'*64}{R}\n")
        print(f"  {GR}Generating RSA-2048 keypair...{R}", flush=True)
        t0 = time.time()
        self._priv, self._pub = generate_rsa_keypair()
        self._pub_der = serialize_public_key(self._pub)
        print(f"  {G}✔  Keypair ready in {time.time()-t0:.2f}s{R}")
        print(f"  {GR}Fingerprint: {key_fingerprint(self._pub)}{R}")

        # Save RSA_pub.der for vehicles to load
        with open(self.PUB_KEY_FILE, "wb") as f:
            f.write(self._pub_der)
        print(f"  {G}✔  RSA_pub.der saved — distribute to vehicles{R}\n")

        # Session registry: { vehicle_id: { session info } }
        self._sessions: dict = {}
        self._lock            = threading.Lock()
        self._active          = True
        self._msg_count       = 0

    # ── Server lifecycle ───────────────────────────────────────────────────

    def start(self):
        """Bind the server socket and accept vehicle connections."""
        srv = configure_server_socket(self.host, self.port)
        print(f"  {B}{G}Controller listening on {self.host}:{self.port}{R}")
        print(f"  {GR}Waiting for vehicles...{R}\n")

        try:
            while self._active:
                try:
                    conn, addr = srv.accept()
                    conn.settimeout(30.0)
                    t = threading.Thread(
                        target=self._handle_vehicle,
                        args=(conn, addr),
                        daemon=True,
                    )
                    t.start()
                except OSError:
                    break
        finally:
            srv.close()

    # ── Per-vehicle handler (runs in its own thread) ───────────────────────

    def _handle_vehicle(self, conn: socket.socket, addr: tuple):
        """
        Handle one complete vehicle session:
          Phase 1: Receive MSG 1, send MSG 2 + signature.
          Phase 2: Receive MSG 3, decrypt K_s + K_m, send MSG 4.
          Phase 3: Receive MSG 5+ encrypted telemetry, send ACK.
        """
        peer = f"{addr[0]}:{addr[1]}"
        vehicle_id = "UNKNOWN"

        try:
            # ── PHASE 1: RSA Handshake ─────────────────────────────────────
            self._log_phase(peer, "1", "RSA Handshake starting")

            # MSG 1: ClientHello
            msg1_bytes = recv_bytes_msg(conn)
            m1_dict    = json.loads(msg1_bytes)
            vehicle_id = m1_dict.get("vehicle_id", "UNKNOWN")
            self._log_rx(vehicle_id, "MSG 1", "ClientHello",
                         f"N_v={m1_dict.get('nonce_v','')[:8]}...")

            # Create per-session handshake handler
            handshake = HandshakeController(self._priv, vehicle_id)

            # MSG 2 + 2b: ServerHello + Signature
            msg2_bytes = handshake.process_client_hello(msg1_bytes)
            send_bytes_msg(conn, msg2_bytes)
            self._log_tx(vehicle_id, "MSG 2", "ServerHello + RSA_pub + Signature")

            # MSG 3: KeyPackage (RSA-encrypted K_s, K_m)
            msg3_bytes = recv_bytes_msg(conn)
            self._log_rx(vehicle_id, "MSG 3", "KeyPackage",
                         f"{len(msg3_bytes)}B RSA-OAEP ciphertext")

            # MSG 4: HandshakeACK (AES-CBC proof of K_s recovery)
            msg4_bytes = handshake.process_key_package(msg3_bytes)
            send_bytes_msg(conn, msg4_bytes)
            self._log_tx(vehicle_id, "MSG 4", "HandshakeACK (AES-encrypted SESSION_READY)")

            # ── Session established ────────────────────────────────────────
            session      = handshake.get_session()
            decryptor    = session.controller_decryptor
            fp           = session.key_fingerprints()
            session_disp = session.session_id_display()

            self._log_session_up(vehicle_id, session_disp, fp)

            with self._lock:
                self._sessions[vehicle_id] = {
                    "session_id"  : session.session_id.hex(),
                    "established" : time.time(),
                    "msg_count"   : 0,
                    "k_s_fp"      : fp["k_s_fp"],
                    "k_m_fp"      : fp["k_m_fp"],
                }

            # ── PHASE 3: Secure data exchange ─────────────────────────────
            self._log_phase(peer, "3", "Secure data exchange active")
            self._receive_loop(conn, vehicle_id, decryptor)

        except ConnectionError as e:
            self._log_warn(vehicle_id, f"Connection closed: {e}")
        except ValueError as e:
            self._log_err(vehicle_id, f"Security/protocol error: {e}")
            send_error(conn, str(e))
        except Exception as e:
            self._log_err(vehicle_id, f"Unexpected error: {e}")
        finally:
            conn.close()
            with self._lock:
                self._sessions.pop(vehicle_id, None)
            self._log_warn(vehicle_id, "Session closed")

    def _receive_loop(self, conn: socket.socket, vid: str,
                      decryptor: ControllerDecryptor):
        """
        Continuously receive encrypted MSG 5+ packets from a vehicle.

        Processing order (Encrypt-then-MAC, as designed in Module 2):
          1. Receive raw framed bytes.
          2. Deserialise EncryptedPacket.
          3. Call decryptor.receive() → HMAC verify, replay check, decrypt.
          4. Log result.
          5. Send encrypted ACK back to vehicle.

        Exits cleanly on:
          - CLOSE message from vehicle
          - Connection drop
          - HMAC/replay failure (security event)
        """
        seq_expected = 1
        while True:
            try:
                raw = recv_bytes_msg(conn)
            except ConnectionError:
                break

            # Check for control messages (JSON)
            try:
                ctrl = json.loads(raw)
                if ctrl.get("type") == "CLOSE":
                    self._log_warn(vid, "Vehicle sent CLOSE — session ending")
                    break
                if ctrl.get("type") == "ERROR":
                    self._log_err(vid, f"Vehicle error: {ctrl.get('reason')}")
                    break
                if ctrl.get("type") == "DATA":
                    # DATA wrapper — extract the inner EncryptedPacket bytes
                    raw = bytes.fromhex(ctrl["packet"])
            except (json.JSONDecodeError, KeyError):
                pass   # raw is an EncryptedPacket directly

            # Deserialise and process the EncryptedPacket
            try:
                packet = EncryptedPacket.from_bytes(raw)
                result = decryptor.receive(packet)
            except Exception as e:
                self._log_err(vid, f"Packet processing error: {e}")
                send_error(conn, "Packet processing failed")
                break

            self._msg_count += 1
            with self._lock:
                if vid in self._sessions:
                    self._sessions[vid]["msg_count"] += 1

            if result["status"] == "OK":
                payload = result["payload"]
                self._log_data_ok(vid, packet.sequence_no,
                                  len(packet.ciphertext), payload)
                # Send ACK back
                try:
                    ack = json.dumps({
                        "type"    : "ACK",
                        "seq"     : packet.sequence_no,
                        "status"  : "OK",
                        "ts"      : time.time(),
                    }).encode()
                    send_bytes_msg(conn, ack)
                except OSError:
                    break
            else:
                self._log_err(vid, f"[seq={packet.sequence_no}] "
                              f"{result['status']}: {result['reason'][:60]}")
                send_error(conn, result["reason"])
                if result["status"] in ("HMAC_FAIL", "REPLAY"):
                    break   # security event — terminate session

    # ── Display helpers ───────────────────────────────────────────────────

    def _log_phase(self, peer, n, desc):
        print(f"\n  {B}{BL}── Phase {n}: {desc} [{peer}]{R}")

    def _log_rx(self, vid, msg, mtype, detail=""):
        d = f"  {GR}({detail}){R}" if detail else ""
        print(f"  {CY}←  {vid:<10}{R}  {B}{msg}{R}  {mtype}{d}")

    def _log_tx(self, vid, msg, mtype):
        print(f"  {YL}→  {vid:<10}{R}  {B}{msg}{R}  {mtype}")

    def _log_session_up(self, vid, sid, fp):
        print(f"\n  {B}{G}✔  SESSION ESTABLISHED{R}")
        print(f"     {GR}Vehicle:    {vid}{R}")
        print(f"     {GR}Session ID: {sid}{R}")
        print(f"     {GR}K_s fp:     {fp['k_s_fp']}...{R}")
        print(f"     {GR}K_m fp:     {fp['k_m_fp']}...{R}\n")

    def _log_data_ok(self, vid, seq, ct_len, payload):
        p_str = json.dumps(payload)
        if len(p_str) > 72:
            p_str = p_str[:72] + "..."
        print(f"  {G}✔{R}  {vid:<10}  seq={seq:<4}  ct={ct_len}B  "
              f"{GR}payload={R}{p_str}")

    def _log_warn(self, vid, msg):
        print(f"  {YL}⚠  {vid:<10}  {msg}{R}")

    def _log_err(self, vid, msg):
        print(f"  {RED}✘  {vid:<10}  {msg}{R}")

    def status(self) -> dict:
        """Return current server status for testing/monitoring."""
        with self._lock:
            return {
                "active_sessions": len(self._sessions),
                "total_messages" : self._msg_count,
                "sessions"       : dict(self._sessions),
            }


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else SecureController.DEFAULT_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else SecureController.DEFAULT_PORT

    ctrl = SecureController(host, port)
    try:
        ctrl.start()
    except KeyboardInterrupt:
        print(f"\n\n  {YL}Controller shutting down...{R}\n")