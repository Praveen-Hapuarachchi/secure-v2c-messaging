"""
=============================================================================
MODULE 4: Vehicle — TCP Client
=============================================================================
Project : Secure Vehicle-to-Controller Message Exchange
Group   : 29  |  Module : 4 of 4  |  Course : EE8257 Information Security

Run:  python vehicle.py VH-001              (default: 127.0.0.1:9999)
      python vehicle.py VH-002 127.0.0.1 9999

The Vehicle:
  1. Loads the pre-installed RSA_pub.der (factory pre-loaded key).
  2. Connects to the Controller via TCP.
  3. Executes the full 4-message RSA handshake:
       MSG 1 → MSG 2+2b → MSG 3 → MSG 4
  4. After handshake: sends AES-CBC+HMAC encrypted telemetry in a loop.
  5. Receives and verifies encrypted ACK from Controller after each message.
  6. Handles connection errors gracefully.

Syllabus: Lecture 8 — SSL/TLS client architecture:
"Client initiates handshake, verifies server certificate (here: RSA_pub),
then uses the negotiated session keys for data transfer."
=============================================================================
"""

import socket
import sys
import os
import json
import time
import random

# Add module directory to path
sys.path.insert(0, os.path.dirname(__file__))

from modules.rsa_engine  import (
    deserialize_public_key, HandshakeVehicle,
    key_fingerprint, PROTOCOL_VERSION
)
from modules.aes_engine  import VehicleEncryptor, EncryptedPacket
from modules.network     import (
    configure_client_socket, send_bytes_msg, recv_bytes_msg,
    send_json, send_close, TYPE_DATA,
)


# ── Colour helpers ─────────────────────────────────────────────────────────
R="\033[0m"; B="\033[1m"; G="\033[92m"; RED="\033[91m"
CY="\033[96m"; YL="\033[93m"; BL="\033[94m"; GR="\033[90m"; MA="\033[95m"

PUB_KEY_FILE = "RSA_pub.der"


class SecureVehicle:
    """
    Secure vehicle client.

    Executes the full RSA handshake with the controller, then sends
    encrypted telemetry messages in a loop using Modules 1, 2, and 3.

    This mirrors the client side of the TLS architecture described in
    Lecture 8: the vehicle pre-holds the server's public key (analogous
    to a root CA certificate pre-installed in a browser).
    """

    DEFAULT_HOST    = "127.0.0.1"
    DEFAULT_PORT    = 9999
    TELEMETRY_DELAY = 1.0   # seconds between messages (configurable)

    def __init__(self, vehicle_id: str, host: str = DEFAULT_HOST,
                 port: int = DEFAULT_PORT):
        self.vehicle_id = vehicle_id
        self.host       = host
        self.port       = port

        print(f"\n{B}{BL}{'═'*64}{R}")
        print(f"{B}{BL}  EE8257 Information Security — Group 29{R}")
        print(f"{B}{BL}  Vehicle Client: {vehicle_id}{R}")
        print(f"{B}{BL}{'═'*64}{R}\n")

        # ── Load pre-installed controller RSA public key ──────────────────
        if not os.path.exists(PUB_KEY_FILE):
            print(f"  {RED}✘  {PUB_KEY_FILE} not found.{R}")
            print(f"  {YL}  Run controller.py first to generate RSA_pub.der{R}\n")
            sys.exit(1)

        with open(PUB_KEY_FILE, "rb") as f:
            self._trusted_der = f.read()

        trusted_pub = deserialize_public_key(self._trusted_der)
        print(f"  {G}✔  RSA_pub.der loaded{R}")
        print(f"  {GR}  Fingerprint: {key_fingerprint(trusted_pub)}{R}\n")

    def connect_and_run(self, n_messages: int = 10):
        """
        Connect to the controller, perform handshake, send n_messages
        encrypted telemetry messages, then close gracefully.

        Parameters
        ----------
        n_messages : int — number of telemetry messages to send (0 = infinite)
        """
        print(f"  {GR}Connecting to {self.host}:{self.port}...{R}", flush=True)
        try:
            sock = configure_client_socket(self.host, self.port)
        except ConnectionRefusedError:
            print(f"  {RED}✘  Connection refused. Is the controller running?{R}\n")
            return
        except OSError as e:
            print(f"  {RED}✘  Connection error: {e}{R}\n")
            return

        print(f"  {G}✔  TCP connection established{R}\n")

        try:
            encryptor = self._perform_handshake(sock)
            if encryptor is None:
                return
            self._send_telemetry(sock, encryptor, n_messages)
        finally:
            send_close(sock)
            sock.close()
            print(f"\n  {YL}  Connection closed gracefully.{R}\n")

    # ── RSA Handshake ──────────────────────────────────────────────────────

    def _perform_handshake(self, sock: socket.socket
                           ) -> "VehicleEncryptor | None":
        """
        Execute the 4-message RSA handshake protocol.

        Returns VehicleEncryptor on success, None on failure.

        Protocol (Lecture 5 + Lecture 8 SSL/TLS):
          MSG 1  Vehicle → Controller : ClientHello (VehicleID + N_v)
          MSG 2  Controller → Vehicle : ServerHello (N_c + RSA_pub + signature)
          MSG 3  Vehicle → Controller : KeyPackage  (RSA_OAEP{K_s|K_m|N_v|N_c})
          MSG 4  Controller → Vehicle : HandshakeACK (AES{SESSION_READY|...})
        """
        print(f"  {B}{BL}── Phase 1–3: RSA Handshake{R}")
        handshake = HandshakeVehicle(
            self.vehicle_id,
            self._trusted_der,
            require_signature=True,
        )

        # ── MSG 1: ClientHello ─────────────────────────────────────────────
        msg1 = handshake.create_client_hello()
        send_bytes_msg(sock, msg1)
        m1d  = json.loads(msg1)
        print(f"  {CY}→  {self.vehicle_id:<10}{R}  {B}MSG 1{R}  "
              f"ClientHello  N_v={m1d['nonce_v'][:8]}...")

        # ── MSG 2: ServerHello + Signature ─────────────────────────────────
        try:
            msg2 = recv_bytes_msg(sock)
        except (ConnectionError, OSError) as e:
            print(f"  {RED}✘  Failed to receive MSG 2: {e}{R}")
            return None

        m2d = json.loads(msg2)
        sig_size = len(bytes.fromhex(m2d.get("signature", "")))
        print(f"  {YL}←  Controller  {R}  {B}MSG 2{R}  "
              f"ServerHello  N_c={m2d['nonce_c'][:8]}...  "
              f"sig={sig_size}B")

        # ── MSG 3: KeyPackage ──────────────────────────────────────────────
        try:
            msg3 = handshake.process_server_hello_and_create_key_package(msg2)
        except ValueError as e:
            print(f"  {RED}✘  Handshake failed at MSG 2 processing: {e}{R}")
            return None

        send_bytes_msg(sock, msg3)
        m3d = json.loads(msg3)
        print(f"  {CY}→  {self.vehicle_id:<10}{R}  {B}MSG 3{R}  "
              f"KeyPackage   RSA_ciphertext={len(bytes.fromhex(m3d['rsa_ciphertext']))}B")

        # ── MSG 4: HandshakeACK ────────────────────────────────────────────
        try:
            msg4 = recv_bytes_msg(sock)
        except (ConnectionError, OSError) as e:
            print(f"  {RED}✘  Failed to receive MSG 4: {e}{R}")
            return None

        try:
            session = handshake.process_handshake_ack(msg4)
        except ValueError as e:
            print(f"  {RED}✘  Handshake failed at MSG 4 verification: {e}{R}")
            return None

        fp = session.key_fingerprints()
        print(f"  {YL}←  Controller  {R}  {B}MSG 4{R}  "
              f"HandshakeACK SESSION_READY ✔")
        print(f"\n  {B}{G}✔  SESSION ESTABLISHED{R}")
        print(f"     {GR}Session ID: {session.session_id_display()}{R}")
        print(f"     {GR}K_s fp:     {fp['k_s_fp']}...{R}")
        print(f"     {GR}K_m fp:     {fp['k_m_fp']}...{R}")
        print(f"     {GR}Keys never transmitted in plaintext.{R}\n")

        return session.vehicle_encryptor

    # ── Encrypted Telemetry ────────────────────────────────────────────────

    def _send_telemetry(self, sock: socket.socket,
                        enc: VehicleEncryptor, n_messages: int):
        """
        Send n_messages encrypted telemetry messages to the controller.

        Each message is:
          1. JSON-encoded vehicle telemetry.
          2. AES-256-CBC encrypted with K_s (Module 2).
          3. HMAC-SHA256 authenticated with K_m (Module 1).
          4. Length-prefixed and sent over TCP (Module 4).

        The controller sends an ACK for each message.
        n_messages=0 means send indefinitely until interrupted.
        """
        print(f"  {B}{BL}── Phase 4: Secure Data Exchange{R}\n")

        i = 0
        while True:
            if n_messages > 0 and i >= n_messages:
                break
            i += 1

            payload = self._generate_telemetry(i)

            # Encrypt + authenticate (Modules 1 + 2)
            try:
                packet = enc.send(payload)
            except Exception as e:
                print(f"  {RED}✘  Encryption error: {e}{R}")
                break

            # Send over TCP (Module 4)
            try:
                send_bytes_msg(sock, packet.to_bytes())
            except OSError as e:
                print(f"  {RED}✘  Send failed: {e}{R}")
                break

            p_str = json.dumps(payload)
            if len(p_str) > 55:
                p_str = p_str[:55] + "..."
            print(f"  {CY}→  {self.vehicle_id:<10}{R}  "
                  f"seq={packet.sequence_no:<4}  "
                  f"ct={len(packet.ciphertext)}B  "
                  f"hmac={packet.hmac_tag.hex()[:10]}...  "
                  f"{GR}{p_str}{R}")

            # Receive ACK from controller
            try:
                ack_raw = recv_bytes_msg(sock)
                ack     = json.loads(ack_raw)
                if ack.get("status") == "OK":
                    print(f"  {YL}←  Controller  {R}  "
                          f"ACK seq={ack.get('seq')}  ✔")
                elif ack.get("type") == "ERROR":
                    print(f"  {RED}←  Controller  ERROR: {ack.get('reason')}{R}")
                    break
            except (ConnectionError, json.JSONDecodeError, OSError) as e:
                print(f"  {RED}✘  ACK receive error: {e}{R}")
                break

            print()
            time.sleep(self.TELEMETRY_DELAY)

    def _generate_telemetry(self, seq: int) -> dict:
        """Generate realistic vehicle telemetry payload."""
        # Simulate vehicle driving — speed fluctuates realistically
        base_speed = 60.0 + (seq % 5) * 8.3
        noise      = random.uniform(-2.5, 2.5)
        speed      = round(max(0.0, base_speed + noise), 1)

        # Kandy, Sri Lanka coordinates with slight variation
        lat  = round(7.2906 + random.uniform(-0.002, 0.002), 4)
        lon  = round(80.6337 + random.uniform(-0.002, 0.002), 4)
        zone = ["A1", "B2", "C3", "D4"][seq % 4]

        payload = {
            "vehicle_id"  : self.vehicle_id,
            "speed_kmh"   : speed,
            "latitude"    : lat,
            "longitude"   : lon,
            "fuel_pct"    : round(max(5.0, 80.0 - seq * 1.5), 1),
            "engine_temp" : round(85.0 + random.uniform(-3.0, 5.0), 1),
            "zone"        : zone,
            "msg_seq"     : seq,
        }

        # Occasionally inject alert messages
        if seq % 7 == 0:
            payload["alert"] = "BRAKE_APPLIED"
        if seq % 11 == 0:
            payload["alert"] = "LOW_FUEL_WARNING"

        return payload


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    vehicle_id = sys.argv[1] if len(sys.argv) > 1 else "VH-001"
    host       = sys.argv[2] if len(sys.argv) > 2 else SecureVehicle.DEFAULT_HOST
    port       = int(sys.argv[3]) if len(sys.argv) > 3 else SecureVehicle.DEFAULT_PORT
    n_msgs     = int(sys.argv[4]) if len(sys.argv) > 4 else 8

    veh = SecureVehicle(vehicle_id, host, port)
    veh.TELEMETRY_DELAY = 0.8   # slightly faster for demo

    try:
        veh.connect_and_run(n_messages=n_msgs)
    except KeyboardInterrupt:
        print(f"\n\n  {YL}Vehicle shutting down...{R}\n")