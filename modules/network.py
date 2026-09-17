"""
=============================================================================
MODULE 4: Network Wire Protocol — TCP Message Framing
=============================================================================
Project : Secure Vehicle-to-Controller Message Exchange
Group   : 29  |  Module : 4 of 4  |  Course : EE8257 Information Security

WHY A FRAMING LAYER IS NEEDED
──────────────────────────────
TCP is a STREAM protocol, not a MESSAGE protocol. It guarantees that bytes
arrive in order and without loss, but it makes NO guarantee about where
message boundaries fall. A 300-byte message sent by the vehicle may arrive
at the controller as:
  - One chunk of 300 bytes  (ideal)
  - Two chunks: 200 + 100 bytes
  - Three chunks: 100 + 150 + 50 bytes
  - Any other split

This is called TCP segmentation (or "TCP nagling"). Without a framing
protocol, the receiver cannot tell where one message ends and the next
begins. This module implements LENGTH-PREFIX FRAMING:

  Wire format: [4-byte big-endian length][payload bytes]

  Sender: prepend struct.pack('>I', len(payload)) before sending
  Receiver: read exactly 4 bytes → parse length N → read exactly N bytes

This produces a clean message-oriented layer on top of TCP, identical
to the framing used in TLS record layer (Lecture 8).

MESSAGE TYPES
──────────────
All messages are JSON-encoded bytes with a "type" field for routing:
  CLIENT_HELLO    — MSG 1  (plaintext, from vehicle)
  SERVER_HELLO    — MSG 2  (plaintext, from controller)
  KEY_PACKAGE     — MSG 3  (RSA-encrypted session keys)
  HANDSHAKE_ACK   — MSG 4  (AES-encrypted session confirmation)
  DATA            — MSG 5+ (AES-CBC + HMAC encrypted telemetry)
  ERROR           — Error  (plaintext error notification)
  CLOSE           — Graceful shutdown
=============================================================================
"""

import socket
import struct
import json
import time
from typing import Optional


# ── Constants ──────────────────────────────────────────────────────────────
HEADER_SIZE   = 4           # bytes — big-endian uint32 length prefix
MAX_MSG_BYTES = 64 * 1024   # 64 KB hard limit per message
RECV_TIMEOUT  = 30.0        # seconds — socket receive timeout
SEND_TIMEOUT  = 10.0        # seconds — socket send timeout

# Message type identifiers (match rsa_engine.py type strings)
TYPE_CLIENT_HELLO   = "CLIENT_HELLO"
TYPE_SERVER_HELLO   = "SERVER_HELLO"
TYPE_KEY_PACKAGE    = "KEY_PACKAGE"
TYPE_HANDSHAKE_ACK  = "HANDSHAKE_ACK"
TYPE_DATA           = "DATA"
TYPE_ERROR          = "ERROR"
TYPE_CLOSE          = "CLOSE"


# =============================================================================
# SECTION 1 — Low-level send / receive with length-prefix framing
# =============================================================================

def send_message(sock: socket.socket, payload: bytes) -> None:
    """
    Send a framed message over a TCP socket.

    Wire format: [4-byte big-endian length N][N bytes of payload]

    Uses sendall() which loops internally until all bytes are delivered
    to the kernel send buffer. This is the correct way to send over TCP
    — a naive send() call may only deliver part of the data if the
    kernel buffer is temporarily full.

    Parameters
    ----------
    sock    : socket.socket — connected TCP socket
    payload : bytes         — message bytes to send

    Raises
    ------
    ValueError  : if payload exceeds MAX_MSG_BYTES
    OSError     : on network failure
    """
    if len(payload) > MAX_MSG_BYTES:
        raise ValueError(
            f"Message too large: {len(payload)} bytes > {MAX_MSG_BYTES} byte limit."
        )
    # Pack a 4-byte big-endian unsigned integer length header
    header = struct.pack('>I', len(payload))
    sock.sendall(header + payload)


def recv_message(sock: socket.socket) -> bytes:
    """
    Receive a framed message from a TCP socket.

    Reads exactly 4 bytes for the length header, then reads exactly
    that many bytes for the payload. Handles TCP segmentation correctly
    by looping until the required byte count is accumulated.

    This is a BLOCKING call. The socket should have a timeout set
    (via sock.settimeout()) to prevent indefinite blocking on a
    slow or adversarial peer.

    Returns
    -------
    bytes : complete message payload

    Raises
    ------
    ConnectionError : if the peer closes the connection mid-receive
    ValueError      : if the declared length exceeds MAX_MSG_BYTES
    OSError         : on network failure
    """
    # ── Read exactly 4-byte length header ─────────────────────────────
    header = _recv_exactly(sock, HEADER_SIZE)
    length = struct.unpack('>I', header)[0]

    if length == 0:
        return b""
    if length > MAX_MSG_BYTES:
        raise ValueError(
            f"Peer declared message length {length} bytes > "
            f"{MAX_MSG_BYTES} byte limit. Possible protocol error."
        )

    # ── Read exactly `length` payload bytes ───────────────────────────
    return _recv_exactly(sock, length)


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """
    Read exactly n bytes from the socket, accumulating across segments.

    TCP may deliver data in arbitrary-sized chunks. This function
    loops until the full requested byte count is available.

    Raises ConnectionError if the peer closes the connection before
    delivering the required bytes (i.e., recv() returns b"").
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(
                f"Connection closed by peer after {len(buf)}/{n} bytes."
            )
        buf.extend(chunk)
    return bytes(buf)


# =============================================================================
# SECTION 2 — JSON message helpers
# =============================================================================

def send_json(sock: socket.socket, obj: dict) -> None:
    """Serialise a dict to JSON and send as a framed message."""
    send_message(sock, json.dumps(obj, sort_keys=True).encode("utf-8"))


def recv_json(sock: socket.socket) -> dict:
    """Receive a framed message and deserialise as JSON."""
    raw = recv_message(sock)
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Received non-JSON message: {exc}") from exc


# =============================================================================
# SECTION 3 — Typed message send helpers (for handshake messages)
# =============================================================================

def send_bytes_msg(sock: socket.socket, payload: bytes) -> None:
    """
    Send raw bytes as a length-prefixed message.
    Used for handshake messages that are already serialised by rsa_engine.
    """
    send_message(sock, payload)


def recv_bytes_msg(sock: socket.socket) -> bytes:
    """Receive a length-prefixed message as raw bytes."""
    return recv_message(sock)


# =============================================================================
# SECTION 4 — Error and close message helpers
# =============================================================================

def send_error(sock: socket.socket, reason: str) -> None:
    """Send a plaintext ERROR message to the peer."""
    try:
        send_json(sock, {"type": TYPE_ERROR, "reason": reason, "ts": time.time()})
    except OSError:
        pass    # best-effort; don't raise if connection already broken


def send_close(sock: socket.socket) -> None:
    """Send a graceful CLOSE notification."""
    try:
        send_json(sock, {"type": TYPE_CLOSE, "ts": time.time()})
    except OSError:
        pass


# =============================================================================
# SECTION 5 — Socket configuration helpers
# =============================================================================

def configure_server_socket(host: str, port: int) -> socket.socket:
    """
    Create, configure, and bind a TCP server socket.

    SO_REUSEADDR allows reuse of the port immediately after a previous
    server process exits. Without this, the OS holds the port in
    TIME_WAIT state for ~60 seconds after a crash.

    Parameters
    ----------
    host : str — IP address to bind (e.g. "127.0.0.1" or "0.0.0.0")
    port : int — TCP port number

    Returns
    -------
    socket.socket : bound, listening server socket
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(10)   # backlog: up to 10 pending connections
    return srv


def configure_client_socket(host: str, port: int,
                            timeout: float = RECV_TIMEOUT) -> socket.socket:
    """
    Create and connect a TCP client socket.

    Parameters
    ----------
    host    : str   — Server IP or hostname
    port    : int   — Server TCP port
    timeout : float — Socket timeout in seconds

    Returns
    -------
    socket.socket : connected client socket
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock