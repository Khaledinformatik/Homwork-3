#!/usr/bin/env python3
"""
Simplified OPAQUE
- Registration: server stores OPRF key k and server static keypair (b,B)
- OPRF: client blinds H(pw), server evaluates k * blinded, client unblinds
- AKE: 3DH as in lecture (client/server functions)
- Key Confirmation: derive (Kc,Ks) from SK using HKDF and exchange HMACs

"""

from typing import Tuple, Optional
import hashlib
import hmac
from secrets import token_bytes, randbelow

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from ecdsa import ellipticcurve, curves
from ecdsa.numbertheory import square_root_mod_prime, inverse_mod

# -------------------------
# Curve setup (P-256)
# -------------------------
P256 = curves.NIST256p
G = P256.generator
n = P256.order
_curve = P256.curve
_a = _curve.a()
_b = _curve.b()
_p = _curve.p()
HASH = hashlib.sha256

# -------------------------
# Helpers
# -------------------------
def Create_P256_point(x: int, y: int) -> ellipticcurve.Point:
    return ellipticcurve.Point(_curve, x, y)

def GetY(x: int):
    rhs = (pow(x, 3, _p) + _a * x + _b) % _p
    try:
        y0 = square_root_mod_prime(rhs, _p)
        return (y0, (_p - y0) % _p)
    except Exception:
        return None

def printable_P256_point(P: ellipticcurve.Point) -> str:
    if P == ellipticcurve.INFINITY:
        return "(INFINITY)"
    return f"({P.x()}, {P.y()})"

def random_scalar() -> int:
    """Secure random scalar in [1, n-1]."""
    return randbelow(n - 1) + 1

def inv_scalar(x: int) -> int:
    return inverse_mod(x, n)

def point_to_bytes(P: ellipticcurve.Point) -> bytes:
    if P == ellipticcurve.INFINITY:
        return b'\x00' * 64
    return P.x().to_bytes(32, "big") + P.y().to_bytes(32, "big")

def bytes_to_point(data: bytes) -> Optional[ellipticcurve.Point]:
    if len(data) != 64:
        return None
    x = int.from_bytes(data[:32], "big")
    y = int.from_bytes(data[32:], "big")
    try:
        return Create_P256_point(x, y)
    except Exception:
        return None

# -------------------------
#  hash_to_curve
# -------------------------
def hash_to_curve(msg_bytes: bytes) -> ellipticcurve.Point:
    """
    Lecture-style mapping (illustrative, not uniform RFC):
    - h = SHA256(msg)
    - derive msb flags from first byte
    - build P_left (x = p - h_int, decrement) and P_right (x = h_int, increment)
    - choose y for each using msb flags, return P_left + P_right
    """
    if not isinstance(msg_bytes, (bytes, bytearray)):
        raise ValueError("msg must be bytes")

    h = HASH(msg_bytes).digest()
    first_byte = h[0]
    msb_left = (first_byte & 0x80) != 0
    msb_right = not msb_left

    h_int = int.from_bytes(h, "big") % _p

    # P_left
    x_left = (_p - h_int) % _p
    while True:
        y_pair = GetY(x_left)
        if y_pair is not None:
            break
        x_left = (x_left - 1) % _p
    y_left = y_pair[0] if msb_left else y_pair[1]
    P_left = Create_P256_point(x_left, y_left)

    # P_right
    x_right = h_int
    while True:
        y_pair = GetY(x_right)
        if y_pair is not None:
            break
        x_right = (x_right + 1) % _p
    y_right = y_pair[0] if msb_right else y_pair[1]
    P_right = Create_P256_point(x_right, y_right)

    return P_left + P_right

# -------------------------
# HKDF / HMAC helpers
# -------------------------
def derive_Kc_Ks(SK: bytes, salt: Optional[bytes] = None, transcript_info: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    if not isinstance(SK, (bytes, bytearray)) or len(SK) == 0:
        raise ValueError("SK must be non-empty bytes")
    info = b"Key Confirmation"
    if transcript_info:
        info += b"|" + transcript_info
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=info, backend=default_backend())
    okm = hkdf.derive(SK)
    return okm[:32], okm[32:]

def HMAC_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

# -------------------------
# 3DH helpers
# -------------------------
def HKDF_concat_points(*points: ellipticcurve.Point) -> bytes:
    data = b"".join(point_to_bytes(P) for P in points)
    return hashlib.sha256(data).digest()

def KClient_3DH(a: int, x: int, B: ellipticcurve.Point, Y: ellipticcurve.Point) -> bytes:
    return HKDF_concat_points(x * B, x * Y, a * Y)

def KServer_3DH(b: int, y: int, A: ellipticcurve.Point, X: ellipticcurve.Point) -> bytes:
    return HKDF_concat_points(b * X, y * X, y * A)

# -------------------------
# OPRF (DH-OPRF) helpers
# -------------------------
def OPRF_client_start(pw: bytes):
    P = hash_to_curve(pw)
    r = random_scalar()
    blinded = r * P
    return r, blinded

def OPRF_server_eval(blinded_P: ellipticcurve.Point, k: int) -> ellipticcurve.Point:
    return k * blinded_P

def OPRF_client_finish(r: int, eval_P: ellipticcurve.Point) -> ellipticcurve.Point:
    r_inv = inv_scalar(r)
    return r_inv * eval_P

# -------------------------
# AEAD envelope (AES-GCM)
# -------------------------
def aead_encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
    aesgcm = AESGCM(key)
    nonce = token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct

def aead_decrypt(key: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
    aesgcm = AESGCM(key)
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    return aesgcm.decrypt(nonce, ct, aad)

# -------------------------
# Server / Client classes
# -------------------------
class Server:
    def __init__(self):
        self.db = {}  # username -> record
        # Note: in production protect k (HSM)

    def register(self, username: str, pw_bytes: bytes):
        if not isinstance(username, str) or not isinstance(pw_bytes, (bytes, bytearray)):
            raise ValueError("invalid inputs")
        k = random_scalar()          # OPRF secret
        b = random_scalar()          # server static secret
        B = b * G
        self.db[username] = {"k": k, "b": b, "B": B, "envelope": None}

    def register_oprf_eval(self, username: str, blinded_P: ellipticcurve.Point) -> ellipticcurve.Point:
        rec = self.db.get(username)
        if rec is None:
            raise ValueError("unknown user")
        return rec["k"] * blinded_P

    def store_envelope(self, username: str, envelope: bytes):
        rec = self.db.get(username)
        if rec is None:
            raise ValueError("unknown user")
        rec["envelope"] = envelope

    def login_oprf_eval(self, username: str, blinded_P: ellipticcurve.Point) -> ellipticcurve.Point:
        rec = self.db.get(username)
        if rec is None:
            raise ValueError("unknown user")
        return rec["k"] * blinded_P

    def ake_3dh_server(self, username: str, X: ellipticcurve.Point, A: ellipticcurve.Point, K_oprf: bytes,
                       salt: Optional[bytes] = None, transcript_info: Optional[bytes] = None):
        rec = self.db.get(username)
        if rec is None:
            raise ValueError("unknown user")
        b = rec["b"]
        B = rec["B"]
        y = random_scalar()
        Y = y * G
        SK_3dh = KServer_3DH(b, y, A, X)
        SK = hashlib.sha256(SK_3dh + K_oprf).digest()
        return Y, SK

class Client:
    def __init__(self, username: str, pw_bytes: bytes):
        if not isinstance(username, str) or not isinstance(pw_bytes, (bytes, bytearray)):
            raise ValueError("invalid inputs")
        self.username = username
        self.pw = pw_bytes
        # static keypair will be created at registration and stored in envelope
        self.static_sk = None
        self.static_pk = None

    def register_interactive(self, server: Server):
        # server prepares record
        server.register(self.username, self.pw)

        # OPRF: blind/eval/unblind
        r, blinded = OPRF_client_start(self.pw)
        eval_P = server.register_oprf_eval(self.username, blinded)
        oprf_point = OPRF_client_finish(r, eval_P)
        K_oprf = hashlib.sha256(oprf_point.x().to_bytes(32, "big")).digest()

        # create client static keypair (used in AKE) and store in envelope
        sk_c = random_scalar()
        lpkc = sk_c * G
        sk_c_bytes = sk_c.to_bytes(32, "big")
        lpkc_bytes = point_to_bytes(lpkc)
        plaintext = sk_c_bytes + lpkc_bytes
        aad = self.username.encode()
        envelope = aead_encrypt(K_oprf, plaintext, aad=aad)
        server.store_envelope(self.username, envelope)

        # set client's static keypair locally (ensure consistency)
        self.static_sk = sk_c
        self.static_pk = lpkc

    def login(self, server: Server, salt: Optional[bytes] = None, transcript_info: Optional[bytes] = None) -> bool:
        # OPRF
        r, blinded = OPRF_client_start(self.pw)
        eval_P = server.login_oprf_eval(self.username, blinded)
        oprf_point = OPRF_client_finish(r, eval_P)
        K_oprf = hashlib.sha256(oprf_point.x().to_bytes(32, "big")).digest()

        # retrieve and decrypt envelope
        rec = server.db.get(self.username)
        if rec is None or rec.get("envelope") is None:
            raise ValueError("no envelope stored")
        envelope = rec["envelope"]
        aad = self.username.encode()
        try:
            plaintext = aead_decrypt(K_oprf, envelope, aad=aad)
        except Exception:
            return False  # wrong password or tampering

        sk_c = int.from_bytes(plaintext[:32], "big")
        lpkc = bytes_to_point(plaintext[32:96])
        if lpkc is None:
            return False

        # ensure client's static keypair matches envelope
        self.static_sk = sk_c
        self.static_pk = lpkc

        # AKE 3DH
        x = random_scalar()
        X = x * G
        Y, SK_server = server.ake_3dh_server(self.username, X, self.static_pk, K_oprf, salt=salt, transcript_info=transcript_info)
        SK_client_3dh = KClient_3DH(self.static_sk, x, server.db[self.username]["B"], Y)
        SK_client = hashlib.sha256(SK_client_3dh + K_oprf).digest()

        # Key Confirmation (derive keys bound to transcript)
        Kc_client, Ks_client = derive_Kc_Ks(SK_client, salt=salt, transcript_info=transcript_info)
        mac_c = HMAC_sha256(Kc_client, b"Client KC" + (transcript_info or b""))

        # Server verifies client MAC
        Kc_server, Ks_server = derive_Kc_Ks(SK_server, salt=salt, transcript_info=transcript_info)
        mac_c_check = HMAC_sha256(Kc_server, b"Client KC" + (transcript_info or b""))
        if not hmac.compare_digest(mac_c_check, mac_c):
            return False

        # Server computes its MAC and client verifies
        mac_s = HMAC_sha256(Ks_server, b"Server KC" + (transcript_info or b""))
        mac_s_check = HMAC_sha256(Ks_client, b"Server KC" + (transcript_info or b""))
        return hmac.compare_digest(mac_s_check, mac_s)

# -------------------------
# Demo run / quick tests
# -------------------------
if __name__ == "__main__":
    server = Server()
    client = Client("user1", b"password123")

    # Registration (interactive)
    client.register_interactive(server)

    # session binding
    session_salt = token_bytes(16)
    transcript = hashlib.sha256(b"client: X || server: Y || other").digest()

    ok = client.login(server, salt=session_salt, transcript_info=transcript)
    print("Authentication:", "Success" if ok else "Fail")
