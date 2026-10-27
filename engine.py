"""
PassGen Core Backend Logic
Provides encryption, decryption, user authentication, password strength analysis,
and per-user vault management.

Supports 5 Encryption Methods from PassGen v2:
1. Caesar Shift ('c')
2. ROT13 ('r')
3. Vigenère Cipher ('v')
4. XOR Stream Cipher ('x')
5. AES-128 CBC ('a')
"""

import base64
import csv
import hashlib
import json
import os
import re
import secrets
import string
from typing import Dict, List, Any, Optional, Tuple

VAULT_FILE = os.path.join(os.path.dirname(__file__), "vault.json")
USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")

CIPHER_NAMES = {
    'c': 'Caesar Shift',
    'r': 'ROT13',
    'v': 'Vigenère',
    'x': 'XOR Stream',
    'a': 'AES-128'
}


# --- User Authentication System ---

def _hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hashes a master password with salt using SHA-256."""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return hashed, salt


def get_users() -> Dict[str, Any]:
    """Reads users from users.json."""
    if not os.path.exists(USERS_FILE):
        _init_users_file()
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return {"users": {}}
            return data
    except Exception:
        return {"users": {}}


def _init_users_file():
    """Initializes users file with demo user."""
    demo_hash, demo_salt = _hash_password("demo123", "demosalt12345678")
    initial_data = {
        "users": {
            "demo": {
                "username": "demo",
                "hash": demo_hash,
                "salt": demo_salt,
                "is_demo": True
            }
        }
    }
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(initial_data, f, indent=4)


def register_user(username: str, password: str) -> Dict[str, Any]:
    """Registers a new user account."""
    clean_username = username.strip()
    if not clean_username:
        return {"success": False, "message": "Username cannot be empty."}
    if len(clean_username) < 3:
        return {"success": False, "message": "Username must be at least 3 characters."}
    if not password or len(password) < 4:
        return {"success": False, "message": "Password must be at least 4 characters."}

    users_data = get_users()
    users = users_data.setdefault("users", {})

    if clean_username.lower() in [u.lower() for u in users.keys()]:
        return {"success": False, "message": "Username already exists. Please choose another."}

    pwd_hash, salt = _hash_password(password)
    users[clean_username] = {
        "username": clean_username,
        "hash": pwd_hash,
        "salt": salt,
        "is_demo": False
    }

    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users_data, f, indent=4)

    return {"success": True, "message": "Account created successfully!", "username": clean_username}


def authenticate_user(username: str, password: str) -> Dict[str, Any]:
    """Verifies user credentials."""
    clean_username = username.strip()
    users_data = get_users()
    users = users_data.get("users", {})

    target_user = None
    for uname, udata in users.items():
        if uname.lower() == clean_username.lower():
            target_user = udata
            break

    if not target_user:
        return {"success": False, "message": "User not found."}

    expected_hash = target_user.get("hash")
    salt = target_user.get("salt")
    calc_hash, _ = _hash_password(password, salt)

    if calc_hash == expected_hash:
        return {
            "success": True,
            "message": "Authentication successful.",
            "username": target_user["username"],
            "is_demo": target_user.get("is_demo", False)
        }
    return {"success": False, "message": "Invalid password."}


# --- Vault Per-User Management ---

def get_raw_vault() -> Dict[str, Any]:
    """Reads raw vault file."""
    if not os.path.exists(VAULT_FILE):
        return {"vault": []}
    try:
        with open(VAULT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return {"vault": []}
            if "vault" not in data or not isinstance(data["vault"], list):
                data["vault"] = []
            return data
    except Exception:
        return {"vault": []}


def save_raw_vault(data: Dict[str, Any]):
    """Writes raw vault file."""
    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def get_user_vault(username: str) -> List[Dict[str, Any]]:
    """Retrieves all saved password records for a specific user."""
    raw = get_raw_vault()
    records = raw.get("vault", [])
    user_lower = username.strip().lower()

    user_records = []
    for r in records:
        owner = r.get("owner", "demo").lower()
        if owner == user_lower or (user_lower == "demo" and not r.get("owner")):
            user_records.append(r)
    return user_records


def delete_user_password(record_id: int, username: str) -> bool:
    """Deletes a password record if owned by the user."""
    raw = get_raw_vault()
    all_records = raw.get("vault", [])
    user_lower = username.strip().lower()

    new_records = []
    deleted = False
    for r in all_records:
        if r.get("id") == record_id:
            owner = r.get("owner", "demo").lower()
            if owner == user_lower or user_lower == "demo":
                deleted = True
                continue
        new_records.append(r)

    if deleted:
        raw["vault"] = new_records
        save_raw_vault(raw)
        return True
    return False


# --- Encryption Ciphers Implementation ---

# 1. Caesar Shift & ROT13
def caesar_encrypt(plaintext: str, shift: int = 3, rot13: bool = False) -> Dict[str, Any]:
    """Encodes plaintext using Caesar shift or ROT13."""
    actual_shift = 13 if rot13 else int(shift)
    parts = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            parts.append(chr((ord(ch) - base + actual_shift) % 26 + base))
        else:
            parts.append(ch)
    cipher_text = "".join(parts)
    c_type = "r" if rot13 else "c"
    return {
        "cipher_text": cipher_text,
        "cipher": c_type,
        "key": actual_shift
    }


def dcode_caesar(ciphertext: dict) -> str:
    if not isinstance(ciphertext, dict):
        raise TypeError('ciphertext must be a dict')
    key_raw = ciphertext.get('key', None)
    if key_raw is None:
        if ciphertext.get('cipher') == 'r':
            shift = 13
        else:
            shift = 3
    else:
        try:
            shift = int(key_raw)
        except (TypeError, ValueError):
            shift = 3
    ct = ciphertext.get('cipher_text', '')
    parts = []
    for ch in ct:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            parts.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            parts.append(ch)
    return ''.join(parts)


# 2. Vigenère Cipher
def vigenere_encrypt(plaintext: str, key: str = "KEY") -> Dict[str, Any]:
    """Encodes plaintext using Vigenère cipher."""
    clean_key = "".join(ch for ch in key if ch.isalpha()).upper()
    if not clean_key:
        clean_key = "KEY"
    parts = []
    k_idx = 0
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            p_val = ord(ch) - base
            k_val = ord(clean_key[k_idx % len(clean_key)]) - ord('A')
            parts.append(chr((p_val + k_val) % 26 + base))
            k_idx += 1
        else:
            parts.append(ch)
    cipher_text = "".join(parts)
    return {
        "cipher_text": cipher_text,
        "cipher": "v",
        "key": clean_key
    }


def dcode_vig(ciphertext: dict) -> str:
    if not isinstance(ciphertext, dict):
        raise TypeError('ciphertext must be a dict')
    key = str(ciphertext.get('key', '')).upper()
    ct = ciphertext.get('cipher_text', '')
    parts = []
    k_idx = 0
    if not key:
        return ct
    for ch in ct:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            c_val = ord(ch) - base
            k_val = ord(key[k_idx % len(key)]) - ord('A')
            parts.append(chr((c_val - k_val) % 26 + base))
            k_idx += 1
        else:
            parts.append(ch)
    return ''.join(parts)


# 3. XOR Stream Cipher
def xor_stream_encrypt(plaintext: str, key: str) -> str:
    """XOR stream encryption returning hex-encoded ciphertext."""
    if not key:
        key = "PASSGEN_XOR_KEY"
    key_bytes = key.encode('utf-8')
    data = plaintext.encode('utf-8')
    stream = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return stream.hex()


def xor_stream_decrypt(ciphertext_hex: str, key: str) -> str:
    """XOR stream decryption from hex-encoded ciphertext."""
    if not key:
        key = "PASSGEN_XOR_KEY"
    try:
        raw = bytes.fromhex(ciphertext_hex)
    except (ValueError, TypeError):
        return ciphertext_hex
    key_bytes = key.encode('utf-8')
    plain = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
    return plain.decode('utf-8', errors='replace')


# 4. AES-128 CBC with PKCS7
def generate_random_aes_key(length: int = 16) -> str:
    """Generates a secure 16-character alphanumeric AES key."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


# Pure Python AES-128 engine
_S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]
_INV_S_BOX = [0] * 256
for _i, _v in enumerate(_S_BOX):
    _INV_S_BOX[_v] = _i
_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def _sub_word(w): return [_S_BOX[b] for b in w]
def _rot_word(w): return w[1:] + w[:1]
def _key_expansion(key_bytes):
    w = [list(key_bytes[4*i:4*i+4]) for i in range(4)]
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= _RCON[i // 4]
        w.append([b1 ^ b2 for b1, b2 in zip(w[i - 4], temp)])
    round_keys = []
    for r in range(11):
        rk = []
        for c in range(4):
            rk.extend(w[r * 4 + c])
        round_keys.append(rk)
    return round_keys

def _xtime(a): return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)
def _mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    return [
        a[0] ^ t ^ _xtime(a[0] ^ a[1]),
        a[1] ^ t ^ _xtime(a[1] ^ a[2]),
        a[2] ^ t ^ _xtime(a[2] ^ a[3]),
        a[3] ^ t ^ _xtime(a[3] ^ u)
    ]
def _mix_columns(s):
    res = []
    for c in range(4):
        col = [s[c], s[4 + c], s[8 + c], s[12 + c]]
        res.extend(_mix_single_column(col))
    out = [0]*16
    for c in range(4):
        for r in range(4):
            out[r*4 + c] = res[c*4 + r]
    return out

def _mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p

def _inv_mix_columns(s):
    out = [0]*16
    for c in range(4):
        col = [s[c], s[4+c], s[8+c], s[12+c]]
        out[c]    = _mul(col[0], 0x0E) ^ _mul(col[1], 0x0B) ^ _mul(col[2], 0x0D) ^ _mul(col[3], 0x09)
        out[4+c]  = _mul(col[0], 0x09) ^ _mul(col[1], 0x0E) ^ _mul(col[2], 0x0B) ^ _mul(col[3], 0x0D)
        out[8+c]  = _mul(col[0], 0x0D) ^ _mul(col[1], 0x09) ^ _mul(col[2], 0x0E) ^ _mul(col[3], 0x0B)
        out[12+c] = _mul(col[0], 0x0B) ^ _mul(col[1], 0x0D) ^ _mul(col[2], 0x09) ^ _mul(col[3], 0x0E)
    return out

def _aes_enc_blk(blk, rkeys):
    state = [s ^ k for s, k in zip(blk, rkeys[0])]
    for r in range(1, 10):
        state = [_S_BOX[b] for b in state]
        state = [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11]
        ]
        state = _mix_columns(state)
        state = [s ^ k for s, k in zip(state, rkeys[r])]
    state = [_S_BOX[b] for b in state]
    state = [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11]
    ]
    return bytes([s ^ k for s, k in zip(state, rkeys[10])])

def _aes_dec_blk(blk, rkeys):
    state = [s ^ k for s, k in zip(blk, rkeys[10])]
    for r in range(9, 0, -1):
        state = [
            state[0], state[13], state[10], state[7],
            state[4], state[1], state[14], state[11],
            state[8], state[5], state[2], state[15],
            state[12], state[9], state[6], state[3]
        ]
        state = [_INV_S_BOX[b] for b in state]
        state = [s ^ k for s, k in zip(state, rkeys[r])]
        state = _inv_mix_columns(state)
    state = [
        state[0], state[13], state[10], state[7],
        state[4], state[1], state[14], state[11],
        state[8], state[5], state[2], state[15],
        state[12], state[9], state[6], state[3]
    ]
    state = [_INV_S_BOX[b] for b in state]
    return bytes([s ^ k for s, k in zip(state, rkeys[0])])


def aes_128_encrypt(plaintext: str, key: str | None = None, iv: bytes | None = None) -> dict:
    """AES-128 CBC encryption with PKCS7 padding."""
    if key is None or not key:
        key = generate_random_aes_key()
    key_bytes = key.encode('utf-8')
    if len(key_bytes) != 16:
        # Pad or truncate to 16 bytes for user resilience
        key_bytes = (key_bytes + b'0'*16)[:16]
        key = key_bytes.decode('utf-8', errors='replace')

    iv = iv or os.urandom(16)

    # Attempt cryptography if available
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return {'cipher_text': base64.b64encode(ciphertext).decode('utf-8'), 'iv': base64.b64encode(iv).decode('utf-8'), 'key': key, 'cipher': 'a'}
    except ImportError:
        pass

    # Pure Python fallback
    data = plaintext.encode('utf-8')
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len] * pad_len)
    rkeys = _key_expansion(key_bytes)
    prev = iv
    ciphertext = b''
    for i in range(0, len(padded), 16):
        blk = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
        enc = _aes_enc_blk(blk, rkeys)
        ciphertext += enc
        prev = enc
    return {'cipher_text': base64.b64encode(ciphertext).decode('utf-8'), 'iv': base64.b64encode(iv).decode('utf-8'), 'key': key, 'cipher': 'a'}


def aes_128_decrypt(ciphertext: str, key: str, iv_b64: str) -> str:
    """AES-128 CBC decryption with PKCS7 unpadding."""
    key_bytes = key.encode('utf-8')
    if len(key_bytes) != 16:
        key_bytes = (key_bytes + b'0'*16)[:16]

    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        iv = base64.b64decode(iv_b64.encode('utf-8'))
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        raw = decryptor.update(base64.b64decode(ciphertext.encode('utf-8'))) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(raw) + unpadder.finalize()).decode('utf-8', errors='replace')
    except ImportError:
        pass

    try:
        raw_ct = base64.b64decode(ciphertext.encode('utf-8'))
        iv = base64.b64decode(iv_b64.encode('utf-8'))
        rkeys = _key_expansion(key_bytes)
        prev = iv
        decrypted_padded = b''
        for i in range(0, len(raw_ct), 16):
            enc = raw_ct[i:i+16]
            dec = _aes_dec_blk(enc, rkeys)
            decrypted_padded += bytes(a ^ b for a, b in zip(dec, prev))
            prev = enc
        if not decrypted_padded:
            return ''
        pad = decrypted_padded[-1]
        if 1 <= pad <= 16:
            plain = decrypted_padded[:-pad]
        else:
            plain = decrypted_padded
        return plain.decode('utf-8', errors='replace')
    except Exception as e:
        return f"[AES Decrypt Error: {e}]"


# --- Master Record Decoding & Saving ---

def decode_record(rec: Dict[str, Any]) -> str:
    """Decodes a vault record according to its cipher type."""
    if not isinstance(rec, dict):
        raise TypeError('rec must be a dict')

    cipher = str(rec.get('cipher', '')).lower()
    cipher_text = rec.get('cipher_text', '')

    if cipher in {'c', 'r'}:
        return dcode_caesar(rec)
    elif cipher == 'v':
        return dcode_vig(rec)
    elif cipher == 'x':
        key = str(rec.get('key', 'PASSGEN_XOR_KEY'))
        return xor_stream_decrypt(str(cipher_text), key)
    elif cipher == 'a':
        key = str(rec.get('key', ''))
        iv = str(rec.get('iv', ''))
        if not key or not iv:
            return ''
        return aes_128_decrypt(str(cipher_text), key, iv)
    else:
        return str(cipher_text)


def save_user_password(
    username: str,
    service_name: str,
    account_username: str,
    plaintext_password: str,
    cipher_type: str = "caesar",
    shift: int = 3,
    key: str = "KEY",
    iv: Optional[str] = None
) -> Dict[str, Any]:
    """Encrypts and stores a new password record for the user across all 5 cipher methods."""
    clean_service = service_name.strip() or "Untitled Service"
    clean_account = account_username.strip() or username
    cipher_norm = cipher_type.strip().lower()

    extra_data = {}
    if cipher_norm in ("caesar", "c"):
        enc = caesar_encrypt(plaintext_password, shift=shift, rot13=False)
    elif cipher_norm in ("rot13", "r"):
        enc = caesar_encrypt(plaintext_password, shift=13, rot13=True)
    elif cipher_norm in ("vigenere", "v"):
        enc = vigenere_encrypt(plaintext_password, key=key)
    elif cipher_norm in ("xor", "x"):
        xor_key = str(key) if key else "PASSGEN_XOR_KEY"
        ct = xor_stream_encrypt(plaintext_password, xor_key)
        enc = {"cipher_text": ct, "cipher": "x", "key": xor_key}
    elif cipher_norm in ("aes", "a"):
        aes_res = aes_128_encrypt(plaintext_password, key=str(key) if key else None)
        enc = {"cipher_text": aes_res["cipher_text"], "cipher": "a", "key": aes_res["key"]}
        extra_data["iv"] = aes_res["iv"]
    else:
        enc = caesar_encrypt(plaintext_password, shift=3, rot13=False)

    raw = get_raw_vault()
    all_records = raw.get("vault", [])
    next_id = max((r.get("id", 0) for r in all_records if isinstance(r, dict)), default=0) + 1

    new_record = {
        "id": next_id,
        "owner": username.strip(),
        "service": clean_service,
        "account_username": clean_account,
        "cipher_text": enc["cipher_text"],
        "cipher": enc["cipher"],
        "key": enc["key"]
    }
    new_record.update(extra_data)

    all_records.append(new_record)
    raw["vault"] = all_records
    save_raw_vault(raw)
    return new_record


def export_user_passwords(username: str, master_password: str) -> Dict[str, Any]:
    """
    Verifies user credentials before decrypting and returning all saved passwords
    for the user across all cipher methods.
    """
    if username.strip().lower() == "demo" and (not master_password or master_password == "demo123"):
        auth_ok = True
    else:
        auth_res = authenticate_user(username, master_password)
        auth_ok = auth_res.get("success", False)

    if not auth_ok:
        return {
            "success": False,
            "message": "Export failed: Authentication error. Incorrect username or master password.",
            "records": []
        }

    records = get_user_vault(username)
    decrypted_records = []
    for r in records:
        dec = decode_record(r)
        c_code = r.get("cipher", "")
        method_label = CIPHER_NAMES.get(c_code, c_code.upper() or "Unknown")

        decrypted_records.append({
            "id": r.get("id"),
            "service": r.get("service", "General"),
            "account_username": r.get("account_username", username),
            "cipher_method": method_label,
            "cipher_code": c_code,
            "key": r.get("key"),
            "encrypted_password": r.get("cipher_text"),
            "decrypted_password": dec
        })

    return {
        "success": True,
        "message": f"Successfully exported {len(decrypted_records)} decrypted password(s).",
        "username": username,
        "records": decrypted_records
    }


def export_to_csv_string(records: List[Dict[str, Any]]) -> str:
    """Generates a CSV formatted string of decrypted records."""
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Service", "Account Username", "Encryption Method", "Ciphertext", "Decrypted Password"])
    for r in records:
        writer.writerow([
            r.get("id", ""),
            r.get("service", ""),
            r.get("account_username", ""),
            r.get("cipher_method", ""),
            r.get("encrypted_password", r.get("cipher_text", "")),
            r.get("decrypted_password", "")
        ])
    return output.getvalue()


# --- Password Quality & Strength Analysis (Regex Complexity) ---

def analyze_password_strength(password: str) -> Dict[str, Any]:
    """
    Analyzes password quality using regular expressions for complexity.
    Criteria:
      1. Minimum Length (8+ characters)
      2. Strong Length (12+ characters)
      3. Uppercase Letters ([A-Z])
      4. Lowercase Letters ([a-z])
      5. Numbers / Digits ([0-9])
      6. Special Symbols / Punctuation
    """
    if not password:
        return {
            "score": 0,
            "percentage": 0,
            "label": "None",
            "color": "#343a40",
            "criteria": {
                "min_length": False,
                "length_12": False,
                "has_uppercase": False,
                "has_lowercase": False,
                "has_number": False,
                "has_symbol": False
            }
        }

    has_len8 = len(password) >= 8
    has_len12 = len(password) >= 12
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_number = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password))

    points = 0
    if has_len8:
        points += 1
    if has_len12:
        points += 1
    if has_upper:
        points += 1
    if has_lower:
        points += 1
    if has_number:
        points += 1
    if has_symbol:
        points += 1

    if points <= 1:
        label = "Very Weak"
        score = 1
        pct = 20
        color = "#ef4444"
    elif points == 2:
        label = "Weak"
        score = 2
        pct = 40
        color = "#f14e32"
    elif points in (3, 4):
        label = "Fair"
        score = 3
        pct = 60
        color = "#f59e0b"
    elif points == 5:
        label = "Strong"
        score = 4
        pct = 80
        color = "#10b981"
    else:
        label = "Very Strong"
        score = 5
        pct = 100
        color = "#22c55e"

    return {
        "score": score,
        "percentage": pct,
        "label": label,
        "color": color,
        "criteria": {
            "min_length": has_len8,
            "length_12": has_len12,
            "has_uppercase": has_upper,
            "has_lowercase": has_lower,
            "has_number": has_number,
            "has_symbol": has_symbol
        }
    }


def _seed_demo_vault():
    """Seeds initial demo records if vault is empty."""
    raw = get_raw_vault()
    if not raw.get("vault"):
        raw["vault"] = [
            {
                "id": 1,
                "owner": "demo",
                "service": "Email Account",
                "account_username": "demo@example.com",
                "cipher_text": "khoor",
                "cipher": "c",
                "key": 3
            },
            {
                "id": 2,
                "owner": "demo",
                "service": "Work Portal",
                "account_username": "demo_work",
                "cipher_text": "Uryyb123!",
                "cipher": "r",
                "key": 13
            }
        ]
        save_raw_vault(raw)

_seed_demo_vault()


# --- Special Access & Export Functions (from PassGen v2 spl_ppl / full_record) ---

SPECIAL_DENIED_NAMES = {"Maria", "Devananda"}
SPECIAL_MASTER_NAME = "Jenifa"

def check_special_access(name: str) -> Dict[str, Any]:
    """Evaluates special name privileges matching spl_ppl()."""
    clean_name = (name or "").strip()
    if clean_name in SPECIAL_DENIED_NAMES:
        return {
            "status": "denied",
            "name": clean_name,
            "message": "Access denied."
        }
    if clean_name == SPECIAL_MASTER_NAME:
        return {
            "status": "jenifa",
            "name": clean_name,
            "message": "Hi ma'am, What would you like to do?"
        }
    return {
        "status": "sybau",
        "name": clean_name,
        "message": "Sybau"
    }


def generate_vault_records_csv(output_path: Optional[str] = None) -> Tuple[str, str]:
    """Generates vault_records.csv with Index, Ciphertext as in full_record()."""
    if not output_path:
        output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault_records.csv")
    
    raw = get_raw_vault()
    records = raw.get("vault", [])
    
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Index", "Ciphertext"])
    for rec in records:
        writer.writerow([rec.get("id", ""), rec.get("cipher_text", "")])
    
    csv_content = output.getvalue()
    try:
        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            f.write(csv_content)
    except Exception as e:
        print(f"Warning: Could not write vault_records.csv to disk: {e}")
        
    return csv_content, output_path


def generate_jenifa_decrypted_csv(output_path: Optional[str] = None) -> Tuple[str, str]:
    """Generates vault_records_decrypted.csv with Ciphertext, Plaintext, Encryption Method as in spl_ppl()."""
    if not output_path:
        output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault_records_decrypted.csv")
        
    raw = get_raw_vault()
    records = raw.get("vault", [])
    
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Ciphertext", "Plaintext", "Encryption Method"])
    
    for rec in records:
        ct = rec.get("cipher_text", "")
        try:
            pt = decode_record(rec)
        except Exception as dec_err:
            pt = f"[Decode unavailable: {dec_err}]"
        method = CIPHER_NAMES.get(rec.get("cipher", ""), rec.get("cipher", "Unknown"))
        writer.writerow([ct, pt, method])
        
    csv_content = output.getvalue()
    try:
        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            f.write(csv_content)
    except Exception as e:
        print(f"Warning: Could not write vault_records_decrypted.csv to disk: {e}")
        
    return csv_content, output_path


def get_all_decoded_vault_records() -> List[Dict[str, Any]]:
    """Returns all records decoded for Jenifa master view."""
    raw = get_raw_vault()
    records = raw.get("vault", [])
    results = []
    for rec in records:
        ct = rec.get("cipher_text", "")
        c_code = rec.get("cipher", "c")
        try:
            pt = decode_record(rec)
        except Exception as e:
            pt = f"[Decode error: {e}]"
        results.append({
            "id": rec.get("id"),
            "cipher": c_code,
            "cipher_name": CIPHER_NAMES.get(c_code, c_code),
            "cipher_text": ct,
            "plain_text": pt,
            "key": rec.get("key"),
            "service": rec.get("service", "General"),
            "account_username": rec.get("account_username", "demo")
        })
    return results

