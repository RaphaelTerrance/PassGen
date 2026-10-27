#learning fns in py
#wish me luck 
#khoor=hello(shift3)
from colorama import Fore, Style, init #
import base64
import csv
import json
import os
import secrets
import string
import time

try:
    import hashlib
except ImportError:
    hashlib = None

print("hi")
init(autoreset=True)#rids me of writing reset_all

VAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vault.json')


#fills the entering var with the json file
def getdata() -> dict:
    if not os.path.exists(VAULT_FILE):
        return {'vault': []}
    with open(VAULT_FILE, 'r') as file:
        data = json.load(file)
    if not data:
        return {'vault': []}
    if 'vault' not in data:
        data['vault'] = []
    return data

def savedata(data:dict):    
    file_data = getdata()
    file_data['vault'].append(data)
    with open(VAULT_FILE,'w') as file:
        json.dump(file_data, file, indent=4)
    return

def start():
    while(True):
        print("Hi! Welcome to PassGen. What would you like? \n 1. Ciphertext Generation \n 2. Records \n Q for Quit")
        
        choi1=input().strip()
        
        if(choi1=='1'): cipher_generation()
        
        elif(choi1=='2'): full_record()
        
        elif(choi1=='3'): spl_ppl()
        
        elif(choi1=='Q' or choi1=='q'): quit(0)
        
        else:
            print('SYBAU')
            continue
    
def load_animation():
    spinner = ["|", "/", "-", "\\"]
    matrix_glyphs = "01$#%&*+=-~<>[]{}?@!"
    colors = [Fore.CYAN, Fore.GREEN, Fore.YELLOW, Fore.MAGENTA, Fore.BLUE]

    print("\n")
    for frame in range(16):
        spin = spinner[frame % len(spinner)]
        color = colors[frame % len(colors)]
        progress = frame / 15.0
        bar_len = 24
        filled = int(progress * bar_len)
        bar = "█" * filled + "░" * (bar_len - filled)
        
        # Scrambled hex / matrix ticker
        seed = secrets.token_hex(6).upper()
        ticker = "".join(secrets.choice(matrix_glyphs) for _ in range(8))
        
        print(
            f"\r{color}{Style.BRIGHT}[{spin}] ENCRYPTING VAULT [{bar}] {int(progress * 100):3d}% | {seed} {ticker}{Style.RESET_ALL}",
            end='',
            flush=True
        )
        time.sleep(0.06)

    print(f"\r{Fore.GREEN}{Style.BRIGHT}[✓] ENCRYPTING VAULT [{ '█' * 24 }] 100% | READY!                    {Style.RESET_ALL}\n", flush=True)
    return


def xor_stream_encrypt(plaintext: str, key: str) -> str:
    if not key:
        raise ValueError('XOR key cannot be empty.')
    key_bytes = key.encode('utf-8')
    data = plaintext.encode('utf-8')
    stream = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return stream.hex()


def xor_stream_decrypt(ciphertext_hex: str, key: str) -> str:
    if not key:
        raise ValueError('XOR key cannot be empty.')
    raw = bytes.fromhex(ciphertext_hex)
    key_bytes = key.encode('utf-8')
    plain = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
    return plain.decode('utf-8', errors='replace')


def generate_random_aes_key(length: int = 16) -> str:
    if length <= 0:
        raise ValueError('AES key length must be positive.')
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def aes_128_encrypt(plaintext: str, key: str | None = None, iv: bytes | None = None) -> dict:
    if key is None or not key:
        key = generate_random_aes_key()
    if len(key.encode('utf-8')) != 16:
        raise ValueError('AES-128 requires a 16-byte key.')

    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise RuntimeError('Install cryptography to use AES-128 encryption.') from exc

    iv = iv or os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(key.encode('utf-8')), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return {'cipher_text': base64.b64encode(ciphertext).decode('utf-8'), 'iv': base64.b64encode(iv).decode('utf-8'), 'key': key, 'cipher': 'a'}


def aes_128_decrypt(ciphertext: str, key: str, iv_b64: str) -> str:
    if len(key.encode('utf-8')) != 16:
        raise ValueError('AES-128 requires a 16-byte key.')

    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise RuntimeError('Install cryptography to use AES-128 decryption.') from exc

    iv = base64.b64decode(iv_b64.encode('utf-8'))
    cipher = Cipher(algorithms.AES(key.encode('utf-8')), modes.CBC(iv))
    decryptor = cipher.decryptor()
    raw = decryptor.update(base64.b64decode(ciphertext.encode('utf-8'))) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(raw) + unpadder.finalize()).decode('utf-8', errors='replace')


def ascon_hash256(data: str | bytes) -> str:
    payload = data.encode('utf-8') if isinstance(data, str) else data
    try:
        import ascon
        if hasattr(ascon, 'hash256'):
            digest = ascon.hash256(payload)
            if hasattr(digest, 'hex'):
                return digest.hex()
            return str(digest)
    except ImportError:
        pass

    if hashlib is None:
        raise RuntimeError('A supported hash library is required for Ascon Hash256.')
    return hashlib.sha256(payload).hexdigest()


def cipher_generation(): 
    plaintext = input("Enter plaintext: ")
    print("Select cipher: 1 = Caesar Shift  2 = ROT13  3 = Vigenère\n 4 = XOR Stream Cipher 5 = AES-128 6 = Ascon Hash 256")
    opt = input("> ").strip()

    if opt == '1':
        result = caesar(plaintext, False)
    elif opt == '2':
        result = caesar(plaintext, True)
    elif opt == '3':
        result = vignere(plaintext)
    elif opt == '4':
        key = input('Enter XOR key: ').strip()
        result = {'cipher_text': xor_stream_encrypt(plaintext, key), 'cipher': 'x', 'key': key}
    elif opt == '5':
        result = aes_128_encrypt(plaintext, generate_random_aes_key())
    elif opt == '6':
        result = {'cipher_text': ascon_hash256(plaintext), 'cipher': 'h', 'key': 'ascon-hash256'}
    else:
        print("Unknown option.")
        return

    load_animation()
    if input("Shall I save this? (y/n): ").strip().lower() == 'y':
        data = getdata()
        records = data.get('vault', [])
        next_id = max((r.get('id', 0) for r in records), default=0) + 1
        result['id'] = next_id
        savedata(result)

def caesar(plaintext:str, rot13:bool ) -> dict:
    while True:
        try:
            shift = int(input('Enter shift (integer): ')) if rot13 is False else 13
            break
        except ValueError:
            print('Please enter a valid integer.')
    parts = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            parts.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            parts.append(ch)
    cipher_text = ''.join(parts)
    c_type = 'c' if rot13 is False else 'r'
    key = shift
    print('Encoding:', end=' ')
    load_animation()
    return({"cipher_text":cipher_text,"cipher":c_type,"key":key})

def dcode_caesar(ciphertext:dict) -> str:
    # get the shift from "key", then apply dcode
    if not isinstance(ciphertext, dict):
        raise TypeError('ciphertext must be a dict')
    # determine shift: accept int, numeric string, or fallback to 13 for ROT13
    key_raw = ciphertext.get('key', None)
    if key_raw is None:
        if ciphertext.get('cipher') == 'r':
            shift = 13
        else:
            raise ValueError('No key found for Caesar decryption')
    else:
        try:
            shift = int(key_raw)
        except (TypeError, ValueError):
            raise ValueError('Invalid key for Caesar decryption; expected integer')
    ct = ciphertext.get('cipher_text', '')
    parts = []
    for ch in ct:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            parts.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            parts.append(ch)
    return (''.join(parts))

def dcode_vig(ciphertext:dict) -> str:
    # get the keyword from "key", then decode
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
    return (''.join(parts))

def vignere(plaintext:str) -> dict:
    key = input('Enter key (letters only): ').strip().upper()
    if not key: key = 'testkey'
    parts = []
    k_idx = 0
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            p_val = ord(ch) - base
            k_val = ord(key[k_idx % len(key)]) - ord('A')
            parts.append(chr((p_val + k_val) % 26 + base))
            k_idx += 1
        else:
            parts.append(ch)
    cipher_text = ''.join(parts)
    c_type = 'v'
    return({"cipher_text":cipher_text,"cipher":c_type,"key":key})

CIPHER_NAMES = {
    'c': 'Caesar Shift',
    'r': 'ROT13',
    'v': 'Vigenère',
    'x': 'XOR Stream',
    'a': 'AES-128',
    'h': 'Ascon Hash 256'
}

# change such that it only shows ciphertext list
def full_record():
    load_animation()
    data = getdata()
    records = data.get('vault', [])
    for rec in records:
        print(f"{rec.get('id')} {rec.get('cipher_text')}")

    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vault_records.csv')
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(['Index', 'Ciphertext'])
            for rec in records:
                writer.writerow([rec.get('id', ''), rec.get('cipher_text', '')])
        print(f"\n[+] Excel spreadsheet generated: {csv_path}")
    except Exception as e:
        print(f"Error generating Excel sheet: {e}")
    return

def decode_record(rec: dict) -> str:
    if rec['cipher'] == 'c':
        return dcode_caesar(rec)
    elif rec['cipher'] == 'r':
        return dcode_caesar(rec)
    elif rec['cipher'] == 'v':
        return dcode_vig(rec)
    elif rec['cipher'] == 'x':
        return xor_stream_decrypt(rec.get('cipher_text', ''), str(rec.get('key', '')))
    elif rec['cipher'] == 'a':
        return aes_128_decrypt(rec.get('cipher_text', ''), str(rec.get('key', '')), str(rec.get('iv', '')))
    elif rec['cipher'] == 'h':
        return f"Hash256 digest: {rec.get('cipher_text', '')}"
    else:
        return ''

def spl_ppl():
    print("Welcome. Your good name please?")
    name = input("> ").strip()

    data = getdata()
    records = data.get('vault', [])

    if name in {'Maria', 'Devananda'}:
        print("Access denied.")
        return

    if name == 'Jenifa':
        print("Hi ma'am, What would you like to do?")
        print("1. Decode records\n2. Export Excel sheet with decrypted records (Ciphertext, Plaintext, Encryption Method)")
        jen_opt = input("> ").strip()

        if jen_opt == '2':
            jen_csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vault_records_decrypted.csv')
            try:
                with open(jen_csv_path, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Ciphertext', 'Plaintext', 'Encryption Method'])
                    for rec in records:
                        ct = rec.get('cipher_text', '')
                        pt = decode_record(rec)
                        method = CIPHER_NAMES.get(rec.get('cipher', ''), rec.get('cipher', 'Unknown'))
                        writer.writerow([ct, pt, method])
                print(f"[+] Decrypted Excel spreadsheet generated: {jen_csv_path}")
            except Exception as e:
                print(f"Error generating Excel sheet: {e}")
            return

        print("Which would you like to decode? Enter T or an index number.")
        sel = input("> ").strip()

        if sel.upper() == 'T':
            for rec in records:
                print(rec['id'], rec['cipher'], decode_record(rec))
        else:
            if not sel.isdigit():
                print('Sybau')
                return
            idx = int(sel)
            for rec in records:
                if rec['id'] == idx:
                    print(decode_record(rec))
                    return
            print("Record not found.")

                
        
    #elif(name matches with class db):
        #sorry aint got time
    else: 
        print('Sybau')
        exit(0)

#it's the start of the prg 
if __name__ == "__main__":
    load_animation()
    start()




