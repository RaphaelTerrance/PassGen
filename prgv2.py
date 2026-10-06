#learning fns in py
#wish me luck 
#khoor=hello(shift3)
from colorama import Fore, Style, init #
import json
import time
print("hi")
init(autoreset=True)#rids me of writing reset_all


#fills the entering var with the json file
def getdata() -> dict:
    with open('vault.json', 'r') as file:
        data = json.load(file)
    if not data:
        return {'vault': []}
    if 'vault' not in data:
        data['vault'] = []
    return data

def savedata(data:dict):    
    file_data = getdata()
    file_data['vault'].append(data)
    with open('vault.json','w') as file:
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
    for i in range(10):
        print(Fore.RED+'*',end='',flush=True)
        time.sleep(0.05)
    print()
    return
   

def cipher_generation(): 
    plaintext = input("Enter plaintext: ")
    print("Select cipher: 1=Caesar  2=ROT13  3=Vigenère")
    opt = input("> ").strip()

    if opt == '1':
        result = caesar(plaintext, False)
    elif opt == '2':
        result = caesar(plaintext, True)
    elif opt == '3':
        result = vignere(plaintext)
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

# change such that it only shows ciphertext list
def full_record():
    load_animation()
    data = getdata()
    for rec in data.get('vault', []):
        print(f"{rec.get('id')} {rec.get('cipher_text')}")
    return

def decode_record(rec: dict) -> str:
    if rec['cipher'] == 'c':
        return dcode_caesar(rec)
    elif rec['cipher'] == 'r':
        return dcode_caesar(rec)
    elif rec['cipher'] == 'v':
        return dcode_vig(rec)
    else: return ''

def spl_ppl():
    print("Welcome. Your good name please?")
    name = input("> ").strip()

    data = getdata()
    records = data.get('vault', [])

    if name in {'Maria', 'Devananda'}:
        print("Access denied.")
        return

    if name == 'Jenifa':
        print("Hi ma'am, Which would you like to decode? Enter T or an index number.")
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
        #show respective gif
    else: 
        print('Sybau')
        exit(0)

#it's the start of the prg 
if __name__ == "__main__":
    load_animation()
    start()




