#learning fns in py
#wish me luck
from colorama import Fore,Style,init #for colors
#import string #for printable
import time #rly?
import json

init(autoreset=True)#rids me of writing reset_all


#need to see if it just throws that specific dict or entire file
def getdata() -> dict:
    with open('vault.json','w+') as file:
        open_file = json.load(file)
        return open_file

def savedata(data:dict):    
    with open('vault.json','w') as file:
        json.dump(data, file, indent=4)
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

#it's the start of the prg    
if __name__ == "__main__":
    load_animation()
    start()

def cipher_generation(): 
    plaintext = input('Enter plaintext: ')
    print('Select cipher: 1=Caesar  2=ROT13  3=Vigenère')
    opt = input('> ').strip()
    #ur choice of cipher
    if opt == '1':
        # Caesar encryption
        result=caesar(plaintext,False)  
    elif opt == '2':
        # ROT13
        result=caesar(plaintext,True)            
    elif opt == '3':
        # Vigenère
        result = vignere(plaintext)
    else:
        print('Unknown option.')
        return
    #saving into "vault"'s pair (list)
    print("Shall I save this?"+Fore.GREEN+('(y/')+Fore.RED+('n'))
    if str(input().strip())=='y':
        data = getdata()
        records_list = data.get('vault', [])
        id = id+1
        result['id'] = id
        records_list.append(result)
        data['vault'] = records_list
        savedata(data)
        print('Record saved to vault.')
        return
    
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

def full_record():
    return(print(getdata()))

def decode_record(rec: dict) -> str:
    if rec['cipher'] in {'c', 'r'}:
        return dcode_caesar(rec)
    elif rec['cipher'] == 'v':
        return dcode_vig(rec)
    return ''

def spl_ppl():
    print('Welcome. Your good name please?')
    name = input('> ').strip()
    data = getdata()
    records = data.get('vault',[])
    print(f'Hi {name}. We have {len(records)} ciphertext(s).')
    if input('Wanna decode?'+Fore.YELLOW+' (y/n)').strip().lower() != 'y':
        return
    if( name in {'Maria','Devananda'}):
        print(Fore.RED+"Access denied.")
        exit(0)
    elif(name in ['Jenifa']):
        print(Fore.GREEN+"Hi ma'am, Which would you like to decode? Enter T for total list or an index number.")
        sel = input('> ').strip()
        if sel.upper() == 'T':#full records
            if not records:
                print('No records to decode.')
                return
            for rec in records:
                plain = decode_record(rec)
                print(f"({rec['id']},{rec['cipher']}) ciphertext:{rec['cipher_text']}, plaintext:{plain}")
            return
        else:#check single index number
            idx = int(sel)
            for i in records:
                flag = True
                if(idx==i['id']):
                    plain = decode_record(i)
                    print(f"({i['id']},{i['cipher']}) ciphertext:{i['cipher_text']}, plaintext:{plain}")
                    flag=False
            if flag:print("No one with that ID, ma'am."); return #gaslighting the code?   

                
        
    #elif(name matches with class db):
        #show respective gif
    else: 
        print('Sybau')
        exit(0)




