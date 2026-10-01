#learning fns in py
#wish me luck
from colorama import Fore,Style,init #for colors
#import string #for printable
import time #rly?
import json

init(autoreset=True)#rids me of writing reset_all


#need to see if it just throws that specific dict or entire file
def getdata() -> dict:
    with open('vault.json','r') as file:
        open_file = json.load(file)
        return open_file


def savedata(data):
    with open('vault.json','w') as file:
        json.dump(data, file, indent=4)
    return
    
def start():
    print("Hi! Welcome to PassGen. What would you like? \n 1. Ciphertext Generation \n 2. Records")
    choi1=int(input())
    if(choi1==1): cipher_generation()
    elif(choi1==2): records()
    elif(choi1==3): spl_ppl()
    else:print('SYBAU')
    
def load_animation():
    for i in range(10):
        print(Fore.RED+'*',end='',flush=True)
        time.sleep(0.05)
    print()
    
    start()

#think it's the start of the prg    
if __name__ == "__main__":
    load_animation()

def cipher_generation(): 
    plaintext = input('Enter plaintext: ')
    print('Select cipher: 1=Caesar  2=ROT13  3=Vigenère')
    opt = input('> ').strip()
    if opt == '1':
                # Caesar encrypt
                while True:
                    try:
                        shift = int(input('Enter shift (integer): '))
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
                c_type = 'c'
    
    elif opt == '2':
        # ROT13
        parts = []
        for ch in plaintext:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                parts.append(chr((ord(ch) - base + 13) % 26 + base))
            else:
                parts.append(ch)
        cipher_text = ''.join(parts)
        c_type = 'r'

    elif opt == '3':
        # Vigenère
        key = input('Enter key (letters only): ').strip().upper()
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
    
    else:
        print('Unknown option.')
        return
    

def records():
    return(getdata())

def spl_ppl():
    print('Welcome. Your good name please?')
    name = input('> ').strip()
    if( name=='Maria' or name =='Devananda'):
        print(Fore.RED+"Read the code. This ain't for you.")
        exit(0)
    elif(name=='Jenifa'):
        print(Fore.GREEN+"Hi ma'am, Which would you like to decode? Enter T for total list or an index number.")
        sel = input('> ').strip()
    #elif(name matches with class db):
        #show respective gif
    else: 
        print('Sybau')
        exit(0)



