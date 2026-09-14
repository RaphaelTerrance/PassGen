#this took 3 days of recoding by hand, 1 hr by codex
#pls kurt cobain me
import time

# Storage for records: each record is a dict with id, cipher, type ('c', 'r', 'v')
records = []
next_id = 1
special_names = {'Maria', 'Devananda', 'Jenifa'}

def show_dots():
    # small helper kept as a single short function for UX only
    for _ in range(8):
        print('*', end='', flush=True)
        time.sleep(0.03)
    print()

while True:
    print('\n Hi! Choose an option:')
    print('1. Ciphertext Generation')
    print('2. Ciphertext Record')
    print('3. Type one of the special names.')
    print('Q. Quit')
    choice = input('> ').strip()

    if choice == '1':
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
            continue

        print('Encoding:', end=' ')
        show_dots()
        print('The ciphertext:', cipher_text)
        if input('Save to list? (y/n) ').strip().lower() == 'y':
            # store meta so we can decode automatically later
            if c_type == 'c':
                meta = shift
            elif c_type == 'v':
                meta = key.upper()
            else:
                meta = None
            records.append({'id': next_id, 'cipher': cipher_text, 'type': c_type, 'meta': meta})
            next_id += 1

    elif choice == '2':
        if not records:
            print('No records saved yet.')
        else:
            print('Saved ciphertext records:')
            for rec in records:
                print(f"[{rec['id']}] type={rec['type']}  cipher={rec['cipher']}")

    elif choice == '3':
        name = input('Enter name: ').strip()
        if name not in special_names:
            print('Name not recognized.')
            continue

        print(f'Hi {name}. We have {len(records)} ciphertext(s).')
        if input('Wanna decode? (y/n) ').strip().lower() != 'y':
            continue

        if name in {'Maria', 'Devananda'}:
            print("Access restricted. You don't have decode permissions.")
            if input('Exit program? (y/n) ').strip().lower() == 'y':
                break
            continue

        # Jenifa: allow decoding
        if name == 'Jenifa':
            print('Hi madam Which would you like to decode? Enter T for total list or an index number.')
            sel = input('> ').strip()
            if sel.upper() == 'T':
                if not records:
                    print('No records to decode.')
                    continue
                for rec in records:
                    print(f"Decoding record [{rec['id']}]: type={rec['type']} cipher={rec['cipher']}")
                    if rec['type'] == 'c':
                        # use stored shift if available
                        if rec.get('meta') is not None:
                            shift = int(rec['meta'])
                        else:
                            while True:
                                try:
                                    shift = int(input(f"Enter shift for Caesar record [{rec['id']}]: "))
                                    break
                                except ValueError:
                                    print('Please enter an integer shift.')
                        parts = []
                        for ch in rec['cipher']:
                            if ch.isalpha():
                                base = ord('A') if ch.isupper() else ord('a')
                                parts.append(chr((ord(ch) - base - shift) % 26 + base))
                            else:
                                parts.append(ch)
                        plain = ''.join(parts)
                        print(f"Decoded [{rec['id']}]: {plain}\n")

                    elif rec['type'] == 'r':
                        parts = []
                        for ch in rec['cipher']:
                            if ch.isalpha():
                                base = ord('A') if ch.isupper() else ord('a')
                                parts.append(chr((ord(ch) - base + 13) % 26 + base))
                            else:
                                parts.append(ch)
                        print(f"Decoded [{rec['id']}]: {''.join(parts)}\n")

                    elif rec['type'] == 'v':
                        # use stored key if available
                        if rec.get('meta'):
                            key_use = rec['meta']
                        else:
                            key_use = input(f"Enter key for Vigenère record [{rec['id']}]: ").strip().upper()
                        parts = []
                        k_idx = 0
                        for ch in rec['cipher']:
                            if ch.isalpha():
                                base = ord('A') if ch.isupper() else ord('a')
                                c_val = ord(ch) - base
                                k_val = ord(key_use[k_idx % len(key_use)]) - ord('A')
                                parts.append(chr((c_val - k_val) % 26 + base))
                                k_idx += 1
                            else:
                                parts.append(ch)
                        print(f"Decoded [{rec['id']}]: {''.join(parts)}\n")

            else:
                try:
                    idx = int(sel)
                except ValueError:
                    print('Invalid index.')
                    continue
                found = None
                for r in records:
                    if r['id'] == idx:
                        found = r
                        break
                if not found:
                    print('Record not found.')
                    continue

                print(f"Decoding record [{found['id']}]: type={found['type']} cipher={found['cipher']}")
                if found['type'] == 'c':
                    if found.get('meta') is not None:
                        shift = int(found['meta'])
                    else:
                        while True:
                            try:
                                shift = int(input(f"Enter shift for Caesar record [{found['id']}]: "))
                                break
                            except ValueError:
                                print('Please enter an integer shift.')
                    parts = []
                    for ch in found['cipher']:
                        if ch.isalpha():
                            base = ord('A') if ch.isupper() else ord('a')
                            parts.append(chr((ord(ch) - base - shift) % 26 + base))
                        else:
                            parts.append(ch)
                    print('Decoded:', ''.join(parts))

                elif found['type'] == 'r':
                    parts = []
                    for ch in found['cipher']:
                        if ch.isalpha():
                            base = ord('A') if ch.isupper() else ord('a')
                            parts.append(chr((ord(ch) - base + 13) % 26 + base))
                        else:
                            parts.append(ch)
                    print('Decoded:', ''.join(parts))

                elif found['type'] == 'v':
                    if found.get('meta'):
                        key_use = found['meta']
                    else:
                        key_use = input(f"Enter key for Vigenère record [{found['id']}]: ").strip().upper()
                    parts = []
                    k_idx = 0
                    for ch in found['cipher']:
                        if ch.isalpha():
                            base = ord('A') if ch.isupper() else ord('a')
                            c_val = ord(ch) - base
                            k_val = ord(key_use[k_idx % len(key_use)]) - ord('A')
                            parts.append(chr((c_val - k_val) % 26 + base))
                            k_idx += 1
                        else:
                            parts.append(ch)
                    print('Decoded:', ''.join(parts))

    elif choice.upper() == 'Q':
        break
    else:
        print('Unknown choice, please try again.')





