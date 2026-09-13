import time

print("Hi! Check out our services. Type the nos. to use it. \n 1. Ciphertext Generation \n 2. Ciphertext Record \n 3. Type the special name")
choi1 = int(input())
cipher_rec=[]
rec_no=0
if choi1 == '1':
     while(check=True):
        plain_t = input("Go ahead, enter that pwd! : ")
        choi2 = int(print("Select your choice of cipher! \n 1 = Ceasar shift \n 2 = ROT-13 \n 3 = Vignere" ))
        cipher_t =""
        if choi2 == 1:
            shift = int(print("Enter how many shifts: "))
            for char in plain_t:
                    if char.isalpha():
                    #big brain move
                    #check if upper or lower then used ord(A)/ord(a) as needed
                    case_char = ord(A) if char.isupper() else ord (a)
                    cipher_t += chr((ord(char)-case_char+shift)%26+case_char)
                    else:
                        cipher+=char
            print("Encoding:")
            while i <=10:
                print("*")
                time.sleep(0.1)
            print("The cipher text:"+cipher_t+"\n Shall I save it to the list? (y/n)")
            if (input()==y):
                rec_no+=1
                cipher_rec.append(rec_no,cipher_t,'c')
        if choi2 == 2:
            for char in plain_t:
                if char.isalpha():
                # shift is 13
                case_char = ord(A) if char.isupper() else ord (a)
                cipher_t += chr((ord(char) - case_char + 13)%26+case_char)
                else:
                    cipher+=char
            print("Encoding:")
                while i <=10:
                    print("*")
                    time.sleep(0.1)
            print("The cipher text:"+cipher_t+"\n Shall I save it to the list? (y/n)")
            if (input()==y):
                rec_no+=1
                cipher_rec.append(rec_no,cipher_t,'r')
        if choi2 == 3:
            key = input("Enter your key: ")
            key_index = 0
            for char in plaintext:
                if char.isalpha():
                    start = ord('A') if char.isupper() else ord('a')
                    
                    # Message shift: 0 to 25
                    p_val = ord(char) - start
                    # Key shift: 0 to 25
                    k_val = ord(key[key_index % len(key)]) - ord('A')
                    
                    # Apply shift with wrap-around
                    c_val = (p_val + k_val) % 26
                    ciphertext.append(chr(start + c_val))
                    
                    # Move to the next letter of the key
                    key_index += 1
            else:
                cipher_t.append(char)
            print("Encoding")
            print("The cipher text:"+cipher_t+"\n Shall I save it to the list? (y/n)")
            if (input()==y):
                rec_no+=1
                cipher_rec.append(rec_no,cipher_t,'v')
        checkk = print("More Encoding? (y/n)")
        check = False if checkk==y else True
#End of encoding
if choi1 == '2':
    print(cipher_rec[i] for i in range (len(key)))

if choi1 == 'Maria' or 'Devananda' or "Jenifa":
    print("Hi. You have complete access to the record and their plaintext. We have access of ", (int(len(cipher_rec)/3)), " ciphertext.")
    print("Wanna decode? (y/n)")
    check = True if input() == 'y' else False
    if choi1 == "Maria" or "Devananda":
        print("Don't bother.")
    




