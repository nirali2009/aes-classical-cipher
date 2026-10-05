import argparse
import base64

parser=argparse.ArgumentParser()

group=parser.add_mutually_exclusive_group(required=True)
group.add_argument('-e','--encrypt',action='store_true')
group.add_argument('-d','--decrypt',action='store_true')

parser.add_argument('-c','--cipher',choices=['vigenere','aes'],required=True)

inp_grp=parser.add_mutually_exclusive_group(required=True)
inp_grp.add_argument('-s','--string')
inp_grp.add_argument('-f','--file')

parser.add_argument('-k','--key',required=True)

parser.add_argument('-o', '--output', choices=['hex','base64'], default='hex')

args=parser.parse_args()

def get_data():
    if args.string:
        data=args.string
    elif args.file:
        with open(args.file,'r') as file:
            data=file.read()
    return data

text=get_data()

def vigenere():
    key_val=args.key
    key=key_val.upper()
    if not key:
        raise ValueError("Key can not be empty")
    if not key.isalpha():
        raise ValueError("Key must contain only alphabets")
    key_index=0
    result=''
    for i in text:
        if i.isalpha()!=True:
            result+=i
        else:
            if i.isupper():
                j=ord(i)-ord('A')
            else:
                j=ord(i)-ord('a')
            key_index_val=ord(key[key_index])-ord('A')
            if args.encrypt:
                k=(j+key_index_val)%26
            elif args.decrypt:
                k=(j-key_index_val)%26
            if i.isupper():
                ch=chr(k+ord('A'))
            else:
                ch=chr(k+ord('a'))
            result+=ch
            key_index+=1
            if key_index>=len(key):
                key_index=0
    return result

#AES IMPLEMENTATION
def pkcs7():
    data=text.encode("utf-8")
    len_data=len(data)
    padding_len=16-(len_data%16)
    padding=bytes([padding_len])
    data+=padding*padding_len
    return data

data=pkcs7()

def block_split_data(data):
    state_list=[]
    while len(data)>0:
        block=data[0:16]
        data=data[16:]
        state=[]
        for i in range(4):
            row=[block[i],block[i+4],block[i+8],block[i+12]]
            state.append(row)
        state_list.append(state)
    return state_list

state_list=block_split_data(data)

def xtime(byte):
    msb=byte >> 7
    byte=(byte<<1)&0xFF
    if msb==1:
        byte=byte^0x1B
    return byte

def gmul(a,b):
    result=0
    for i in range(8):
        if b & 1:
            result=result^a
        a=xtime(a)
        b=b>>1
    return result

def multiplicative_inverse(byte):
    if byte==0:
        return 0
    for i in range(1,256):
        if gmul(byte,i)==1:
            return i

def affine_transform(byte):
    result=0
    for i in range(8):
        bit=(
            ((byte>>i) & 1)
            ^((byte>>((i+4)%8))&1)
            ^((byte>>((i+5)%8))&1)
            ^((byte>>((i+6)%8))&1)
            ^((byte>>((i+7)%8))&1)
            ^((0x63>>i)&1)
        )
        result=result|(bit << i)
    return result

def sbox(byte):
    inverse=multiplicative_inverse(byte)
    result=affine_transform(inverse)
    return result

def inv_sbox(value):
    for x in range(256):
        if sbox(x) == value:
            return x

def rotword(word):
    word=list(word)
    word=word[1:]+[word[0]]
    return word

def subword(word):
    result=[]
    for i in word:
        result.append(sbox(i))
    return result

def rcon(round_no):
    value=0x01
    for i in range(1,round_no):
        value=xtime(value)
    return value

def g(word,round_no):
    word=rotword(word)
    word=subword(word)
    word[0]=word[0]^rcon(round_no)
    return word

def key_expansion(key):
    words=[]
    for i in range(0,16,4):
        words.append(key[i:i+4])
    round_keys=[words.copy()]
    for round_no in range(1,11):
        W0=words[-4]
        W1=words[-3]
        W2=words[-2]
        W3=words[-1]
        temp=g(W3,round_no)
        W4=[]
        for i in range(4):
            W4.append(W0[i]^temp[i])
        W5=[]
        for i in range(4):
            W5.append(W1[i]^W4[i])
        W6=[]
        for i in range(4):
            W6.append(W2[i]^W5[i])
        W7=[]
        for i in range(4):
            W7.append(W3[i]^W6[i])
        words.extend([W4,W5,W6,W7])
        round_keys.append([W4,W5,W6,W7])
    return round_keys

def key_matrix(round_key):
    matrix=[]
    for i in range(4):
        row=[]
        for j in range(4):
            row.append(round_key[j][i])
        matrix.append(row)
    return matrix

def add_round_keys(state, key_matrix):
    new_state=[]
    for i in range(4):
        row=[]
        for j in range(4):
            row.append(state[i][j]^key_matrix[i][j])
        new_state.append(row)
    return new_state

def sub_bytes(state):
    new_state=[]
    for i in range(4):
        row=[]
        for j in  range(4):
            row.append(sbox(state[i][j]))
        new_state.append(row)
    return new_state

def inv_sub_bytes(state):
    new_state = []
    for row in state:
        new_row = []
        for value in row:
            new_row.append(inv_sbox(value))
        new_state.append(new_row)
    return new_state

def shift_rows(state):
    new_state=[]
    for i in range(4):
        row=[]
        for j in range(4):
            row.append(state[i][(j+i)%4])
        new_state.append(row)
    return new_state

def inv_shift_rows(state):
    new_state=[]
    for i in range(4):
        row=[]
        for j in range(4):
            row.append(state[i][(j-i)%4])
        new_state.append(row)
    return new_state

def mix_column(state):
    new_state=[[],[],[],[]]
    for i in range(4):
        a=state[0][i]
        b=state[1][i]
        c=state[2][i]
        d=state[3][i]
        new_a=xtime(a)^(xtime(b)^b)^c^d
        new_b=a^xtime(b)^(xtime(c)^c)^d
        new_c=a^b^xtime(c)^(xtime(d)^d)
        new_d=(xtime(a)^a)^b^c^xtime(d)
        new_state[0].append(new_a)
        new_state[1].append(new_b)
        new_state[2].append(new_c)
        new_state[3].append(new_d)
    return new_state

def inv_mix_column(state):
    new_state=[[],[],[],[]]
    for i in range(4):
        a=state[0][i]
        b=state[1][i]
        c=state[2][i]
        d=state[3][i]
        new_a=gmul(a,14)^gmul(b,11)^gmul(c,13)^gmul(d,9)
        new_b=gmul(a,9)^gmul(b,14)^gmul(c,11)^gmul(d,13)
        new_c=gmul(a,13)^gmul(b,9)^gmul(c,14)^gmul(d,11)
        new_d=gmul(a,11)^gmul(b,13)^gmul(c,9)^gmul(d,14)
        new_state[0].append(new_a)
        new_state[1].append(new_b)
        new_state[2].append(new_c)
        new_state[3].append(new_d)
    return new_state

def state_to_bytes(state):
    data=[]
    for i in range(4):
        for j in range(4):
            data.append(state[j][i])
    return(bytes(data))

def aes_encrypt():
    key=args.key.encode("utf-8")
    if len(key)!=16:
        raise ValueError("AES-128 key must be exactly 16 bytes")
    round_keys=key_expansion(key)
    ciphertext=b''
    for state in state_list:
        k0_matrix=key_matrix(round_keys[0])
        state=add_round_keys(state,k0_matrix)
        for i in range(1,10):
            state=sub_bytes(state)
            state=shift_rows(state)
            state=mix_column(state)
            key_mat=key_matrix(round_keys[i])
            state=add_round_keys(state,key_mat)
        state=sub_bytes(state)
        state=shift_rows(state)
        k10_matrix=key_matrix(round_keys[10])
        state=add_round_keys(state,k10_matrix)
        ciphertext+=state_to_bytes(state)
    return ciphertext

def aes_decrypt(ciphertext):
    key=args.key.encode("utf-8")
    if len(key)!=16:
        raise ValueError("AES-128 key must be exactly 16 bytes")
    round_keys=key_expansion(key)
    if len(ciphertext)==0 or len(ciphertext)%16!=0:
        raise ValueError("Invalid ciphertext length")
    plaintext=b''
    state_list=block_split_data(ciphertext)
    for state in state_list:
        k10_matrix=key_matrix(round_keys[10])
        state=add_round_keys(state,k10_matrix)
        for round_no in range(9,0,-1):
            state=inv_shift_rows(state)
            state=inv_sub_bytes(state)
            key_mat=key_matrix(round_keys[round_no])
            state=add_round_keys(state,key_mat)
            state=inv_mix_column(state)
        state=inv_shift_rows(state)
        state=inv_sub_bytes(state)
        k0_matrix=key_matrix(round_keys[0])
        state=add_round_keys(state,k0_matrix)
        plaintext+=state_to_bytes(state)
    return plaintext

def unpad(data):
    if not data:
        raise ValueError("Invalid padding")
    padding_len=data[-1]
    if padding_len<1 or padding_len>16:
        raise ValueError("Invalid padding")
    if data[-padding_len:] != bytes([padding_len])*padding_len:
        raise ValueError("Invalid padding")
    return data[:-padding_len]

if args.cipher=='vigenere':
    output=vigenere()
    print(output)
if args.cipher=='aes':
    if args.encrypt:
        ciphertext=aes_encrypt()
        if args.output=='hex':
            print(ciphertext.hex())
        elif args.output=='base64':
            print(base64.b64encode(ciphertext).decode())
    elif args.decrypt:
        if args.output=='hex':
            ciphertext=bytes.fromhex(text)
        elif args.output=='base64':
            ciphertext=base64.b64decode(text, validate=True)
        plaintext=aes_decrypt(ciphertext)
        plaintext=unpad(plaintext)
        print(plaintext.decode("utf-8"))