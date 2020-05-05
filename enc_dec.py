from Crypto.Cipher import DES
from Crypto import Random
from Crypto.Util import Counter
from hashlib import pbkdf2_hmac,sha1
from base64 import b64decode, b64encode
from os.path import splitext

def xor(x, y):
    return bytes(x[i] ^ y[i] for i in range(min(len(x), len(y))))

def hmac_sha1(key_K, data):
    if len(key_K) > 64:
        raise ValueError('The key must be <= 64 bytes in length')
    padded_K = key_K + b'\x00' * (64 - len(key_K))
    ipad = b'\x36' * 64
    opad = b'\x5c' * 64
    h_inner = sha1(xor(padded_K, ipad))
    h_inner.update(data)
    h_outer = sha1(xor(padded_K, opad))
    h_outer.update(h_inner.digest())
    return h_outer.digest()

def calculate_hmac(ct):
    k = b'\x0b' * 20
    result = hmac_sha1(k, ct)
    return result

def encrypt(inputFilePath,inputPassword):
    encFilePath = splitext(inputFilePath)[0] + '.enc'

    try:
        inputFile = open(inputFilePath)
    except OSError as err:
        return {"error":True,"title":"File not found","msg":"Input file doesn't exist"}

    encFile = open(encFilePath,'w')

    lines = inputFile.readlines()
    data = ''.join(lines).encode()

    # b64encode(hashlib.sha256(salt.encode() + password.encode()).digest())
    key = pbkdf2_hmac('sha256',inputPassword.encode(),''.encode(),10000,8)
    # 4-byte nonce
    nonce = Random.new().read(int(DES.block_size/2))
    # 32-bit counter
    ctr = Counter.new(DES.block_size*4, prefix=nonce)

    cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
    ct = cipher.encrypt(data)

    key = b64encode(key).decode('utf-8')
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct).decode('utf-8')
    hmac = b64encode(calculate_hmac(ct.encode())).decode('utf-8')

    print("Key:",key)
    print("Nonce:",nonce)
    print("Ciphertext:",ct)
    print("HMAC:",hmac)

    msg = key + nonce + ct + hmac

    print("Encryption is completed successfully\n\n")
    encFile.write(msg)
    inputFile.close()
    encFile.close()
    return {"error":False,"title":"Success","msg":"File is encrypted successfully\nEncrypted file is stored at the same folder with .enc extension"}


def decrypt(encFilePath,inputPassword):
    encryptedFilePathObj = splitext(encFilePath)
    decFilePath = encryptedFilePathObj[0] + '-out.txt'

    try:
        encFile = open(encryptedFilePathObj[0]+'.enc')
    except OSError as err:
        return {"error":True,"title":"File not found","msg":"Encrypted file doesn't exist"}

    decFile = open(decFilePath,mode="w")   
    encData = encFile.read()
    key = encData[0:12]
    nonce = encData[12:20]
    ct = encData[20:-28]
    hmac = encData[len(key)+len(nonce)+len(ct):]

    print("Received:",encData)
    print("Key:",key)
    print("Nonce:",nonce)
    print("Ciphertext:",ct)
    print("HMAC:",hmac)
    
    try:
        key = b64decode(key)
        inputKey = pbkdf2_hmac('sha256',inputPassword.encode(),''.encode(),10000,8)

        if not(inputKey == key):
            return {"error":True,"title":"Incorrect Password","msg":"Please enter the correct password"}

        inputHMAC = calculate_hmac(ct.encode())
        nonce = b64decode(nonce)
        ct = b64decode(ct)
        hmac = b64decode(hmac)

    except BaseException as err:
        return {"error":True,"title":"Changed File","msg":"The encrypted file has been changed"}

    if not(inputHMAC == hmac):
        return {"error":True,"title":"Changed File","msg":"The encrypted file has been changed"}

    # # 32-bit counter
    ctr = Counter.new(DES.block_size*4, prefix=nonce)
    cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
    data = cipher.decrypt(ct).decode()

    print("Decryption is completed successfully")
    decFile.write(data)
    encFile.close()
    decFile.close()
    return {"error":False,"title":"Success","msg":"File is decrypted successfully\nDecrypted file is stored at the same folder with postfix -out.txt extension"}