from Crypto.Cipher import DES
from Crypto import Random
from Crypto.Util import Counter
from hashlib import pbkdf2_hmac,sha1
from base64 import b64encode

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

def do_tests(ct):
    k = b'\x0b' * 20
    result = hmac_sha1(k, ct)
    return result

inputFile = "test1.txt"
outputFile = "test1.enc"
inputPassword = '12345678'

inputFile = open(inputFile)
outputFile = open(outputFile,mode="w")
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

nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(ct).decode('utf-8')
hmac = b64encode(do_tests(ct.encode())).decode('utf-8')

print("Nonce:",nonce)
print("Ciphertext:",ct)
print("HMAC:",hmac)

msg = nonce + ct + hmac

print(("Ciphertext:%s") % (msg))
outputFile.write(msg)
outputFile.close()