from Crypto.Cipher import DES
from Crypto import Random
from Crypto.Util import Counter
from base64 import b64decode,b64encode
from hashlib import pbkdf2_hmac

encFile = "test1.enc"
decFile = "test1.out"
inputPassword = '12345678'

encFile = open(encFile)
decFile = open(decFile,mode="w")
encData = encFile.read()
nonce = encData[0:8]
ct = encData[8:-28]
hmac = encData[len(nonce)+len(ct):]

print("Received:",encData)
print("Nonce:",nonce)
print("Ciphertext:",ct)
print("HMAC:",hmac)

key = pbkdf2_hmac('sha256',inputPassword.encode(),''.encode(),10000,8)
nonce = b64decode(nonce)
ct = b64decode(ct)

# # 32-bit counter
ctr = Counter.new(DES.block_size*4, prefix=nonce)
cipher = DES.new(key, DES.MODE_CTR, counter=ctr)

data = cipher.decrypt(ct).decode()

print(("%s") % (data))
decFile.write(data)
decFile.close()