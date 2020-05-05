from Crypto.Cipher import DES
from Crypto import Random
from Crypto.Util import Counter
from base64 import b64encode
import json

inputFile = "test1.txt"
outputFile = "test1.enc"
inputPassword = b'12345678'

inputFile = open(inputFile)
outputFile = open(outputFile,mode="w")
lines = inputFile.readlines()
data = ''.join(lines).encode()
key = inputPassword

# 4-byte nonce
nonce = Random.new().read(int(DES.block_size/2))
# 32-bit counter
ctr = Counter.new(DES.block_size*4, prefix=nonce)

cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
ct = cipher.encrypt(data)

nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(ct).decode('utf-8')
msg = json.dumps({'nonce':nonce, 'ciphertext':ct})

print(("Ciphertext:%s") % (msg))
outputFile.write(msg)
outputFile.close()