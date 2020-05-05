from Crypto.Cipher import DES
from Crypto import Random
from Crypto.Util import Counter
from base64 import b64decode,b64encode
import json

inputFile = "test1.enc"
outputFile = "test1.out"
inputPassword = b'12345678'

inputFile = open(inputFile)
outputFile = open(outputFile,mode="w")
jsonData = json.loads(inputFile.readline())

key = inputPassword
nonce = b64decode(jsonData['nonce'])
ct = b64decode(jsonData['ciphertext'])

# # 32-bit counter
ctr = Counter.new(DES.block_size*4, prefix=nonce)
cipher = DES.new(key, DES.MODE_CTR, counter=ctr)

data = cipher.decrypt(ct).decode()

print(("%s") % (data))
outputFile.write(data)
outputFile.close()