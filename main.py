import des

inputFile = "test1.txt"
inputPassword = b'12345678'

inputFile = open(inputFile)
lines = inputFile.readlines()
data = ''.join(lines).encode()

key = des.DesKey(inputPassword)
encrypted = key.encrypt(data , padding=True)
decrypted = key.decrypt(encrypted, padding=True)

print(decrypted==data)