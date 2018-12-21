from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto import Random

import binascii


random_gen = Random.new().read
private_key = RSA.generate(1024, random_gen)
public_key = private_key.publickey()


# message = 'To be encrypted'
message = 'To be encrypted.'
# h = SHA.new(message.encode('ascii'))
h = SHA.new(message.encode('ascii'))

print('original message')
print('len', len(message), message)
print()

cipher = PKCS1_v1_5.new(public_key)
ciphertext = cipher.encrypt(message.encode('ascii')+h.digest())

print('encrypted message')
print(type(ciphertext), ciphertext)
print()

ciphertext = binascii.hexlify(ciphertext).decode('ascii')

print(type(ciphertext), ciphertext)
print()

ciphertext = binascii.unhexlify(ciphertext)

dsize = SHA.digest_size
sentinel = Random.new().read(15+dsize)

cipher = PKCS1_v1_5.new(private_key)
message = cipher.decrypt(ciphertext, sentinel)

digest = SHA.new(message[:-dsize]).digest()

if digest == message[-dsize:]:
  print("correct")
  print(message[:-dsize].decode('utf8'))
else:
  print("not correct")

