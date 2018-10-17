from os import chmod
from Crypto.PublicKey import RSA

key = RSA.generate(2048)
with open('private.pem', 'wb') as f:
    chmod('private.pem', 600)
    f.write(key.exportKey('PEM'))

pubkey = key.publickey()
with open('public.pem', 'wb') as f:
    f.write(pubkey.exportKey('OpenSSH'))
