import Crypto
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto import Random

import binascii


def decrypt_record(encrypted_data, private_key):
    private_key = RSA.importKey(binascii.unhexlify(private_key))
    dsize = SHA.digest_size
    # Let's assume that average data length is 15
    sentinel = Crypto.Random.new().read(15+dsize)
    cipher = PKCS1_v1_5.new(private_key)
    message = cipher.decrypt(binascii.unhexlify(encrypted_data), sentinel)
    digest = SHA.new(message[:-dsize]).digest()

    if digest == message[-dsize:]:
        return message[:-dsize].decode('ascii')
    else:
        return False


ciphertext = input('Enter ciphertext: ')
# private_key = input('Enter private key: ')
private_key = '3082025d02010002818100fd2003a0380122e75453bf42590225c42eccde4d69c3d9cc2082ab612553a6fdb8cdd3aa336b824774fccb2840eeabdb739cae64d9259df7ac72138067ae616ae5a9993711ee3c0d780f3041f5b46b2a8d8af960d8da97d1668e3874a1628bcea40d84e336d0061b2897e84c491b9fc7ebd21fe3526d91218339bf45f0bb5167020301000102818100a654b82d3b3ffbe898f02338fcf63d4cea17f368593cba4cb97c4413a50c902a1f9b1920b98346eb9fc351d854bac131868a09caf92a0fe0a56f9cc2fede86e20214269bfe9dc2a5effa32153bd409f49691030b1e5381a3a64e476373cf9ef231f010a6d09394be2b97936e856cbb4a824f682d5d7649b9499b18df1367cdb9024100fd2cbcfc210afd48baee1def25f449ccd5ea641364434487a8d1f2263d470cfec05426cbf313295195bb83ab1507c45618fb4899c2481e35ecbc65598e8ac8dd024100fff3224a915652bff19cc6bc9093a008a475691dc5bad80d3872bfb7e4945dca9c8c8c66365192fce582432c681d3ec9a7eeab698efbb49c0ae1773a8edcfd13024100cc1d169c5b7385b2ee6a6d9dd246ba7d3775ca8b4bc963e5cf78bc36922ec74e57f740742b9c2632cd7a297473f71816a5fb6993f56bb957966e6973a39546cd0240296dc16f3077388db91e174d0e59d6dd8f4131f28fbede99c5394daf0660bd8dbe2941d0899a4aa084c5c0f9bf207cb947656a797b9b62709f923f2a4b5599e1024059c09ca4c65c514597b71006307a8164f094dca84debda1110e271b0e9036ae0fbe16a83c29f017018041ad90dfd4103ed8dfcd431ab4af63c215dbd4356df79'

result = decrypt_record(ciphertext, private_key)
print('\nDecrypt message: ', result)