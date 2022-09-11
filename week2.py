 
from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii
 
# keys and ciphertexts are hex-encoded.
keys = ["140b41b22a29beb4061bda66b6747e14",
        "140b41b22a29beb4061bda66b6747e14",
        "36f18357be4dbd77f050515c73fcf9f2",
        "36f18357be4dbd77f050515c73fcf9f2"]
ciphertexts =["4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81",
              "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253",
              "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329",
              "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"]


def decrypt_cbc(ciphertext, key):
    """
    Perform AES CBC decryption with PKCS5 Padding.   (bytes, bytes) -> string
    """
    iv = ciphertext[:AES.block_size]
    iv_stripped_cipher = ciphertext[AES.block_size:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    plaintext = aes.decrypt(iv_stripped_cipher)
    plaintext = str(plaintext, 'ascii') 
    # Note the result needs padding => 
# b'Basic CBC mode encryption needs padding.\x08\x08\x08\x08\x08\x08\x08\x08' => "Basic CBC mode encryption needs padding.\b\b\b\b\b\b\b\b"
    plaintext = plaintext[:-ord(plaintext[-1])]
    return plaintext


def decrypt_ctr(ciphertext, key):
    """
    Perform AES CTR decryption using Counter mechanism. (bytes, bytes) -> string 
    """
    iv = ciphertext[:AES.block_size]
    ctr = Counter.new(128, initial_value=int(binascii.hexlify(iv), 16))
    iv_stripped_cipher = ciphertext[AES.block_size:]
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    plaintext = aes.decrypt(iv_stripped_cipher)
    plaintext = str(plaintext, 'ascii')
    return plaintext


 
key_unhex = [binascii.unhexlify(element) for element in keys]
cipher_text_unhex = [binascii.unhexlify(element) for element in ciphertexts]

plaintext1 = decrypt_cbc(cipher_text_unhex[0], key_unhex[0])
plaintext2 = decrypt_cbc(cipher_text_unhex[1], key_unhex[1])

plaintext3 = decrypt_ctr(cipher_text_unhex[2], key_unhex[2])
plaintext4 = decrypt_ctr(cipher_text_unhex[3], key_unhex[3])

print("Answer:", plaintext1 )
print("Answer:", plaintext2 )
print("Answer:", plaintext3 )
print("Answer:", plaintext4 )

 