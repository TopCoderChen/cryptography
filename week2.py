from Crypto.Cipher import AES
from Crypto.Util import Counter

# Note: the key and IV must be 16-byte, everything should be byte.

def show_plaintext(MODE, hex_ciphertext, hex_key):
    iv_hex = hex_ciphertext[:32] 
    iv = bytes.fromhex(iv_hex)
    key = bytes.fromhex(hex_key)
    if MODE == AES.MODE_CBC:
        obj  = AES.new(key, MODE, iv)
    elif MODE == AES.MODE_CTR:
        ctr = Counter.new(128, initial_value=int(iv_hex, 16))
        obj  = AES.new(key, MODE, counter=ctr)
    bt = obj.decrypt(bytes.fromhex(hex_ciphertext[32:]))
    plaintext = bt.decode()
    print(plaintext)

# def utf8len(s):  # just for debug
#     return len(s.encode('utf-8'))
# print(utf8len(iv_hex))

cbc_key_cipher_pairs = [
# Note the result needs padding => 
# b'Basic CBC mode encryption needs padding.\x08\x08\x08\x08\x08\x08\x08\x08' => "Basic CBC mode encryption needs padding.\b\b\b\b\b\b\b\b"
('140b41b22a29beb4061bda66b6747e14', '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'),
('140b41b22a29beb4061bda66b6747e14', '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'),
]

for key, cipher in cbc_key_cipher_pairs:
    show_plaintext(AES.MODE_CBC, cipher, key)


ctr_key_cipher_pairs = [
('36f18357be4dbd77f050515c73fcf9f2', '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'),
('36f18357be4dbd77f050515c73fcf9f2', '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'),
]

for key, cipher in ctr_key_cipher_pairs:
    show_plaintext(AES.MODE_CTR, cipher, key)
