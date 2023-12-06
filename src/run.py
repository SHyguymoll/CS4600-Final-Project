from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import os
import random
import sys
import requests

AES_KEY_BIT_SIZE = 256
SYSTEM_IV = modes.CBC(os.urandom(16))
SYSTEM_HMAC_KEY = os.urandom(32)

def main():
    print(sys.argv)
    if len(sys.argv) != 2:
        print("Usage: python run.py <message_filepath>")
        return
    name_one = requests.get("https://random-word-api.herokuapp.com/word").json()[0]
    name_two = requests.get("https://random-word-api.herokuapp.com/word").json()[0]
    sendCli = client(name_one)
    recvCli = client(name_two)
    sendCli.send_message(sys.argv[1], recvCli)
    

class client():
    name : str
    rsa_key_pair : rsa.RSAPrivateKey
    
    def __str__(self):
        return self.name
    
    def __init__(self, name: str | None):
        if name is None:
            self.name = random.choice(["Andy", "Alex", "Blair", "Royal", "Arron", "Ashley", "Tory", "Cecil", "Marley", "Cody"])
        else:
            self.name = name
        self.rsa_key_pair = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    
    def get_pub_key(self) -> rsa.RSAPublicKey:
        return self.rsa_key_pair.public_key()
    
    def create_mac(*args):
        hmac_sys = hmac.HMAC(SYSTEM_HMAC_KEY, hashes.SHA256())
        for data in args[1:]:
            hmac_sys.update(data)
        mac = hmac_sys.finalize()
        return mac
    
    def send_message(self, msg_location: str, recipient) -> None:
        # initializing and creating AES key with initialization vector (both random)
        picked_aes_key = algorithms.AES(bytes(os.urandom(AES_KEY_BIT_SIZE//8)))
        
        # opening message from file
        message_file = open(msg_location)
        message = message_file.readline().encode()
        message_file.close()
        if len(message) == 0:
            print("message has no content, aborting.")
            return
        
        # AES encryption of message, see https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
        ciph = Cipher(picked_aes_key, SYSTEM_IV)
        enc = ciph.encryptor()
        
        # Data padding, see https://www.askpython.com/python/examples/implementing-aes-with-padding
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message) + padder.finalize()
        enc_message = enc.update(padded_data) + enc.finalize()
        
        # RSA Public Key encryption of AES key, see https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption
        aes_transmit = recipient.get_pub_key().encrypt(
            picked_aes_key.key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Creating HMAC of encrypted message and AES key
        mac = self.create_mac(enc_message, aes_transmit)
        # Sending message to recipient
        print(self, "is sending", message, "to", recipient)
        recipient.recieve_message((enc_message, aes_transmit, mac), self)
    
    def recieve_message(self, message_block: tuple, sender):
        # Print received data
        print(f"{self} recieved {str(message_block)[0:7]}...{str(message_block)[len(str(message_block))-7:len(str(message_block))]} from {sender}")
        
        enc_msg, aes_trans, mac = message_block
        
        # MAC check
        comp_mac = self.create_mac(enc_msg, aes_trans)
        if comp_mac != mac:
            print("MAC comparison failed! Aborting decryption.")
            return
        
        # Decrypt AES key
        aes_recv = self.rsa_key_pair.decrypt(
            aes_trans,
            padding.OAEP(
                padding.MGF1(hashes.SHA256()),
                hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt message
        ciph = Cipher(algorithms.AES(aes_recv), SYSTEM_IV)
        dec = ciph.decryptor()
        dec_message = dec.update(enc_msg) + dec.finalize()
        
        # Print message
        print("decrypted encrypted message as", dec_message)

if __name__ == "__main__":
    main()