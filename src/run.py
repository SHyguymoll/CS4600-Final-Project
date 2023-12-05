from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import os
import random
import sys

AES_KEY_SIZE = 32
SYSTEM_IV = modes.CBC(os.urandom(16))
SYSTEM_HMAC_KEY = os.urandom(32)

def main():
    print(sys.argv)
    if len(sys.argv) != 2:
        print("Usage: python run.py <message_filepath>")
        return
    sendCli = client(None)
    recvCli = client(None)
    sendCli.send_message(sys.argv[1], recvCli)
    

class client():
    name : str
    rsa_key_pair : rsa.RSAPrivateKey
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
        for data in args: hmac_sys.update(data)
        mac = hmac_sys.finalize()
        return mac
    
    def send_message(self, msg_location: str, recipient) -> None:
        # initializing and creating AES key with initialization vector (both random)
        picked_aes_key = algorithms.AES(bytes(os.urandom(AES_KEY_SIZE)))
        
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
        enc_message = enc.update(message) + enc.finalize()
        
        # RSA Public Key encryption of AES key, see https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption
        aes_transmit : bytes = recipient.get_pub_key().encrypt(
            picked_aes_key,
            padding.OAEP(
                padding.MGF1(hashes.SHA256()),
                hashes.SHA256()
            )
        )
        
        # Creating HMAC of encrypted message and AES key
        mac = self.create_mac(enc_message, aes_transmit)
        # Sending message to recipient
        recipient.recieve_message((enc_message, aes_transmit, mac), self)
    
    def recieve_message(self, message_block: tuple, sender):
        # Print received data
        print(f"recieved {message_block} from {sender}")
        
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
                hashes.SHA256()
            )
        )
        
        # Decrypt message
        ciph = Cipher(aes_recv, SYSTEM_IV)
        dec = ciph.decryptor()
        dec_message = dec.update(enc_msg) + dec.finalize()
        
        # Print message
        print(dec_message)

if __name__ == "__main__":
    main()