from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import os
import random
import sys
import requests

AES_KEY_LENGTH = 32
AES_IV_LENGTH = 16
HMAC_KEY_LENGTH = 32

CLIENT_ID_LENGTH = 8

def main():
    print(sys.argv)
    if len(sys.argv) != 2:
        print("Usage: python run.py <message_filepath>")
        return
    sendCli = client()
    recvCli = client()
    sendCli.send_message(sys.argv[1], recvCli)
    

class client():
    name : str
    rsa_key_pair : rsa.RSAPrivateKey
    uniq_id : int
    
    def __str__(self):
        return f"{self.name} ({self.uniq_id})"
    
    def __eq__(self, other):
        if isinstance(other, client):
            return self.uniq_id == other.uniq_id
        return False
    
    def __init__(self, name: str = None):
        if name is None:
            # This was more for me than the project
            self.name = requests.get("https://random-word-api.herokuapp.com/word").json()[0]
        else:
            self.name = name
        self.rsa_key_pair = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.uniq_id = int.from_bytes(os.urandom(CLIENT_ID_LENGTH), sys.byteorder)
    
    def get_pub_key(self) -> rsa.RSAPublicKey:
        return self.rsa_key_pair.public_key()
    
    def create_mac(self, hmac_key, to_mac):
        hmac_sys = hmac.HMAC(hmac_key, hashes.SHA256())
        for data in to_mac:
            hmac_sys.update(data)
        mac = hmac_sys.finalize()
        return mac
    
    def send_message(self, msg_location: str, recipient) -> None:
        # initializing and creating AES key with initialization vector (both random)
        picked_aes_key = algorithms.AES(os.urandom(AES_KEY_LENGTH))

        picked_iv = os.urandom(AES_IV_LENGTH)
        picked_hmac_key = os.urandom(HMAC_KEY_LENGTH)
        
        # opening message from file
        message_file = open(msg_location)
        message = message_file.readline().encode()
        message_file.close()
        if len(message) == 0:
            print("message has no content, aborting.")
            return
        
        # Data padding, see https://www.askpython.com/python/examples/implementing-aes-with-padding
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message) + padder.finalize()

        # AES encryption of message, see https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
        ciph = Cipher(picked_aes_key, modes.CBC(picked_iv))
        enc = ciph.encryptor()
        enc_message = enc.update(padded_data) + enc.finalize()
        
        # RSA Public Key encryption of AES key, see https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption
        aes_key_transmit = recipient.get_pub_key().encrypt(
            picked_aes_key.key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Ditto encryption of AES IV and HMAC key
        aes_iv_transmit = recipient.get_pub_key().encrypt(
            picked_iv,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        h_key_transmit = recipient.get_pub_key().encrypt(
            picked_hmac_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Creating HMAC of encrypted message and AES key
        mac = self.create_mac(picked_hmac_key, (enc_message, aes_key_transmit, aes_iv_transmit, h_key_transmit))
        # Sending message to recipient
        print(self, "is sending", message, "to", recipient)
        recipient.recieve_message((enc_message, aes_key_transmit, aes_iv_transmit, h_key_transmit, mac), self)
    
    def recieve_message(self, message_block: tuple, sender):
        # Print received data
        print(f"{self} recieved {message_block} from {sender}")
        
        enc_msg, aes_key_trans, aes_iv_trans, h_key_trans, mac = message_block
        # Decrypt HMAC key
        hmac_key_recv = self.rsa_key_pair.decrypt(
            h_key_trans,
            padding.OAEP(
                padding.MGF1(hashes.SHA256()),
                hashes.SHA256(),
                label=None
            )
        )

        # MAC check
        comp_mac = self.create_mac(hmac_key_recv, (enc_msg, aes_key_trans, aes_iv_trans, h_key_trans))
        if comp_mac != mac:
            print("MAC comparison failed! Aborting decryption.")
            return
        
        # Decrypt AES key and AES iv
        aes_key_recv = self.rsa_key_pair.decrypt(
            aes_key_trans,
            padding.OAEP(
                padding.MGF1(hashes.SHA256()),
                hashes.SHA256(),
                label=None
            )
        )
        aes_iv_recv = self.rsa_key_pair.decrypt(
            aes_iv_trans,
            padding.OAEP(
                padding.MGF1(hashes.SHA256()),
                hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt message
        ciph = Cipher(algorithms.AES(aes_key_recv), modes.CBC(aes_iv_recv))
        dec = ciph.decryptor()
        dec_message = dec.update(enc_msg) + dec.finalize()
        
        # Remove padding from message
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_message = unpadder.update(dec_message) + unpadder.finalize()
        
        # Print message
        print(self, "decrypted encrypted message as", unpadded_message)

if __name__ == "__main__":
    main()