from cryptography.hazmat.primitives.asymmetric import rsa, keywrap, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import os
import sys

AES_KEY_SIZE = 256
SYSTEM_IV = modes.CBC(os.urandom(16))
SYSTEM_HMAC_KEY = os.urandom(32)

def main():
    sendCli = client()
    recvCli = client()
    sendCli.add_client(recvCli, True)
    

def client():
    rsa_key_pair : rsa.RSAPrivateKey
    known_clients = []
    def __init__(self):
        rsa_key_pair = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    
    def get_pub_key(self) -> rsa.RSAPublicKey:
        return self.rsa_key_pair.public_key()
    
    def add_client(self, other: client, first: bool) -> None:
        self.known_clients.append({other, other.get_pub_key()})
        if first:
            other.add_client(self, False)
    
    def create_mac(*args):
        hmac_sys = hmac.HMAC(SYSTEM_HMAC_KEY, hashes.SHA256())
        for data in args: hmac_sys.update(data)
        mac = hmac_sys.finalize()
        return mac
    
    def send_message(self, msg_location: str, recipient: client) -> None:
        if recipient not in self.known_clients:
            print(f"error, {recipient} is not known, aborting.")
            return
        # initializing and creating AES key with initialization vector (both random)
        picked_aes_key = algorithms.AES(os.urandom(AES_KEY_SIZE))
        
        # opening message from file
        message_file = open(msg_location)
        message = message_file.readline().encode()
        message_file.close()
        
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
        mac = create_mac(enc_message, aes_transmit)
        # Sending message to recipient
        recipient.recieve_message((enc_message, aes_transmit, mac), self)
    
    def recieve_message(self, message_block: tuple, sender: client):
        if sender not in self.known_clients:
            print("Unknown sender! Aborting decryption.")
        enc_msg, aes_trans, mac = message_block
        comp_mac = create_mac(enc_msg, aes_trans)
        if comp_mac != mac:
            print("MAC comparison failed! Aborting decryption.")
            return
        
        

if __name__ == "__main__":
    main()