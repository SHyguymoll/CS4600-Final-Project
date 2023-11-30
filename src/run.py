from cryptography.hazmat.primitives.asymmetric import rsa, keywrap, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os
import sys

AES_KEY_SIZE = 256

def main():
    sendCli = client()
    recvCli = client()
    sendCli.add_client(recvCli, True)
    

def client():
    def __init__(self):
        self.rsa_key_pair = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.connected_client : client
        self.messages = []
        self.known_clients = []
    
    def get_pub_key(self) -> rsa.RSAPublicKey:
        return self.rsa_key_pair.public_key()
    
    def add_client(self, other: client, first: bool) -> None:
        self.known_clients.append({other, other.get_pub_key()})
        if first:
            other.add_client(self, False)
    
    def send_message(self, msg_location: str, recipient: client) -> None:
        if recipient not in self.known_clients:
            print(f"error, {recipient} is not known, aborting.")
            return
        # initializing and creating AES key with initialization vector (both random)
        picked_aes_key = algorithms.AES(os.urandom(AES_KEY_SIZE))
        iv = modes.CBC(os.urandom(16))
        # opening message from file
        message_file = open(msg_location)
        message = message_file.readline().encode()
        message_file.close()
        
        # AES encryption of message
        ciph = Cipher(picked_aes_key, iv)
        enc = ciph.encryptor()
        enc_message = enc.update(message) + enc.finalize()
        
        # RSA Public Key encryption of AES key
        aes_transmit : bytes = recipient.get_pub_key().encrypt(
            picked_aes_key,
            padding.OAEP(
                padding.MGF1(hashes.SHA256()),
                hashes.SHA256()
            )
        )
        self.connected_client.messages.append()
        

if __name__ == "__main__":
    main()