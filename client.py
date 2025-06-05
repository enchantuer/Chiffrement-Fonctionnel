from mife.multiclient.damgard import FeDamgardMultiClient
from trust_server import T_server

class Client:
    def __init__(self, client_id, T_server):
        self.client_id = client_id
        """Récupère la clé fonctionne grâce au serveur de confiance"""
        self.pub_key = T_server.get_pub_key()
        self.enc_key = T_server.ask_key(client_id)

    def encrypt_and_send(self, data, tag):
        cipher = FeDamgardMultiClient.encrypt(data, tag, self.enc_key, self.pub_key)
        with open(f"db/client{self.client_id}_data.bin", "wb") as f:
            f.write(cipher.export())
        return cipher
