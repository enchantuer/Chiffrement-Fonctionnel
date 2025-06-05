from mife.multiclient.damgard import FeDamgardMultiClient

class T_server:
    def __init__(self, n_clients=3, vector_size=3):
        self.n_clients = n_clients
        self.vector_size = vector_size
        self.key = FeDamgardMultiClient.generate(n_clients, vector_size)

    def get_pub_key(self):
        return self.key.get_public_key()

    def ask_key(self, client_id=None):
        if client_id < self.n_clients:
            return self.key.get_enc_key(client_id)
        else:
            raise ValueError("Client ID invalide")

    def derive_functional_key(self, y_vector):
        return FeDamgardMultiClient.derive_key(y_vector, self.key.get_secret_key())
