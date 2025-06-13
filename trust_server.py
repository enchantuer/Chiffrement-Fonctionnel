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

    def functional_keygen(self, y):
        return FeDamgardMultiClient.keygen(y, self.key)
    


    def authorize_function_request(self, requester_id, function_type, data_owners):
        """Vérifie si requester_id peut calculer function_type sur les données de data_owners"""
        pass

    def create_policy(self, data_owner, authorized_functions, authorized_users):
        """Permet aux propriétaires de données de définir qui peut calculer quoi"""
        pass

    def authenticate_client(self, client_id, credentials):
        """Vérifie l'identité avant de donner les clés"""
        pass

    def register_client(self, client_info):
        """Enregistre un nouveau client dans le système"""
        pass

    def log_key_distribution(self, client_id, key_type):
        """Trace qui a reçu quelles clés"""
        pass

    def log_function_key_generation(self, requester, function_vector):
        """Trace quelles fonctions ont été autorisées"""
        pass

    def get_sum_key(self, n_clients, vector_size):
        """Génère la clé pour calculer une somme"""
        y = [[1 for j in range(vector_size)] for i in range(n_clients)]
        return self.functional_keygen(y)

    def get_mean_key(self, n_clients, vector_size):
        """Génère la clé pour calculer une moyenne"""
        return self.get_sum_key(n_clients, vector_size)  # Même clé, division après

    def get_correlation_keys(self, n_clients, vector_size):
        """Génère les 3 clés nécessaires pour calculer une corrélation"""
        # Retourne (xy_key, xx_key, sum_key)
        pass