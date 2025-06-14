import pickle
import os
from datetime import datetime
from mife.multiclient.damgard import FeDamgardMultiClient

class T_server:
    def __init__(self, n_clients=3, vector_size=3, keys_directory="keys/"):
        self.keys_directory = keys_directory
        self.n_clients = n_clients
        self.vector_size = vector_size

        os.makedirs(keys_directory, exist_ok=True)
        
        # Charger les clés existantes ou en générer de nouvelles
        self.key = self._load_or_generate_master_keys()
        
        # Dictionnaire pour stocker les clés fonctionnelles générées
        self.functional_keys = {}


    def _load_or_generate_master_keys(self):
        """Charge les clés maîtres ou les génère si elles n'existent pas"""
        master_key_path = os.path.join(self.keys_directory, "master_key.pkl")
        
        if os.path.exists(master_key_path):
            print("🔑 Chargement des clés maîtres existantes...")
            with open(master_key_path, 'rb') as f:
                return pickle.load(f)
        else:
            print("🔑 Génération de nouvelles clés maîtres...")
            key = FeDamgardMultiClient.generate(self.n_clients, self.vector_size)
            
            # Sauvegarder immédiatement
            with open(master_key_path, 'wb') as f:
                pickle.dump(key, f)
            
            return key
        
    def save_functional_key(self, function_id, function_vector, sk):
        """Sauvegarde une clé fonctionnelle pour réutilisation"""
        key_info = {
            'function_vector': function_vector,
            'functional_key': sk,
            'created_at': datetime.now(),
            'function_id': function_id
        }
        
        # Sauvegarder en mémoire
        self.functional_keys[function_id] = key_info
        
        # Sauvegarder sur disque
        func_key_path = os.path.join(self.keys_directory, f"func_key_{function_id}.pkl")
        with open(func_key_path, 'wb') as f:
            pickle.dump(key_info, f)
    
    def load_functional_key(self, function_id):
        """Charge une clé fonctionnelle existante"""
        if function_id in self.functional_keys:
            return self.functional_keys[function_id]['functional_key']
        
        func_key_path = os.path.join(self.keys_directory, f"func_key_{function_id}.pkl")
        if os.path.exists(func_key_path):
            with open(func_key_path, 'rb') as f:
                key_info = pickle.load(f)
                self.functional_keys[function_id] = key_info
                return key_info['functional_key']
        
        return None
    

    def get_pub_key(self):
        return self.key.get_public_key()
        
    def ask_key(self, client_id=None):
        if client_id is not None and 0 <= client_id < self.n_clients:  # Ajouter vérification >= 0
            return self.key.get_enc_key(client_id)
        else:
            raise ValueError(f"Client ID invalide: {client_id}")
    

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