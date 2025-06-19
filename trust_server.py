import pickle
import os
from datetime import datetime
from mife.multiclient.damgard import FeDamgardMultiClient

import socket
import ssl
import threading
import re

HOST = 'localhost'
PORT = 1560

CERTFILE = 'certs/trust_server/server.cert'
KEYFILE = 'certs/trust_server/server.key'
CA = 'certs/ca/ca.cert'

KEYS = "keys/"

def extract_client_id(cn: str) -> int | None:
    match = re.fullmatch(r"client_(\w+)", cn)
    if match:
        return int(match.group(1))
    return None

class TrustServer:
    def __init__(self, n_clients=3, vector_size=3, host=HOST, port=PORT, keys_directory=KEYS, certfile = CERTFILE, keyfile = KEYFILE, ca = CA):
        self.keys_directory = keys_directory
        self.n_clients = n_clients
        self.vector_size = vector_size

        # Socket
        self.host = host
        self.port = port

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.context.load_verify_locations(ca)
        self.context.verify_mode = ssl.CERT_REQUIRED

        os.makedirs(keys_directory, exist_ok=True)
        
        # Charger les clés existantes ou en générer de nouvelles
        self.key = self._load_or_generate_master_keys()
        
        # Dictionnaire pour stocker les clés fonctionnelles générées
        self.functional_keys = {}

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.bind((self.host, self.port))
            srv.listen()
            print(f"[TrustServer] listening {self.host}:{self.port} ...")

            with self.context.wrap_socket(srv, server_side=True) as ssock:
                while True:
                    conn, _ = ssock.accept()
                    threading.Thread(target=self._handle_request, args=(conn,), daemon=True).start()

    def _handle_request(self, conn):
        with conn:
            peer_cert = conn.getpeercert()
            subject = dict(x[0] for x in peer_cert['subject'])
            cn = subject.get('commonName')
            client_id = extract_client_id(cn)
            if client_id is None:
                return

            req = pickle.loads(conn.recv(16384))
            print(f"[TrustServer] Client : {client_id}, req['type'] = {req['type']}")
            if req['type'] == 'get_keys':
                try:
                    key = self.ask_key(client_id)
                except ValueError:
                    conn.sendall(pickle.dumps({'status': 'error', 'message': f'The client {client_id} isn\'t valid'}))
                    print(f"[TrustServer] Invalid client id : {client_id}")
                    return
                conn.sendall(pickle.dumps({'status': 'ok', 'pub_key': self.get_pub_key(), 'enc_key': key}))
                print(f"[TrustServer] Key for client {client_id} send.")
                return

            elif req['type'] == 'get_func_key':
                function = req.get('function')

                try:
                    if isinstance(function, str):
                        if function == "sum":
                            key = self.get_sum_key()
                        elif function == "mean":
                            key = self.get_mean_key()
                        elif function == "correlation":
                            key = self.get_correlation_keys(req.get('additional_data'))
                        else:
                            return
                    else:
                        key = self.functional_keygen(function)
                    print(f"[TrustServer] Key for function {function} generated.")
                    conn.sendall(pickle.dumps({'status': 'ok', 'func_key': key}))
                    print(f"[TrustServer] Key for function {function} send.")
                except Exception as e:
                    print(f"[TrustServer] Key for function {function} could not be generated. Error : {e}")
                    conn.sendall(pickle.dumps({'status': 'error', 'message': 'Error while generating the functional key'}))



    def _load_or_generate_master_keys(self):
        """Charge les clés maîtres ou les génère si elles n'existent pas"""
        master_key_path = os.path.join(self.keys_directory, "master_key.pkl")
        
        if os.path.exists(master_key_path):
            print(f"[TrustServer] Loading Master Key from {master_key_path} ...")
            with open(master_key_path, 'rb') as f:
                return pickle.load(f)
        else:
            print(f"[TrustServer] Generating Master Key and saving into {master_key_path} ...")
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
        if client_id is not None and 0 <= client_id < self.n_clients:  
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


    def get_sum_key(self):
        """Génère la clé pour calculer une somme"""
        y = [[1 for _ in range(self.vector_size)] for _ in range(self.n_clients)]
        return self.functional_keygen(y)

    def get_mean_key(self):
        """Génère la clé pour calculer une moyenne"""
        return self.get_sum_key()  # Même clé, division après

    def get_correlation_keys(self, y):
        """Génère les 3 clés nécessaires pour calculer une corrélation"""
        return self.functional_keygen(y), self.get_sum_key()
        # return self.get_sum_key(), self.get_sum_key()
        pass