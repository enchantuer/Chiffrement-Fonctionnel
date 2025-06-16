import pickle
from mife.multiclient.damgard import FeDamgardMultiClient

import socket

TRUST_SERVER = ('localhost', 1560)
COMPUTING_SERVER = ('localhost', 1567)

class Client:
    def __init__(self, client_id, trust_serveur=TRUST_SERVER, computing_server=COMPUTING_SERVER):
        self.client_id = client_id

        self.pub_key = None
        self.enc_key = None

        # Socket
        self.t_server = trust_serveur
        self.c_server = computing_server

    def get_keys(self):
        # Création de la requête pour la réception de la clé publique du serveur de confiance et de la clé de chiffrement du client
        req = {
            'type': 'get_keys',
            'client_id': self.client_id
        }
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clt:
            clt.connect(self.t_server)
            clt.sendall(pickle.dumps(req))

            response = pickle.loads(clt.recv(16384))
            if response.get('status') != 'ok':
                print("Erreur lors de la récupération des clés depuis le serveur de confiance")

            self.pub_key = response['pub_key']
            self.enc_key = response['enc_key']
            print(f"[Client {self.client_id}] Clés reçues avec succès.")

    def encrypt_and_send(self, data, tag):
        cipher = FeDamgardMultiClient.encrypt(data, tag, self.enc_key, self.pub_key)
        if cipher is None:
            print("Le chiffrement a échoué (cispher est None)")
        
        # Création de la requête pour l'envoie des données chiffrés
        req = {
            'type': 'ciphertext',
            'client_id': self.client_id,
            'tag': tag,
            'data': pickle.dumps(cipher) 
        }

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clt:
            clt.connect(self.c_server)
            clt.sendall(pickle.dumps(req))

            response = pickle.loads(clt.recv(4096))
            if response.get('status') != 'ok':
                print(f"Erreur serveur : {response.get('message')}")
            print(f"[Client {self.client_id}] Données envoyées avec succès au serveur.")

        return cipher
    
    def request_result(self, tag, function=None, additional_data=None,):
        # Création de la requête pour récupéré la clé fonctionnel
        req = {
            'type': 'get_func_key',
            'function': function,
            'additional_data': additional_data
        }
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clt:
            clt.connect(self.t_server)
            clt.sendall(pickle.dumps(req))

            response = pickle.loads(clt.recv(4096))
            if response.get('status') != 'ok':
                print("Erreur lors de la récupération de la clé depuis le serveur de confiance")

            sk = response.get('func_key')
            print(f"[Client {self.client_id}] Clés reçues avec succès.") 

        # Création de la requête pour l'envoie des données chiffrés
        req = {
            'type': 'func_key',
            'pk': self.pub_key,
            'sk': sk,
            'tag': tag,
            'data': {
                'function': function,
                'additional': additional_data  
            } if function else None
        }

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clt:
            clt.connect(self.c_server)
            clt.sendall(pickle.dumps(req))

            response = pickle.loads(clt.recv(4096))
            if response.get('status') != 'ok':
                print(f"Erreur serveur : {response.get('message')}")

            result = response.get('result')
            print(f"[Client {self.client_id}] Résultat reçu : {result}")
            return result

