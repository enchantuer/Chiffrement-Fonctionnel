import pickle
from mife.multiclient.damgard import FeDamgardMultiClient

import socket
import ssl

TRUST_SERVER = ('localhost', 1560)
COMPUTING_SERVER = ('localhost', 1567)

CA = 'certs/ca/ca.cert'

class Client:
    def __init__(self, certfile, keyfile, trust_serveur=TRUST_SERVER, computing_server=COMPUTING_SERVER, ca=CA):
        # Socket
        self.t_server = trust_serveur
        self.c_server = computing_server

        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.context.check_hostname = True

        self.pub_key = None
        self.enc_key = None
        self.get_keys()

    def get_keys(self):
        # Création de la requête pour la réception de la clé publique du serveur de confiance et de la clé de chiffrement du client
        req = {
            'type': 'get_keys'
        }
        
        with socket.create_connection(self.t_server) as sock:
            with self.context.wrap_socket(sock, server_hostname=self.t_server[0]) as ssock:
                ssock.sendall(pickle.dumps(req))

                response = pickle.loads(ssock.recv(16384))
                if response.get('status') != 'ok':
                    print("[Client] Erreur lors de la récupération des clés depuis le serveur de confiance")

                self.pub_key = response['pub_key']
                self.enc_key = response['enc_key']
                print(f"[Client] Clés reçues avec succès.")

    def encrypt_and_send(self, data, tag):
        cipher = FeDamgardMultiClient.encrypt(data, tag, self.enc_key, self.pub_key)
        if cipher is None:
            print("[Client] Le chiffrement a échoué (cispher est None)")
        
        # Création de la requête pour l'envoie des données chiffrés
        req = {
            'type': 'ciphertext',
            'tag': tag,
            'data': pickle.dumps(cipher) 
        }

        with socket.create_connection(self.c_server) as sock:
            with self.context.wrap_socket(sock, server_hostname=self.c_server[0]) as ssock:
                ssock.sendall(pickle.dumps(req))

                response = pickle.loads(ssock.recv(4096))
                if response.get('status') != 'ok':
                    print(f"[Client] Erreur serveur : {response.get('message')}")
                print(f"[Client] Données envoyées avec succès au serveur.")

        return cipher
    
    def request_result(self, tag, function, additional_data=None):
        # Création de la requête pour récupéré la clé fonctionnel
        req = {
            'type': 'get_func_key',
            'function': function
        }

        with socket.create_connection(self.t_server) as sock:
            with self.context.wrap_socket(sock, server_hostname=self.t_server[0]) as ssock:
                ssock.sendall(pickle.dumps(req))

                response = pickle.loads(ssock.recv(4096))
                if response.get('status') != 'ok':
                    print("[Client] Erreur lors de la récupération de la clé depuis le serveur de confiance")
                    return

                sk = response.get('func_key')
                print(f"[Client] Clés reçues avec succès.")

        # Création de la requête pour l'envoie des données chiffrés
        if(function=="sum"):
            function=None
        req = {
            'type': 'func_key',
            'pk': self.pub_key,
            'sk': sk,
            'tag': tag,
            'data': {
                'function': function,
                'additional': additional_data  
            } if isinstance(function, str) else None
        }

        with socket.create_connection(self.c_server) as sock:
            with self.context.wrap_socket(sock, server_hostname=self.c_server[0]) as ssock:
                ssock.sendall(pickle.dumps(req))

                response = pickle.loads(ssock.recv(4096))
                if response.get('status') != 'ok':
                    print(f"[Client] Erreur serveur : {response.get('message')}")

                result = response.get('result')
                print(f"[Client] Résultat reçu : {result}")
                return result

