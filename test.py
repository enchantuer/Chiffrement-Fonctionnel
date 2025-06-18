import threading
import time
from trust_server import TrustServer
from computing_server import ComputingServer
from client import Client

if __name__ == "__main__":
    # === Paramètres ===
    n_clients = 2
    vector_size = 3
    tag = b"tag_test"

    # === Lancer le TrustServer ===
    t_server = TrustServer(n_clients, vector_size)
    trust_thread = threading.Thread(target=t_server.start, daemon=True).start()

    # === Lancer le vrai ComputingServer ===
    c_server = ComputingServer()
    threading.Thread(target=c_server.start, daemon=True).start()

    # === Attente initiale pour setup ===
    time.sleep(1)

    # === Initialisation des deux clients ===
    client0 = Client('certs/clients/0/client.cert', 'certs/clients/0/client.key')
    client1 = Client('certs/clients/1/client.cert', 'certs/clients/1/client.key')

    # === Données de test (vecteurs) ===
    data_client0 = [100, 150, 200]
    data_client1 = [300, 350, 400]

    # Chaque client chiffre et envoie son vecteur
    client0.encrypt_and_send(data_client0, tag)
    client1.encrypt_and_send(data_client1, tag)

    # === Le client 0 demande la somme des vecteurs ===
    result = client0.request_result(tag=tag, function=[[1 for _ in range(vector_size)] for _ in range(n_clients)])
    result = client0.request_result(tag=tag, function="sum")
    print(f"\nRésultat reçu du serveur de calcul (somme vectorielle) : {result}")