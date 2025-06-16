import threading
import pickle
import socket
import time
from client import Client  # Ta classe Client
from mife.multiclient.damgard import FeDamgardMultiClient
from computing_server import ComputingServer  # Ton serveur

# === Paramètres ===
n_clients = 2
vector_size = 3
tag = b"tag_test"

# Génération des clés (maître)
mock_master_key = FeDamgardMultiClient.generate(n_clients, vector_size)
mock_pub_key = mock_master_key.get_public_key()
mock_enc_keys = [mock_master_key.get_enc_key(i) for i in range(n_clients)]

# Définir une fonction de somme simple : [1, 1, 1] pour chaque client
y = [[1 for _ in range(vector_size)] for _ in range(n_clients)]
sum_key = FeDamgardMultiClient.keygen(y, mock_master_key)

# === Fake Trust Server ===
def fake_trust_server():
    HOST, PORT = 'localhost', 1560
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("[FakeTrustServer] En écoute...")
        while True:
            conn, _ = s.accept()
            with conn:
                try:
                    data = pickle.loads(conn.recv(16384))
                    print("[FakeTrustServer] Requête reçue :", data)

                    if data['type'] == 'get_keys':
                        try:
                            client_index = int(data['client_id'].split('_')[-1])
                            res = {
                                'status': 'ok',
                                'pub_key': mock_pub_key,
                                'enc_key': mock_enc_keys[client_index]
                            }
                        except Exception as e:
                            res = {'status': 'error', 'message': f'Invalid client_id: {e}'}

                    elif data['type'] == 'get_func_key':
                        res = {
                            'status': 'ok',
                            'func_key': sum_key
                        }

                    else:
                        res = {'status': 'error', 'message': 'unknown request'}

                    conn.sendall(pickle.dumps(res))

                except Exception as e:
                    print(f"[FakeTrustServer] Erreur : {e}")
                    # Envoyer un message d'erreur au client même en cas d'erreur
                    try:
                        conn.sendall(pickle.dumps({'status': 'error', 'message': str(e)}))
                    except:
                        pass


# === Lancer le FakeTrustServer ===
trust_thread = threading.Thread(target=fake_trust_server, daemon=True)
trust_thread.start()

# === Lancer le vrai ComputingServer ===
computing_server = ComputingServer()
threading.Thread(target=computing_server.start, daemon=True).start()

# === Attente initiale pour setup ===
time.sleep(1)

# === Initialisation des deux clients ===
client0 = Client("client_id_0")
client1 = Client("client_id_1")

client0.get_keys()
client1.get_keys()

# === Données de test (vecteurs) ===
data_client0 = [100, 150, 200]
data_client1 = [300, 350, 400]

# Chaque client chiffre et envoie son vecteur
client0.encrypt_and_send(data_client0, tag)
client1.encrypt_and_send(data_client1, tag)

# === Le client 0 demande la somme des vecteurs ===
result = client0.request_result(tag=tag)
print(f"\nRésultat reçu du serveur de calcul (somme vectorielle) : {result}")
