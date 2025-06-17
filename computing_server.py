import pickle
import sqlite3
import datetime
from typing import Any
from mife.multiclient.damgard import FeDamgardMultiClient

import socket
import threading
import re

import ssl

DB_FILE = 'encrypted_data.db'
HOST = 'localhost'
PORT = 1567

CERTFILE = 'certs/computing_server/server.cert'
KEYFILE = 'certs/computing_server/server.key'
CA = 'certs/ca/root.cert'

def extract_client_id(cn: str) -> str | None:
    match = re.fullmatch(r"client_(\w+)", cn)
    if match:
        return match.group(1)
    return None


class ComputingServer:
    def __init__(self, host=HOST, port=PORT, db_path=DB_FILE, certfile = CERTFILE, keyfile = KEYFILE, ca = CA):
        # Connexion à la base SQLite (fichier local)
        self.db_lock = threading.Lock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._init_db()

        # Socket
        self.host = host
        self.port = port

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.context.load_verify_locations(ca)
        self.context.verify_mode = ssl.CERT_REQUIRED

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.bind((self.host, self.port))
            srv.listen()
            print(f"[ComputeServer] listening {self.host}:{self.port} ...")

            with self.context.wrap_socket(srv, server_side=True) as ssock:
                while True:
                    conn, _ = ssock.accept()
                    threading.Thread(target=self._handle_request, args=(conn,), daemon=True).start()
            # while True:
            #     conn, _ = srv.accept()
            #     threading.Thread(target=self._handle_request, args=(conn,), daemon=True).start()

    def _handle_request(self, conn):
        with conn:
            peer_cert = conn.getpeercert()
            subject = dict(x[0] for x in peer_cert['subject'])
            cn = subject.get('commonName')
            client_id = extract_client_id(cn)
            if client_id is None:
                return

            req = pickle.loads(conn.recv(16384))
            print(f"[ComputeServer] Client : {client_id}, req['type'] = {req['type']}")
            if req['type'] == 'ciphertext':
                tag = req.get('tag')
                data = req.get('data')
                try:
                    self.save_data(client_id, tag, data)
                except sqlite3.IntegrityError as e:
                    conn.sendall(pickle.dumps({'status': 'error', 'message': f'The client {client_id} has already stored data with tag {tag}'}))
                    print(f"[ComputeServer] Ciphertext already for client {client_id} with tag {tag}.")
                    return
                conn.sendall(pickle.dumps({'status': 'ok'}))
                print(f"[ComputeServer] Ciphertext stored for client {client_id} with tag {tag}.")
                return

            elif req['type'] == 'func_key':
                pk = req.get('pk')
                sk = req.get('sk')
                tag = req.get('tag')
                data = req.get('data')

                print(f"[ComputeServer] Function key received.")

                if data is None:
                    print('[ComputeServer] No data received.')
                    try:
                        result = self.apply_fe_key(pk, sk, tag)
                    except Exception as e:
                        conn.sendall(
                            pickle.dumps({'status': 'error', 'message': 'Error while computing functional key function'}))
                        return
                    conn.sendall(pickle.dumps({'status': 'ok', 'result': result}))
                    return

                if data['function']:
                    function = data['function']
                    if function == "mean":
                        try:
                            result = self.mean(pk, sk, tag)
                        except Exception as e:
                            conn.sendall(pickle.dumps({'status': 'error', 'message': 'Error while computing mean function'}))
                            return
                        conn.sendall(pickle.dumps({'status': 'ok', 'result': result}))
                        return
                    elif function == "correlation":
                        try:
                            result = self.correlation(pk, sk, data['additional'], tag)
                        except Exception as e:
                            conn.sendall(pickle.dumps({'status': 'error', 'message': 'Error while computing correlation function'}))
                            return
                        conn.sendall(pickle.dumps({'status': 'ok', 'result': result}))
                        return
                else:
                    conn.sendall(pickle.dumps({'status': 'error', 'message': 'unknown function'}))
                    return
                print("[ComputeServer] Résultat calculé et envoyé.")

    def _init_db(self):
        # Création de la table si elle n'existe pas déjà
        with self.db_lock:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS EncryptedData (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL,
                    tag BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    UNIQUE (client_id, tag)
                )
                ''')
            self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_tag ON EncryptedData(tag)')
            self.conn.commit()
            print("[ComputeServer] Database initialized.")

    def close(self):
        self.conn.close()

    def save_data(self, client_id: str, tag: bytes, data):
        created_at = datetime.datetime.now(datetime.UTC)
        with self.db_lock:
            self.cursor.execute('''
                INSERT INTO EncryptedData (client_id, tag, ciphertext, created_at)
                VALUES (?, ?, ?, ?)
            ''', (client_id, tag, data, created_at))
            self.conn.commit()

    def _get_data_by_tag(self, tag: bytes) -> list[Any]:
        with self.db_lock:
            self.cursor.execute('''
                SELECT ciphertext
                FROM EncryptedData
                WHERE tag = ?
            ''', (tag,))
            rows = self.cursor.fetchall()
        return [pickle.loads(data[0]) for data in rows]

    def apply_fe_key(self, pk, sk, tag: bytes, bound = (0, 2000)):
        data = self._get_data_by_tag(tag)

        # Effectuer le déchiffrement fonctionnel
        result = FeDamgardMultiClient.decrypt(data, pk, sk, bound)
        return result

    def mean(self, pk, sk, tag: bytes, bound = (0, 2000)):
        data = self._get_data_by_tag(tag)
        # Effectuer le déchiffrement fonctionnel
        result = FeDamgardMultiClient.decrypt(data, pk, sk, bound)
        return result / len(data)

    def correlation(self, pk, sks: tuple[Any, Any, Any], data: tuple[int, int], tag: bytes,bound = (0, 2000)):
        mean_y, yy = data
        data = self._get_data_by_tag(tag)

        xy = FeDamgardMultiClient.decrypt(data, pk, sks[0], bound)
        xx = FeDamgardMultiClient.decrypt(data, pk, sks[1], bound)
        sum = FeDamgardMultiClient.decrypt(data, pk, sks[2], bound)

        m = len(data)

        mean_x = sum / m
        numerator = xy - (m * mean_x * mean_y)
        denominator = ((xx - m * mean_x**2) * (yy - m * mean_y**2))**0.5

        return numerator / denominator


# Exemple d'utilisation
if __name__ == "__main__":
    # Test apply fe key
    # n = 2
    # m = 3
    # key = FeDamgardMultiClient.generate(n, m)
    # tag = b'tag'

    server = ComputingServer()
    server.start()

    # server.save_data('client124', tag, pickle.dumps(d))

    # y = [[1 for j in range(m)] for i in range(n)] #SOMME
    # sk = FeDamgardMultiClient.keygen(y, key)
    # print(server.apply_fe_key(key.get_public_key(), sk, tag))

    # Test Mean
    # n = 4
    # m = 1
    # key = FeDamgardMultiClient.generate(n, m)
    # server = ComputingServer()
    # tag = b'tag2'
    #
    # d = FeDamgardMultiClient.encrypt([1], tag, key.get_enc_key(0), key.get_public_key())
    # server.save_data('client123', tag, pickle.dumps(d))
    # d = FeDamgardMultiClient.encrypt([2], tag, key.get_enc_key(1), key.get_public_key())
    # server.save_data('client124', tag, pickle.dumps(d))
    # d = FeDamgardMultiClient.encrypt([3], tag, key.get_enc_key(2), key.get_public_key())
    # server.save_data('client125', tag, pickle.dumps(d))
    # d = FeDamgardMultiClient.encrypt([4], tag, key.get_enc_key(3), key.get_public_key())
    # server.save_data('client126', tag, pickle.dumps(d))
    #
    # y = [[1 for j in range(m)] for i in range(n)] #SOMME
    # sk = FeDamgardMultiClient.keygen(y, key)
    # print(server.mean(key.get_public_key(), sk, tag))