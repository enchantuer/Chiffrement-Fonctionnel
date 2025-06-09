import pickle
import sqlite3
import datetime
from typing import Any
from mife.multiclient.damgard import FeDamgardMultiClient

class ComputingServer:
    def __init__(self, db_path='encrypted_data.db'):
        # Connexion à la base SQLite (fichier local)
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self._create_table()

    def _create_table(self):
        # Création de la table si elle n'existe pas déjà
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

    def close(self):
        self.conn.close()

    def save_data(self, client_id: str, tag: bytes, data):
        created_at = datetime.datetime.now(datetime.UTC)
        self.cursor.execute('''
            INSERT INTO EncryptedData (client_id, tag, ciphertext, created_at)
            VALUES (?, ?, ?, ?)
        ''', (client_id, tag, data, created_at))
        self.conn.commit()

    def _get_data_by_tag(self, tag: bytes) -> list[Any]:
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

    def correlation(self, pk, sks: tuple[3], mean_y, yy, tag: bytes,bound = (0, 2000)):
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
    n = 2
    m = 3
    key = FeDamgardMultiClient.generate(n, m)
    server = ComputingServer()
    tag = b'tag'

    d = FeDamgardMultiClient.encrypt([1, 2, 3], tag, key.get_enc_key(0), key.get_public_key())
    server.save_data('client123', tag, pickle.dumps(d))
    d = FeDamgardMultiClient.encrypt([4, 5, 6], tag, key.get_enc_key(1), key.get_public_key())
    server.save_data('client124', tag, pickle.dumps(d))

    y = [[1 for j in range(m)] for i in range(n)] #SOMME
    sk = FeDamgardMultiClient.keygen(y, key)
    print(server.apply_fe_key(key.get_public_key(), sk, tag))

    # Test Mean
    n = 4
    m = 1
    key = FeDamgardMultiClient.generate(n, m)
    server = ComputingServer()
    tag = b'tag2'

    d = FeDamgardMultiClient.encrypt([1], tag, key.get_enc_key(0), key.get_public_key())
    server.save_data('client123', tag, pickle.dumps(d))
    d = FeDamgardMultiClient.encrypt([2], tag, key.get_enc_key(1), key.get_public_key())
    server.save_data('client124', tag, pickle.dumps(d))
    d = FeDamgardMultiClient.encrypt([3], tag, key.get_enc_key(2), key.get_public_key())
    server.save_data('client125', tag, pickle.dumps(d))
    d = FeDamgardMultiClient.encrypt([4], tag, key.get_enc_key(3), key.get_public_key())
    server.save_data('client126', tag, pickle.dumps(d))

    y = [[1 for j in range(m)] for i in range(n)] #SOMME
    sk = FeDamgardMultiClient.keygen(y, key)
    print(server.mean(key.get_public_key(), sk, tag))

    server.close()