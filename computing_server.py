import pickle
import sqlite3
import base64
import datetime
from typing import Any

from mife.multiclient.damgard import FeDamgardMultiClient


def adapt_datetime_iso(date_time: datetime) -> str:
    """
    Convert a Python datetime.datetime into a timezone-naive ISO 8601 date string.
    >>> adapt_datetime_iso(datetime.datetime(2023, 4, 5, 6, 7, 8, 9))
    '2023-04-05T06:07:08.000009'
    """
    return date_time.isoformat()


def convert_timestamp(time_stamp: bytes) -> datetime:
    """
    Convert an ISO 8601 formatted bytestring to a datetime.datetime object.
    >>> convert_timestamp(b'2023-04-05T06:07:08.000009')
    datetime.datetime(2023, 4, 5, 6, 7, 8, 9)
    """
    return datetime.datetime.strptime(time_stamp.decode("utf-8"), "%Y-%m-%dT%H:%M:%S.%f")


sqlite3.register_adapter(datetime, adapt_datetime_iso)
sqlite3.register_converter("timestamp", convert_timestamp)

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
                created_at TEXT NOT NULL,
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

# Exemple d'utilisation
if __name__ == "__main__":
    key = FeDamgardMultiClient.generate(2, 3)
    server = ComputingServer()
    tag = b'tag'
    d = FeDamgardMultiClient.encrypt([1, 2, 3], tag, key.get_enc_key(0), key.get_public_key())
    server.save_data('client123', tag, pickle.dumps(d))
    d = FeDamgardMultiClient.encrypt([4, 5, 6], tag, key.get_enc_key(1), key.get_public_key())
    server.save_data('client124', tag, pickle.dumps(d))

    y = [[1 for j in range(3)] for i in range(2)] #SOMME
    sk = FeDamgardMultiClient.keygen(y, key)
    print(server.apply_fe_key(key.get_public_key(), sk, tag))
    # data = server._get_data_by_tag(tag)
    # for client_id, ciphertext, created_at in data:
    #     print(f"{client_id} - {created_at} - {ciphertext}")

    server.close()