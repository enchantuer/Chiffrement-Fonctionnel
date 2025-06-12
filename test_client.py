import socket
import pickle
from mife.multiclient.damgard import FeDamgardMultiClient

HOST = 'localhost'
PORT = 1567

if __name__ == '__main__':
    with open('keys/pk.pkl', 'rb') as f:
        pk = pickle.load(f)
    with open('keys/ck0.pkl', 'rb') as f:
        ck0 = pickle.load(f)
    with open('keys/ck1.pkl', 'rb') as f:
        ck1 = pickle.load(f)
    with open('keys/sk.pkl', 'rb') as f:
        sk = pickle.load(f)

    tag = b'tag'

    # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #     s.connect((HOST, PORT))
    #     d = FeDamgardMultiClient.encrypt([1, 2, 3], tag, ck0, pk)
    #     req = {'type': 'ciphertext', 'client_id': 0, 'tag': tag, 'data': pickle.dumps(d)}
    #     s.sendall(pickle.dumps(req))
    #     resp = pickle.loads(s.recv(4096))
    #     print(f"[Client 0] Serveur :", resp)
    # # server.save_data('client123', tag, pickle.dumps(d))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        d = FeDamgardMultiClient.encrypt([4, 5, 6], tag, ck1, pk)
        req = {'type': 'ciphertext', 'client_id': 1, 'tag': tag, 'data': pickle.dumps(d)}
        s.sendall(pickle.dumps(req))
        resp = pickle.loads(s.recv(4096))
        print(f"[Client 1] Serveur :", resp)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        req = {'type': 'func_key', 'pk': pk, 'tag': tag, 'sk': sk}
        s.sendall(pickle.dumps(req))
        resp = pickle.loads(s.recv(4096))
        print(f"[Client request] Serveur :", resp)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        req = {'type': 'func_key', "data": {"function": 'mean'}, 'pk': pk, 'tag': tag, 'sk': sk}
        s.sendall(pickle.dumps(req))
        resp = pickle.loads(s.recv(4096))
        print(f"[Client request] Serveur :", resp)