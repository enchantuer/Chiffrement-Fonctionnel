from trust_server import T_server
from client import Client
from mife.multiclient.damgard import FeDamgardMultiClient

if __name__ == "__main__":

    n_clients = 2
    vector_size = 3
    t_server = T_server(n_clients, vector_size)
    client0 = Client(client_id=0, T_server=t_server)
    client1 = Client(client_id=1, T_server=t_server)

    tag = b"test"
    c1 = client0.encrypt_and_send([1, 2, 3], tag)
    c2 = client1.encrypt_and_send([4, 5, 6], tag)
    
    y = [[1 for j in range(vector_size)] for i in range(n_clients)] #SOMME
    sk = t_server.functional_keygen(y)
    m = FeDamgardMultiClient.decrypt([c1,c2], t_server.key.get_public_key(), sk, (0, 2000))
    
    print(m)