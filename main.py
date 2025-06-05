from trust_server import T_server
from client import Client
from mife.multiclient.damgard import FeDamgardMultiClient

if __name__ == "__main__":

    n_clients = 2
    vector_size = 3
    t_server = T_server(n_clients, vector_size)
    client0 = Client(client_id=0, T_server=t_server)
    client1 = Client(client_id=1, T_server=t_server)
