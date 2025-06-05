from trust_server import T_server
from client import Client

if __name__ == "__main__":

    t_server = T_server(n_clients=3, vector_size=3)
    client0 = Client(client_id=0, T_server=t_server)
    client1 = Client(client_id=1, T_server=t_server)
