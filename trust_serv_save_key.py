import pickle
from mife.multiclient.damgard import FeDamgardMultiClient

if __name__ == '__main__':
    n = 2
    m = 3
    tag = b'tag'
    keys = FeDamgardMultiClient.generate(n, m)

    with open('keys/pk.pkl', 'wb') as f:
        pickle.dump(keys.get_public_key(), f)

    for i in range(n):
        with open('keys/ck{}.pkl'.format(i), 'wb') as f:
            pickle.dump(keys.get_enc_key(i), f)

    y = [[1 for j in range(m)] for i in range(n)] #SOMME
    sk = FeDamgardMultiClient.keygen(y, keys)
    with open('keys/sk.pkl', 'wb') as f:
        pickle.dump(sk, f)