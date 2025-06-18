# Chiffrement Fonctionnel - FE Plateforme multi-client
Analyse collaborative sécurisée de données multi-sources à l’aide du chiffrement fonctionnel

## Installation

### Prérequis
```bash
sudo apt update
sudo apt upgrade
```
Python :
```bash
python3 --version
```
Bibliothèque cryptographique PyMIFE (https://github.com/MechFroG88/PyMIFE):
```bash
pip install pymife
```
Pour le script des certificats OpenSSL est nécessaire
### Installation du projet
```bash
git clone https://github.com/enchantuer/Chiffrement-Fonctionnel
```
```bash
./certs_gen.bat
```


## Structure du projet
```
chiffrement-fonctionnel/
├── certs/                # Stockage des certificats
├── certs_gen.bash        # Génère les certificats sous Linux
├── certs_gen.bat         # Génère les certificats sous Windows
├── keys/                 
│   └── master_key.pkl    # Clés maîtres
├── encrypted_data.db     # BDD des données chiffrés
├── client.py             # Clients
├── computing_server.py   # Serveur de calcul
├── trust_server.py       # Serveur de confiance
├── test.py               # Pour les tests
└── README.md             # Documentation
```

## Utilisation
Pour tester notre plateforme en locale, il y a le fichier *test.py* qui permet de créer le serveur de calcul et de confiance ainsi que de les lancer. Les clients peuvent aussi y être créer et les données envoyer pour être calculées. Sur ce fichier, il est possible de rajouter des clients et des données (en modifiant le serveur de confiance), ainsi que de demander plusieurs opérations sur les données chiffrés.

Pour une utilisation non locale, il faut juste modifier les adresses IP et ports des serveurs et les lancés indépendament. Ainsi différents clients (sur différentes machines) peuvent leurs faire des requêtes et utiliser notre plateforme pour calculer des statistiques sur leurs données sensibles.