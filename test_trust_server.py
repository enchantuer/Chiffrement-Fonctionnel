import os
import pickle
from trust_server import T_server
from mife.multiclient.damgard import FeDamgardMultiClient

def demo_complete():
    """Démonstration complète avec affichage des clés"""
    print("🚀 DÉMONSTRATION COMPLÈTE DU TRUST SERVER")
    print("=" * 60)
    
    # 1. Créer le serveur avec un dossier visible
    print("\n1️⃣ CRÉATION DU SERVEUR")
    keys_dir = "demo_keys/"
    server = T_server(n_clients=3, vector_size=4, keys_directory=keys_dir)
    
    print(f"📁 Dossier des clés: {keys_dir}")
    print(f"👥 Nombre de clients: 3")
    print(f"📏 Taille des vecteurs: 4")
    
    # 2. Examiner les fichiers créés
    print("\n2️⃣ FICHIERS CRÉÉS")
    if os.path.exists(keys_dir):
        files = os.listdir(keys_dir)
        print(f"📂 Fichiers dans {keys_dir}:")
        for file in files:
            size = os.path.getsize(os.path.join(keys_dir, file))
            print(f"   📄 {file} ({size} bytes)")
    
    # 3. Afficher les clés publiques
    print("\n3️⃣ CLÉ PUBLIQUE")
    pub_key = server.get_pub_key()
    print(f"🔑 Type: {type(pub_key)}")
    print(f"🔑 Contenu (aperçu): {str(pub_key)[:100]}...")
    
    # 4. Récupérer les clés clients
    print("\n4️⃣ CLÉS DES CLIENTS")
    client_keys = {}
    for client_id in range(3):
        key = server.ask_key(client_id)
        client_keys[client_id] = key
        print(f"👤 Client {client_id}: {type(key)} - {str(key)[:50]}...")
    
    # 5. Créer et sauvegarder des clés fonctionnelles
    print("\n5️⃣ CLÉS FONCTIONNELLES")
    
    # Clé pour somme
    print("📊 Génération clé SOMME...")
    sum_key = server.get_sum_key(3, 4)
    server.save_functional_key("demo_sum", [[1,1,1,1],[1,1,1,1],[1,1,1,1]], sum_key)
    print(f"✅ Clé somme: {type(sum_key)}")
    
    # Clé pour moyenne
    print("📊 Génération clé MOYENNE...")
    mean_key = server.get_mean_key(3, 4)
    server.save_functional_key("demo_mean", [[1,1,1,1],[1,1,1,1],[1,1,1,1]], mean_key)
    print(f"✅ Clé moyenne: {type(mean_key)}")
    
    # Clé personnalisée (premier élément seulement)
    print("📊 Génération clé PREMIER ÉLÉMENT...")
    first_vector = [[1,0,0,0],[1,0,0,0],[1,0,0,0]]
    first_key = server.functional_keygen(first_vector)
    server.save_functional_key("demo_first", first_vector, first_key)
    print(f"✅ Clé premier élément: {type(first_key)}")
    
    # 6. Voir tous les fichiers maintenant
    print("\n6️⃣ FICHIERS APRÈS GÉNÉRATION DES CLÉS")
    files = os.listdir(keys_dir)
    print(f"📂 Fichiers dans {keys_dir}:")
    for file in files:
        size = os.path.getsize(os.path.join(keys_dir, file))
        print(f"   📄 {file} ({size} bytes)")
        
        # Afficher le contenu des clés fonctionnelles
        if file.startswith("func_key_"):
            with open(os.path.join(keys_dir, file), 'rb') as f:
                key_info = pickle.load(f)
                print(f"      📋 ID: {key_info['function_id']}")
                print(f"      📅 Créé: {key_info['created_at']}")
                print(f"      🔢 Vecteur: {key_info['function_vector']}")
    
    # 7. Test de chiffrement et calcul
    print("\n7️⃣ TEST COMPLET DE CHIFFREMENT")
    
    # Données de test
    data_clients = [
        [10, 20, 30, 40],  # Client 0
        [1, 2, 3, 4],      # Client 1  
        [5, 5, 5, 5]       # Client 2
    ]
    
    print("📊 Données des clients:")
    for i, data in enumerate(data_clients):
        print(f"   👤 Client {i}: {data}")
    
    # Chiffrement
    tag = b"demo_tag"
    encrypted_data = []
    
    print("\n🔐 Chiffrement en cours...")
    for client_id, data in enumerate(data_clients):
        client_key = client_keys[client_id]
        cipher = FeDamgardMultiClient.encrypt(data, tag, client_key, pub_key)
        encrypted_data.append(cipher)
        print(f"   ✅ Client {client_id} chiffré")
    
    # Calculs avec différentes clés fonctionnelles
    print("\n🧮 CALCULS SUR DONNÉES CHIFFRÉES")
    
    # Somme totale
    result_sum = FeDamgardMultiClient.decrypt(encrypted_data, pub_key, sum_key, (0, 500))
    expected_sum = sum(sum(data) for data in data_clients)
    print(f"📊 SOMME: {result_sum} (attendu: {expected_sum})")
    
    # Premier élément de chaque client
    result_first = FeDamgardMultiClient.decrypt(encrypted_data, pub_key, first_key, (0, 100))
    expected_first = sum(data[0] for data in data_clients)
    print(f"📊 PREMIERS ÉLÉMENTS: {result_first} (attendu: {expected_first})")
    
    # Moyenne
    print(f"📊 MOYENNE: {result_sum / len(data_clients)} (attendu: {expected_sum / len(data_clients)})")
    
    # 8. Charger des clés fonctionnelles existantes
    print("\n8️⃣ CHARGEMENT DE CLÉS EXISTANTES")
    loaded_sum = server.load_functional_key("demo_sum")
    loaded_mean = server.load_functional_key("demo_mean")
    loaded_first = server.load_functional_key("demo_first")
    
    print(f"✅ Clé somme rechargée: {loaded_sum is not None}")
    print(f"✅ Clé moyenne rechargée: {loaded_mean is not None}")
    print(f"✅ Clé premier élément rechargée: {loaded_first is not None}")
    
    print("\n" + "=" * 60)
    print("🎉 DÉMONSTRATION TERMINÉE!")
    print(f"📁 Les clés sont sauvegardées dans: {keys_dir}")
    print("💡 Vous pouvez maintenant examiner les fichiers!")

def examine_keys_content():
    """Examine le contenu détaillé des clés"""
    print("\n🔍 EXAMEN DÉTAILLÉ DES CLÉS")
    print("=" * 50)
    
    keys_dir = "demo_keys/"
    
    if not os.path.exists(keys_dir):
        print("❌ Pas de dossier demo_keys/. Lancez d'abord demo_complete()")
        return
    
    # Examiner la clé maître
    master_path = os.path.join(keys_dir, "master_key.pkl")
    if os.path.exists(master_path):
        print("\n🔑 CLÉ MAÎTRE:")
        with open(master_path, 'rb') as f:
            master_key = pickle.load(f)
            print(f"   Type: {type(master_key)}")
            print(f"   Méthodes disponibles: {[m for m in dir(master_key) if not m.startswith('_')]}")
    
    # Examiner les clés fonctionnelles
    print("\n🔧 CLÉS FONCTIONNELLES:")
    for file in os.listdir(keys_dir):
        if file.startswith("func_key_"):
            print(f"\n📄 {file}:")
            with open(os.path.join(keys_dir, file), 'rb') as f:
                key_info = pickle.load(f)
                print(f"   📋 ID: {key_info['function_id']}")
                print(f"   📅 Créé: {key_info['created_at']}")
                print(f"   🔢 Vecteur fonction:")
                for i, row in enumerate(key_info['function_vector']):
                    print(f"      Client {i}: {row}")
                print(f"   🔑 Type clé: {type(key_info['functional_key'])}")

def cleanup_demo():
    """Nettoie les fichiers de démonstration"""
    import shutil
    keys_dir = "demo_keys/"
    if os.path.exists(keys_dir):
        shutil.rmtree(keys_dir)
        print(f"🧹 Dossier {keys_dir} supprimé")
    else:
        print("🧹 Rien à nettoyer")

def interactive_demo():
    """Interface interactive pour explorer le Trust Server"""
    print("🎮 DÉMONSTRATION INTERACTIVE")
    print("=" * 40)
    
    while True:
        print("\nChoisissez une action:")
        print("1. Démonstration complète")
        print("2. Examiner le contenu des clés")
        print("3. Nettoyer les fichiers de démo")
        print("4. Quitter")
        
        choice = input("\nVotre choix (1-4): ").strip()
        
        if choice == "1":
            demo_complete()
        elif choice == "2":
            examine_keys_content()
        elif choice == "3":
            cleanup_demo()
        elif choice == "4":
            print("👋 Au revoir!")
            break
        else:
            print("❌ Choix invalide")

if __name__ == "__main__":
    interactive_demo()