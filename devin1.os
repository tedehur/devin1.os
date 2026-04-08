

import os
import hashlib
import shutil
import time
import psutil

# Configuration
HONEYPOT_PATH = "/path/to/known/file"  # Remplacer par un fichier système connu
HONEYPOT_CLONE = "/path/to/clone/file"  # Chemin du clone à surveiller
SCAN_INTERVAL = 5  # Intervalle de scan en secondes

def create_clone():
    """Crée une copie du fichier système (clone)"""
    try:
        shutil.copy2(HONEYPOT_PATH,HONEYPOT_CLONE)
        return True
    except Exception as e:
        print(f"Erreur création clone: {e}")
        return False

def calculate_hash(file_path):
    """Calcule l'hachage SHA-256 d'un fichier"""
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Erreur calcul hash: {e}")
        return None

def monitor_system():
    """Surveillance principale du système"""
    # Initialisation du hash du clone
    clone_hash = calculate_hash(HONEYPOT_CLONE)
    
    if not clone_hash:
        print("Initialisation impossible - Création du clone échouée")
        return False
    
    print(f"Clone initial hash: {clone_hash[:10]}... (OK)")
    
    while True:
        time.sleep(SCAN_INTERVAL)
        
        # Vérification de l'existence du fichier système original
        if not os.path.exists(HONEYPOT_PATH):
            print("Le fichier système original est introuvable!")
            return False
        
        # Calcul du hash du clone
        current_hash = calculate_hash(HONEYPOT_CLONE)
        
        if not current_hash:
            print("Erreur calcul hash du clone")
            continue
        
        # Vérification de l'intégrité du clone
        if current_hash != clone_hash:
            print("ALERTE: Le clone a été modifié!")
            # Actions supplémentaires : journaliser, alerter, etc.
        else:
            print("Système en sécurité")

if __name__ == "__main__":
    # Initialisation du clone
    if not os.path.exists(HONEYPOT_CLONE):
        if not create_clone():
            print("Échec de la création du clone")
            exit(1)
    
    # Démarrage de la surveillance
    monitor_system()
