# Devin1.os — Honeypot de Surveillance d'Intégrité de Fichiers

Un outil simple et efficace en Python pour détecter toute modification non autorisée sur un fichier système critique grâce à un clone honeypot et un contrôle d'intégrité par hash SHA-256. (https://img.shields.io/badge/Python-3.8+-blue)](https://www.python.org/) (https://img.shields.io/badge/License-MIT-green)](https://github.com/tq-devini1/devin1.os/blob/main/LICENSE)

## À quoi ça sert ?

Devin1.os crée un **clone** d'un fichier système important et surveille en continu son intégrité.  
Si le clone est modifié (par un malware, un administrateur malveillant, ou une intrusion), une **alerte claire** est déclenchée.

**Idéal pour :**
- Protéger les serveurs et infrastructures critiques
- Détecter les manipulations de fichiers système
- Renforcer la sécurité en environnement sensible (gouvernemental, entreprise, DevSecOps)

## Fonctionnalités

- Création automatique d'un clone honeypot
- Calcul de hash SHA-256 robuste
- Surveillance en temps réel toutes les 5 secondes (configurable)
- Détection immédiate des modifications
- Messages clairs d'alerte ou de « système sécurisé »

## Fichiers du projet

- `devin1.os.py` → Script principal
- `devin1.os.txt` → Analyse détaillée (bénéfices / risques / recommandations)

## Installation & Utilisation

```bash
git clone https://github.com/tq-devini1/devin1.os.git
cd devin1.os
⚠️ À tester avec précaution avant toute utilisation en production.

☕ Soutenir le projet
Si cet outil vous est utile, vous pouvez me soutenir ici : (https://buymeacoffee.com/tedehur)
