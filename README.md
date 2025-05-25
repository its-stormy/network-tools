# network-tools
# 🛠️ Outil Avancé de Diagnostic Réseau

Un outil CLI en Python permettant d'effectuer diverses analyses réseau : ping ICMP (maison ou système), traceroute, scan de ports TCP/UDP, et scan de plage IP. Les résultats peuvent être sauvegardés automatiquement dans un fichier JSON.

## ✨ Fonctionnalités

- ✅ **Ping personnalisé (ICMP)** sans appel système (via `icmplib`)
- 🖥️ **Ping système** (compatibilité Windows/Linux)
- 📍 **Traceroute** configurable
- 🔍 **Scan de ports TCP** avec timeout
- 🔍 **Scan de ports UDP** avec détection DNS
- 🌐 **Scan de plage d’IP** (avec filtre sur hôtes en ligne)
- 💾 **Sauvegarde des résultats** dans un fichier `.json`

---

## 📦 Prérequis

- Python 3.7+
- Modules Python :
  - `icmplib`
  - `ipaddress`

### Installation des dépendances
```bash
pip install icmplib


### 🚀 Utilisation
Exécute simplement le fichier Python :

bash
Copier
Modifier
python network_tools.py
