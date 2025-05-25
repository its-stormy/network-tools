import os
import socket
import subprocess
import sys
import time
import select
import json
from typing import List, Tuple, Dict, Union
import platform
from datetime import datetime
from icmplib import ping as icmp_ping  # Pour le ping maison
import ipaddress

class NetworkTools:
    def __init__(self):
        self.config = {
            'ping_timeout': 1,
            'ping_count': 4,
            'traceroute_timeout': 1,
            'traceroute_max_hops': 30,
            'tcp_scan_timeout': 1,
            'udp_scan_timeout': 2,
            'default_ports': [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389],
            'output_file': 'network_scan_results.json'
        }

    def save_results(self, data: Dict, filename: str = None) -> None:
        """Sauvegarde les résultats dans un fichier JSON"""
        if not filename:
            filename = self.config['output_file']
        
        try:
            with open(filename, 'a') as f:
                f.write(json.dumps({
                    'timestamp': datetime.now().isoformat(),
                    'data': data
                }) + '\n')
            print(f"\nRésultats sauvegardés dans {filename}")
        except Exception as e:
            print(f"\033[91mErreur lors de la sauvegarde: {e}\033[0m")

    def custom_ping(self, host: str, count: int = None, timeout: float = None) -> Dict:
        """
        Ping maison utilisant des sockets ICMP (sans commande système)
        Retourne un dictionnaire avec les statistiques
        """
        count = count or self.config['ping_count']
        timeout = timeout or self.config['ping_timeout']
        
        results = {
            'host': host,
            'packets_sent': count,
            'packets_received': 0,
            'rtt_min': float('inf'),
            'rtt_max': 0,
            'rtt_avg': 0,
            'is_alive': False
        }
        
        total_time = 0
        
        try:
            # Résolution DNS si nécessaire
            ip = socket.gethostbyname(host)
            
            for _ in range(count):
                start_time = time.time()
                
                # Utilisation de la bibliothèque icmplib pour un ping fiable
                response = icmp_ping(ip, count=1, timeout=timeout, privileged=False)
                
                if response.is_alive:
                    rtt = (time.time() - start_time) * 1000  # en ms
                    results['packets_received'] += 1
                    total_time += rtt
                    
                    if rtt < results['rtt_min']:
                        results['rtt_min'] = rtt
                    if rtt > results['rtt_max']:
                        results['rtt_max'] = rtt
                
                time.sleep(0.5)  # Délai entre les pings
            
            if results['packets_received'] > 0:
                results['rtt_avg'] = total_time / results['packets_received']
                results['is_alive'] = True
        
        except Exception as e:
            print(f"\033[91mErreur lors du ping: {e}\033[0m")
        
        return results

    def system_ping(self, host: str) -> bool:
        """Ping utilisant la commande système (compatibilité)"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            count = self.config['ping_count']
            command = ['ping', param, str(count), host]
            
            with open(os.devnull, 'w') as devnull:
                return subprocess.call(command, stdout=devnull, stderr=devnull) == 0
        except Exception as e:
            print(f"\033[91mErreur lors du ping système: {e}\033[0m")
            return False

    def traceroute(self, host: str, max_hops: int = None, timeout: float = None) -> List[Tuple[int, str, float]]:
        """Traceroute avec gestion des paramètres configurables"""
        max_hops = max_hops or self.config['traceroute_max_hops']
        timeout = timeout or self.config['traceroute_timeout']
        
        results = []
        
        try:
            if platform.system().lower() == 'windows':
                command = ['tracert', '-h', str(max_hops), '-w', str(int(timeout * 1000)), host]
            else:
                command = ['traceroute', '-m', str(max_hops), '-w', str(timeout), '-q', '1', host]
            
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = process.communicate()
            
            if process.returncode != 0:
                print(f"\033[91mErreur lors du traceroute: {err.decode()}\033[0m")
                return results
            
            lines = out.decode().split('\n')
            for line in lines[1:]:
                if not line.strip():
                    continue
                    
                parts = line.split()
                if len(parts) < 2:
                    continue
                    
                try:
                    hop = int(parts[0])
                    ip = parts[1].strip('()')
                    
                    try:
                        socket.inet_aton(ip)
                        times = [float(p.replace('ms', '')) for p in parts[2:] if 'ms' in p]
                        avg_time = sum(times)/len(times) if times else 0.0
                        results.append((hop, ip, avg_time))
                    except socket.error:
                        continue
                        
                except (ValueError, IndexError):
                    continue
                    
        except Exception as e:
            print(f"\033[91mErreur lors du traceroute: {e}\033[0m")
        
        return results

    def tcp_port_scan(self, host: str, ports: List[int] = None, timeout: float = None) -> Dict[int, str]:
        """Scan des ports TCP avec timeout configurable"""
        timeout = timeout or self.config['tcp_scan_timeout']
        ports = ports or self.config['default_ports']
        
        results = {}
        
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            print(f"\033[91mImpossible de résoudre l'hôte: {host}\033[0m")
            return results
        
        print(f"\nScan TCP des ports sur {host} ({ip})...")
        
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((ip, port))
                    status = "OPEN" if result == 0 else "CLOSED"
                    results[port] = status
                    
                    color = "\033[92m" if status == "OPEN" else "\033[91m"
                    print(f"Port TCP {port}: {color}{status}\033[0m")
                    
            except KeyboardInterrupt:
                print("\033[93m\nScan interrompu par l'utilisateur\033[0m")
                break
            except Exception as e:
                print(f"\033[91mErreur lors du scan du port {port}: {e}\033[0m")
                results[port] = "ERROR"
        
        return results

    def udp_port_scan(self, host: str, ports: List[int] = None, timeout: float = None) -> Dict[int, str]:
        """Scan des ports UDP avec timeout configurable"""
        timeout = timeout or self.config['udp_scan_timeout']
        ports = ports or self.config['default_ports']
        
        results = {}
        
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            print(f"\033[91mImpossible de résoudre l'hôte: {host}\033[0m")
            return results
        
        print(f"\nScan UDP des ports sur {host} ({ip})...")
        print("\033[93mNote: Le scan UDP peut être peu fiable et prendre du temps\033[0m")
        
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    
                    # Envoi d'un paquet vide
                    s.sendto(b'', (ip, port))
                    
                    try:
                        # Essai de réception (certains services répondent même à des paquets vides)
                        data, addr = s.recvfrom(1024)
                        results[port] = "OPEN"
                        print(f"Port UDP {port}: \033[92mOPEN (réponse reçue)\033[0m")
                    except socket.timeout:
                        # Pas de réponse - peut être ouvert ou filtré
                        # Vérification supplémentaire avec un autre protocole si connu
                        if port == 53:  # DNS
                            try:
                                s.sendto(b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03', (ip, port))
                                data, addr = s.recvfrom(1024)
                                results[port] = "OPEN"
                                print(f"Port UDP {port}: \033[92mOPEN (DNS répond)\033[0m")
                            except:
                                results[port] = "OPEN|FILTERED"
                                print(f"Port UDP {port}: \033[93mOPEN|FILTERED\033[0m")
                        else:
                            results[port] = "OPEN|FILTERED"
                            print(f"Port UDP {port}: \033[93mOPEN|FILTERED\033[0m")
                    
            except KeyboardInterrupt:
                print("\033[93m\nScan interrompu par l'utilisateur\033[0m")
                break
            except Exception as e:
                print(f"\033[91mErreur lors du scan du port {port}: {e}\033[0m")
                results[port] = "ERROR"
        
        return results

    def scan_ip_range(self, ip_range: str, ports: List[int] = None, scan_type: str = 'tcp') -> Dict[str, Dict[int, str]]:
        """
        Scan une plage d'IP pour les ports spécifiés
        scan_type peut être 'tcp', 'udp' ou 'both'
        """
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            hosts = list(network.hosts())
            
            if len(hosts) > 255:
                confirm = input(f"\033[93mVous êtes sur le point de scanner {len(hosts)} hôtes. Continuer? (o/n): \033[0m")
                if confirm.lower() != 'o':
                    return {}
            
            results = {}
            
            for ip in hosts:
                ip_str = str(ip)
                print(f"\nScan de {ip_str}...")
                
                if not self.system_ping(ip_str):
                    print(f"{ip_str} \033[91mnon joignable\033[0m")
                    continue
                
                host_results = {}
                
                if scan_type in ['tcp', 'both']:
                    host_results['tcp'] = self.tcp_port_scan(ip_str, ports)
                
                if scan_type in ['udp', 'both']:
                    host_results['udp'] = self.udp_port_scan(ip_str, ports)
                
                if host_results:
                    results[ip_str] = host_results
            
            return results
            
        except ValueError as e:
            print(f"\033[91mPlage d'IP invalide: {e}\033[0m")
            return {}
        except Exception as e:
            print(f"\033[91mErreur lors du scan de plage: {e}\033[0m")
            return {}

def main():
    tools = NetworkTools()
    
    while True:
        print("\n" + "="*60)
        print("🛠️ OUTIL AVANCÉ DE DIAGNOSTIC RÉSEAU".center(60))
        print("="*60)
        print("1. ✅ Ping (ICMP echo request)")
        print("2. 📍 Traceroute (Chemin des paquets)")
        print("3. 🔍 Scan de ports TCP")
        print("4. 🔍 Scan de ports UDP")
        print("5. 🌐 Scan de plage d'IP")
        print("6. ⚙️ Configurer les paramètres")
        print("7. 💾 Afficher/sauvegarder les résultats")
        print("8. ❌ Quitter")
        print("="*60)
        
        choix = input("\nChoisissez une option (1-8): ")
        
        if choix == '1':  # Ping
            host = input("Entrez l'adresse IP ou le nom de domaine à pinger: ")
            count = input(f"Nombre de paquets [{tools.config['ping_count']}]: ")
            timeout = input(f"Timeout (s) [{tools.config['ping_timeout']}]: ")
            
            try:
                count = int(count) if count else tools.config['ping_count']
                timeout = float(timeout) if timeout else tools.config['ping_timeout']
            except ValueError:
                print("\033[91mValeurs invalides, utilisation des paramètres par défaut\033[0m")
                count = tools.config['ping_count']
                timeout = tools.config['ping_timeout']
            
            print(f"\nPing vers {host} avec {count} paquets...")
            result = tools.custom_ping(host, count, timeout)
            
            if result['is_alive']:
                print(f"\n\033[92m{host} est joignable\033[0m")
                print(f"Paquets: {result['packets_received']}/{result['packets_sent']} reçus")
                print(f"Temps: min={result['rtt_min']:.2f}ms, max={result['rtt_max']:.2f}ms, avg={result['rtt_avg']:.2f}ms")
            else:
                print(f"\n\033[91m{host} n'est pas joignable\033[0m")
            
            tools.save_results({'ping': result})
                
        elif choix == '2':  # Traceroute
            host = input("Entrez l'adresse IP ou le nom de domaine à tracer: ")
            max_hops = input(f"Nombre maximal de sauts [{tools.config['traceroute_max_hops']}]: ")
            timeout = input(f"Timeout par saut (s) [{tools.config['traceroute_timeout']}]: ")
            
            try:
                max_hops = int(max_hops) if max_hops else tools.config['traceroute_max_hops']
                timeout = float(timeout) if timeout else tools.config['traceroute_timeout']
            except ValueError:
                print("\033[91mValeurs invalides, utilisation des paramètres par défaut\033[0m")
                max_hops = tools.config['traceroute_max_hops']
                timeout = tools.config['traceroute_timeout']
            
            print(f"\nTraceroute vers {host} (max {max_hops} sauts)...")
            route = tools.traceroute(host, max_hops, timeout)
            
            if not route:
                print("\033[91mImpossible de tracer la route\033[0m")
            else:
                print("\nChemin emprunté:")
                print("-"*60)
                print("N°\tIP\t\t\tTemps (ms)")
                print("-"*60)
                for hop, ip, t in route:
                    print(f"{hop}\t{ip.ljust(16)}\t{t:.2f} ms")
            
            tools.save_results({'traceroute': {'host': host, 'route': route}})
                    
        elif choix == '3':  # Scan TCP
            host = input("Entrez l'adresse IP ou le nom de domaine à scanner: ")
            ports = input(f"Ports à scanner (séparés par des virgules) [défaut: {tools.config['default_ports']}]: ")
            timeout = input(f"Timeout (s) [{tools.config['tcp_scan_timeout']}]: ")
            
            try:
                scan_ports = [int(p.strip()) for p in ports.split(',')] if ports else tools.config['default_ports']
                timeout = float(timeout) if timeout else tools.config['tcp_scan_timeout']
            except ValueError:
                print("\033[91mFormat de ports invalide. Utilisation des ports par défaut.\033[0m")
                scan_ports = tools.config['default_ports']
                timeout = tools.config['tcp_scan_timeout']
            
            results = tools.tcp_port_scan(host, scan_ports, timeout)
            tools.save_results({'tcp_scan': {'host': host, 'ports': results}})
            
        elif choix == '4':  # Scan UDP
            host = input("Entrez l'adresse IP ou le nom de domaine à scanner: ")
            ports = input(f"Ports à scanner (séparés par des virgules) [défaut: {tools.config['default_ports']}]: ")
            timeout = input(f"Timeout (s) [{tools.config['udp_scan_timeout']}]: ")
            
            try:
                scan_ports = [int(p.strip()) for p in ports.split(',')] if ports else tools.config['default_ports']
                timeout = float(timeout) if timeout else tools.config['udp_scan_timeout']
            except ValueError:
                print("\033[91mFormat de ports invalide. Utilisation des ports par défaut.\033[0m")
                scan_ports = tools.config['default_ports']
                timeout = tools.config['udp_scan_timeout']
            
            results = tools.udp_port_scan(host, scan_ports, timeout)
            tools.save_results({'udp_scan': {'host': host, 'ports': results}})
            
        elif choix == '5':  # Scan de plage d'IP
            ip_range = input("Entrez la plage d'IP (ex: 192.168.1.0/24 ou 192.168.1.1-100): ")
            ports = input(f"Ports à scanner (séparés par des virgules) [défaut: {tools.config['default_ports']}]: ")
            scan_type = input("Type de scan (tcp/udp/both) [tcp]: ").lower() or 'tcp'
            
            try:
                scan_ports = [int(p.strip()) for p in ports.split(',')] if ports else tools.config['default_ports']
            except ValueError:
                print("\033[91mFormat de ports invalide. Utilisation des ports par défaut.\033[0m")
                scan_ports = tools.config['default_ports']
            
            if scan_type not in ['tcp', 'udp', 'both']:
                print("\033[91mType de scan invalide. Utilisation de 'tcp'.\033[0m")
                scan_type = 'tcp'
            
            results = tools.scan_ip_range(ip_range, scan_ports, scan_type)
            tools.save_results({'ip_range_scan': {'range': ip_range, 'type': scan_type, 'results': results}})
            
        elif choix == '6':  # Configuration
            print("\nConfiguration actuelle:")
            for key, value in tools.config.items():
                print(f"{key}: {value}")
            
            print("\nModifier un paramètre:")
            param = input("Nom du paramètre (vide pour annuler): ")
            
            if param and param in tools.config:
                new_value = input(f"Nouvelle valeur pour {param} [{tools.config[param]}]: ")
                
                try:
                    # Conversion automatique du type
                    if isinstance(tools.config[param], int):
                        tools.config[param] = int(new_value) if new_value else tools.config[param]
                    elif isinstance(tools.config[param], float):
                        tools.config[param] = float(new_value) if new_value else tools.config[param]
                    elif isinstance(tools.config[param], list):
                        if new_value:
                            tools.config[param] = [int(p.strip()) for p in new_value.split(',')]
                    else:
                        if new_value:
                            tools.config[param] = new_value
                    
                    print("\033[92mParamètre mis à jour\033[0m")
                except ValueError:
                    print("\033[91mValeur invalide pour ce paramètre\033[0m")
            elif param:
                print("\033[91mParamètre inconnu\033[0m")
                
        elif choix == '7':  # Sauvegarde
            filename = input(f"Nom du fichier de sortie [{tools.config['output_file']}]: ") or tools.config['output_file']
            tools.config['output_file'] = filename
            print("\033[92mLes résultats futurs seront sauvegardés dans ce fichier\033[0m")
            
        elif choix == '8':  # Quitter
            print("Au revoir!")
            break
            
        else:
            print("\033[91mOption invalide. Veuillez choisir entre 1 et 8.\033[0m")
        
        input("\nAppuyez sur Entrée pour continuer...")

if __name__ == "__main__":
    # Vérification des dépendances
    try:
        import icmplib
    except ImportError:
        print("\033[93mLa bibliothèque 'icmplib' est requise pour le ping maison.")
        print("Installation avec: pip install icmplib\033[0m")
        sys.exit(1)
    
    # Vérification des privilèges
    if platform.system().lower() != 'windows' and os.getuid() != 0:
        print("\033[93mAttention: Certaines fonctionnalités peuvent nécessiter des droits administrateur (sudo).\033[0m")
    
    main()