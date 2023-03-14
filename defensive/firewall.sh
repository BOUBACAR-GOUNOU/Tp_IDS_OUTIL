
#!/bin/bash
# vérifie que le script est exécuté en mode superutilisateur
if [ "$EUID" -ne 0 ]
  then echo "Veuillez exécuter le script en tant que superutilisateur."
  exit
fi

# Installe iptables si ce n'est pas déjà fait
if ! command -v iptables &> /dev/null
 then
    echo "iptables n'est pas installé, installation en cours..."
    apt-get update
    apt-get install iptables -y
    echo "iptables a été installé avec succès."
 fi

echo "Le pare-feu iptables a été installé avec succès."



# Configure les règles iptables
echo "Configuration des règles iptables..."

# Supprime toutes les règles actuelles
iptables -F

# Bloque toutes les connexions entrantes et sortantes par défaut
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Autorise les connexions déjà établies
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Autorise le trafic SSH entrant
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Autorise le trafic HTTP et HTTPS entrant
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Configure les règles iptables
echo "Configuration des règles iptables..."

# Supprime toutes les règles actuelles
iptables -F

# Bloque toutes les connexions entrantes et sortantes par défaut
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Autorise les connexions déjà établies
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Autorise le trafic SSH entrant
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Autorise le trafic HTTP et HTTPS entrant
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Règles pour bloquer les attaques SYN, RST et ICMP
# Pour bloquer une attaque Syn :limiter le nombre de connexions TCP SYN simultanées en provenance d'une même adresse IP à un maximum de 10
iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 10 --connlimit-mask 32 -j DROP
#Pour bloquer une attaque RST : 
iptables -A INPUT -p tcp --tcp-flags RST RST -m state --state ESTABLISHED,RELATED -j DROP
#Pour bloquer une attaque ICMP : 
iptables -A INPUT -p icmp -m limit --limit 2/second --limit-burst 5 -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# Règles pour bloquer les attaques de service web et de base de données avec Metasploit
# Voici quelques exemples de scripts iptables pour contrer les attaques de service Web et de base de données Metasploit :
# Pour bloquer les attaques de service web : 
iptables -A INPUT -p tcp --dport 80 -m string --string "GET /" --algo bm -j DROP

# Pour bloquer les attaques d'injection SQL :
 
iptables -A INPUT -p tcp --dport 80 -m string --string "SELECT" --algo bm -j DROP
iptables -A INPUT -p tcp --dport 80 -m string --string "UNION" --algo bm -j DROP
iptables -A INPUT -p tcp --dport 80 -m string --string "INSERT" --algo bm -j DROP
iptables -A INPUT -p tcp --dport 80 -m string --string "UPDATE" --algo bm -j DROP
iptables -A INPUT -p tcp --dport 80 -m string --string "DELETE" --algo bm -j DROP


# Pour bloquer les attaques par piratage de session :
# Bloque les paquets avec un flag SYN et FIN à 1
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# Bloque les paquets avec un flag SYN et RST à 1
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# Bloque les paquets avec un flag FIN et RST à 1
iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP

# Bloque les paquets avec un flag FIN seulement
iptables -A INPUT -p tcp --tcp-flags FIN FIN -j DROP

# Bloque les paquets avec un flag RST seulement
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP

# Bloque les paquets avec un flag SYN et ACK à 0
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j DROP

# Bloque les paquets avec un flag ACK seulement et sans paquet préalable de SYN
iptables -A INPUT -p tcp --tcp-flags ACK ACK -m state --state NEW -j DROP



# Pour bloquer les attaques par dépassement de mémoire : 
iptables -A INPUT -p tcp --dport 22 -m limit --limit 5/minute --limit-burst 10 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP
#Ces règles limitent le nombre de connexions SSH entrantes à 5 par minute avec une "burst" de 10 connexions.
#Si un nombre supérieur de connexions est détecté, la règle suivante bloque les connexions entrantes sur le port 22.


# Pour bloquer les attaques par déni de service : 
# Limite le nombre de connexions simultanées TCP sur le port 23 à 10
iptables -A INPUT -p tcp --syn --dport 23 -m connlimit --connlimit-above 10 --connlimit-mask 32 -j DROP

# Limite le nombre de connexions simultanées TCP sur le port 80 à 50
iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 50 --connlimit-mask 32 -j DROP

# Limite le nombre de connexions simultanées UDP à 100
iptables -A INPUT -p udp --dport 0:65535 -m connlimit --connlimit-above 100 --connlimit-mask 0 -j DROP

# Bloquer les attaques par reconnaissance Nmap et Hping
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m recent --set --name nmap_scan
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m recent --update --seconds 60 --hitcount 10 --rttl --name nmap_scan -j DROP

iptables -A INPUT -p tcp --dport 23 -m string --string "hping" --algo bm -j DROP
iptables -A INPUT -p tcp --dport 80 -m string --string "hping" --algo bm -j DROP
iptables -A INPUT -p udp --dport 53 -m string --string "hping" --algo bm -j DROP


# Bloquer les attaques de dictionnaire sur le service telnet en utilisant hydra

iptables -A INPUT -p tcp --dport 23 -m string --string "hydra" --algo bm -j DROP

iptables -A INPUT -p tcp --dport 23 -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport 23 -m conntrack --ctstate NEW -m recent --update --seconds 30 --hitcount 4 -j DROP

iptables -A INPUT -p tcp --dport 23 -m conntrack --ctstate NEW -m recent --set --name TELNET
iptables -A INPUT -p tcp --dport 23 -m conntrack --ctstate NEW -m recent --update --seconds 120 --hitcount 4 --name TELNET -j DROP


iptables-save > /etc/iptables/rules.v4
iptables -L
