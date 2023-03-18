#!/bin/bash

# Vérifier que l'utilisateur a les privilèges d'administrateur
if [[ $EUID -ne 0 ]]; then
  echo "Ce script doit être exécuté avec les privilèges d'administrateur."
  exit 1
fi

#======================================================================================================================================================
#=================================== Installation de iptables =======================================================================
if ! [ -x "$(command -v iptables)" ]; then
  echo "iptables n'est pas installé, installation en cours..."
  apt-get update
  apt-get install iptables -y
  apt-get install iptables-persistent -y
  echo "iptables a été installé avec succès."

else
  echo "Iptables est déjà installé."
fi



#======================================================================================================================================================
#=================================== Installation de tshark et sa configuration =======================================================================
if ! [ -x "$(command -v tshark)" ]; then
  echo "Tshark n'est pas installé, installation en cours..."
  # Installer tshark
  apt-get -y install tshark
  # Vérifier l'installation en affichant la version de Tsark
  tshark -v
  #Définir la variable d'environnement PCAP_COMPRESSION à "gzip"(cette variable signifie que les paquets capturés avec Tshark seront compressés avec gzip avant d'être écrits dans le fichier de sortie.) de manière permanente en ajoutant cette commande dans le fichier de configuration .bashrc de l'utilisateur. La variable d'environnement sera exécutée à chaque ouverture d'un terminal.
  echo 'export PCAP_COMPRESSION=gzip' >> ~/.bashrc
else
  echo "Tshark est déjà installé."
fi


#==================================================================================================================================================
#=================================== Installation de yaf et sa configuration=======================================================================
if ! [ -x "$(command -v yaf)" ]; then
  echo "Yaf n'est pas installé, installation en cours..."
  # Installation des préliminares
  apt-get install -y libglib2.0-dev apt-get libfixbuf-dev libpcap0.8-dev
  #Télécharger le fichier compresser de Yaf et le décompresser
  cd /usr/src || exit
  wget https://tools.netsa.cert.org/releases/yaf-2.13.0.tar.gz
  tar -xzf yaf-2.13.0.tar.gz
  cd yaf-2.13.0
  #Configurer, compiler et installer Yaf
  ./configure
  make
  make install

else
  echo "Yaf est déjà installé."
fi

#=================================================================================================================================================
#=================================== Installation de snort et configuration =======================================================================

if ! [ -x "$(command -v snort)" ]; then
  #Installation de des dependences
  apt-get install libpcap-dev libpcre3-dev libnet1-dev zlib1g-dev libdnet-dev libdumbnet-dev bison flex liblzma-dev openssl libssl-dev pkg-config libhwloc-dev cmake libcmocka-dev libnetfilter-queue-dev libmnl-dev libunwind-dev libfl-dev c++14 ethtool  -y

  cd /usr/src || exit
  git clone https://github.com/snort3/libdaq.git

  cd libdaq
  ./bootstrap
  ./configure
  make
  make install

  cd .. || exit
  git clone https://luajit.org/git/luajit.git
  cd luajit
  make
  make install

  cd .. || exit
  wget https://github.com/gperftools/gperftools/releases/download/gperftools-2.9.1/gperftools-2.9.1.tar.gz
  tar xzf gperftools-2.9.1.tar.gz
  cd gperftools-2.9.1/
  ./configure
  make
  make install

#Installation de snort3
  cd .. || exit
  git clone https://github.com/snort3/snort3.git
  cd snort3
  ./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
  cd build
  make
  make install
  ldconfig
  echo "Snort a été installé avec succès !"
  snort -V
  #configuration d'interface eth1
  ip link set dev eth1 promisc on

  ethtool -K eth1 gro off lro off

  #Creation du fichier snort3-nic.service et sa configuation pour permettre la persistence des config du carte reseau àprès le demarage
  cat > /etc/systemd/system/snort3-nic.service << EOL
  [Unit]
  Description=Set Snort 3 NIC in promiscuous mode and Disable GRO, LRO on boot
  After=network.target

  [Service]
  Type=oneshot
  ExecStart=/usr/sbin/ip link set dev eth1 promisc on
  ExecStart=/usr/sbin/ethtool -K eth1 off lro off
  TimeoutStartSec=0
  RemainAfterExit=yes
  [Install]
  WantedBy=default.target
EOL

  mkdir /var/log/snort

  #cat >> /usr/local/etc/snort/snort.lua << EOL
  #alert_fast = {
  #  file = true,
  #  packet = false,
  #  limit = 10,
  #}
  #EOL

  #Droit Snort
  useradd -r -s /usr/sbin/nologin -M -c SNORT_IDS snort

#Création du service systemd pour demarrage de snort
  cat > /etc/systemd/system/snort3.service << EOL
  [Unit]
  Description=Snort Daemon
  After=syslog.target network.target

  [Service]
  Type=simple
  ExecStart=/usr/local/bin/snort -c /usr/local/etc/snort/snort.lua -s 65535 -k none -i eth1 -m 0x1b -u snort -g snort
  ExecStop=/bin/kill -9 $MAINPID

  [Install]
  WantedBy=multi-user.target
EOL

  systemctl daemon-reload

#Les droits de snort
  chmod -R 5775 /var/log/snort
  chown -R snort:snort /var/log/snort

  systemctl enable --now snort3-nic.service
  systemctl enable --now snort3

  #Règle snort
  mkdir /usr/local/etc/rules
else
  echo "Snort est déjà installé."
fi

#======================================================================================================================================================
#=================================== iptables Rules =======================================================================
if [ -x "$(command -v iptables)" ]; then

  iptables-restore < /etc/iptables/rules.v4
  # Configure les règles iptables
  echo "Configuration des règles iptables..."

  # Supprime toutes les règles actuelles
  iptables -F

  # Bloque toutes les connexions entrantes et sortantes par défaut
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT DROP

  #Bloqer les paquets ICMP
  iptables -A INPUT -p icmp --icmp-type 8 -j DROP

  # Pour bloquer les scans de port et autres
  iptables -N port-scanning
  iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
  iptables -A port-scanning -j DROP

  #Bloquer une attaque DOS
  iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
  iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP

  #Bloquer les adresse ip après certains nombres de tentative de connexion sur le port 23
  iptables -A INPUT -p tcp --dport 23 -m recent --name telnet --set
  iptables -A INPUT -p tcp --dport 23 -m recent --name telnet --update --seconds 60 --hitcount 4 -j DROP

  #SQL injection sql20
  iptables -A INPUT -p tcp --dport 3306 -m string --string "';" --algo bm -j DROP
  iptables -A INPUT -p tcp --dport 3306 -m string --string "--" --algo bm -j DROP
  iptables -A INPUT -p tcp --dport 3306 -m string --string "/*" --algo bm -j DROP

  #DOS Mysql
  iptables -A INPUT -p tcp --dport 3306 -m conntrack --ctstate NEW -m limit --limit 10/s --limit-burst 20 -j ACCEPT
  iptables -A INPUT -p tcp --dport 3306 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -p tcp --dport 3306 -j DROP

  echo "Rules iptables written successfully"
  iptables-save > /etc/iptables/rules.v4
  #iptables -L

fi

#=================================================================================================================================================
#=================================== Ecriture des règles snorts ==================================================================================
if [ -x "$(command -v snort)" ]; then
  cat > /usr/local/etc/rules/local.rules << EOL
  #Syn attaque alert
  alert tcp any any -> 192.168.10.10 any (flags:S; detection_filter: track by_dst, count 70, seconds 10; msg:"SYN attack detected"; sid:1000001; rev:1;)
  #RST attaque alert
  alert tcp any any -> 192.168.10.10 any (flags:R; msg: "RST attack detected"; sid: 1000002; rev: 1;)
  #ICMP attaque alert
  alert icmp any any -> 192.168.10.10 any (msg:"ICMP attaque detected";itype:8; sid:1000003; rev:1;)
  #SQL attaque alert
  alert tcp any any -> any any (msg:"SQL Injection attempt detected with Metasploit"; content:"SELECT"; content:"FROM"; content:"WHERE"; content:"--"; sid:1000004; rev:001;)
EOL
  echo "Rules snort written successfully"
  #snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/local.rules -i eth1 -A alert_fast -s 65535 -k none
  #Demarrage de snort 3 et son logging
  snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/local.rules -i eth1 -A alert_fast -s 65535 -k none -l /var/log/snort
fi
