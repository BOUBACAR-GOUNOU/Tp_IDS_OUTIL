#!/bin/bash

# Vérifier que l'utilisateur a les privilèges d'administrateur
if [[ $EUID -ne 0 ]]; then
  echo "Ce script doit être exécuté avec les privilèges d'administrateur."
  exit 1
fi

# Installation de tshark et sa configuration
if ! [ -x "$(command -v tshark)" ]; then
  echo "Tshark n'est pas installé, installation en cours..."
  # Installer tshark
  apt-get -y install tshark
  # Vérifier l'installation en affichant la version de Tsark
  tshark -v
  #Définir la variable d'environnement PCAP_COMPRESSION à "gzip"(cette variable signifie que les paquets capturés avec Tshark seront compressés avec gzip avant d'être écrits dans le fichier de sortie.) de manière permanente en ajoutant cette commande dans le fichier de configuration .bashrc de l'utilisateur. La variable d'environnement sera exécutée à chaque ouverture d'un terminal.
  echo 'export PCAP_COMPRESSION=gzip' >> ~/.bashrc
fi

# Installation de yaf et sa configuration
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
fi

#Installation des packges
if ! [ -x "$(command -v snort)" ]; then
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
  #configuration d'interface
  ip link set dev eth1 promisc on

  ethtool -K eth1 gro off lro off

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

  #==============================================================================================================
  #=================================== LOG =======================================================================
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

  chmod -R 5775 /var/log/snort
  chown -R snort:snort /var/log/snort

  systemctl enable --now snort3-nic.service
  systemctl enable --now snort3

  #Règle snort
  mkdir /usr/local/etc/rules

  cat > /usr/local/etc/rules/local.rules << EOL
  alert tcp any any -> 192.168.10.10 any (flags:S; detection_filter: track by_dst, count 70, seconds 10; msg:"SYN attack detected"; sid:1000001; rev:1;)
  alert tcp any any -> 192.168.10.10 any (flags:R; msg: "RST attack detected"; sid: 1000002; rev: 1;)
  alert icmp any any -> 192.168.10.10 any (msg:"Ping sweep with Nmap detected";itype:8; sid:1000003; rev:1;)
EOL

  #snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/local.rules -i eth1 -A alert_fast -s 65535 -k none
  snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/local.rules -i eth1 -A alert_fast -s 65535 -k none -l /var/log/snort
else
  echo "Snort est déjà installé."
fi


