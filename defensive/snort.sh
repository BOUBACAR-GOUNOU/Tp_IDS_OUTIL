#!/bin/bash

# Vérifier que l'utilisateur a les privilèges d'administrateur
if [[ $EUID -ne 0 ]]; then
  echo "Ce script doit être exécuté avec les privilèges d'administrateur."
  exit 1
fi

if ! [ -x "$(command -v snort)" ]; then
#Installation des packges
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
else
  echo "Snort est déjà installé."
fi

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

mkdir /var/log/snort

cat > /usr/local/etc/snort/snort.lua << EOL
alert_fast = {
  file = true,
  packet = false,
  limit = 10,
}
EOL

#Droit Snort
useradd -r -s /usr/sbin/nologin -M -c SNORT_IDS snort

cat > /etc/systemd/system/snort3.service << EOL
[Unit]
Description=Snort Daemon
After=syslog.target network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snort -c /usr/local/etc/snort/snort.lua -s 65535 -k none -l /var/log/snort -D -i eth1 -m 0x1b -u snort -g snort
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


snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/local.rules -i enth1 -A alert_fast -s 65535 -k none -l /var/log/snort

