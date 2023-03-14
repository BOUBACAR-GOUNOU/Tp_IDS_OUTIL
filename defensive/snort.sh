#!/bin/bash

# Vérifier que l'utilisateur a les privilèges d'administrateur
if [[ $EUID -ne 0 ]]; then
   echo "Ce script doit être exécuté avec les privilèges d'administrateur." 
   exit 1
fi

if ! [ -x "$(command -v snort)" ]; then
	#Installation des packges
	apt-get install libpcap-dev libpcre3-dev libnet1-dev zlib1g-dev libdnet-dev 	libdumbnet-dev bison flex liblzma-dev openssl libssl-dev pkg-config libhwloc-dev 	cmake libcmocka-dev libnetfilter-queue-dev libmnl-dev libunwind-dev libfl-dev c++14  -y

	cd /usr/src
	git clone https://github.com/snort3/libdaq.git

	cd libdaq
	./bootstrap
	./configure --prefix=/usr/local/lib/daq_s3
	make install

	cd ..
	git clone https://luajit.org/git/luajit.git
	cd luajit
	make 
	make install

#Installation de snort3
	cd ..
	git clone https://github.com/snort3/snort3.git
	cd snort3
	./configure_cmake.sh --prefix=/usr/local
	cd build
	make 
	make install
	ldconfig
	echo "Snort a été installé avec succès !"
else
     echo "Snort est déjà installé."
fi
