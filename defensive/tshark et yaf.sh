#!/bin/bash

# Installation de tshark et sa configuration
if ! command -v tshark &> /dev/null
 then
    echo "Tshark n'est pas installé, installation en cours..."
    # Installer tshark 
    sudo apt-get install tshark
    # Vérifier l'installation en affichant la version de Tsark
    tshark -v
    #Définir la variable d'environnement PCAP_COMPRESSION à "gzip"(cette variable signifie que les paquets capturés avec Tshark seront compressés avec gzip avant d'être écrits dans le fichier de sortie.) de manière permanente en ajoutant cette commande dans le fichier de configuration .bashrc de l'utilisateur. La variable d'environnement sera exécutée à chaque ouverture d'un terminal.
    echo 'export PCAP_COMPRESSION=gzip' >> ~/.bashrc
fi


# Installation de yaf et sa configuration
if ! command -v yaf &> /dev/null
 then
    echo "Yaf n'est pas installé, installation en cours..."
    # Installation des préliminares
    sudo apt-get install libglib2.0-dev
    sudo apt-get install libfixbuf-dev
    sudo apt-get install libpcap0.8-dev
    #Télécharger le fichier compresser de Yaf et le décompresser
    wget https://tools.netsa.cert.org/releases/yaf-2.13.0.tar.gz
    tar -xzf yaf-2.13.0.tar.gz
    cd yaf-2.13.0
    #Configurer, compiler et installer Yaf
    ./configure
    make
    sudo make install
fi

