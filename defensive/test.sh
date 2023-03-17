cat > /usr/local/etc/rules/local.rules << EOL
alert tcp any any -> 192.168.10.10 any (flags:R; msg: "RST attack detected"; sid: 1000002; rev: 1;)
alert icmp any any -> 192.168.10.10 any (msg:"Ping sweep with Nmap detected";itype:8; sid:1000003; rev:1;)
alert tcp any any -> 192.168.10.10 any (flags:S; detection_filter: track by_dst, count 70, seconds 10; msg:"SYN attack detected"; sid:1000001; rev:1;)
EOL