sudo useradd -r -s /usr/sbin/nologin -M -c SNORT_IDS snort

sudo cat > /etc/systemd/system/snort3.service << EOL
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

sudo systemctl daemon-reload

sudo chmod -R 5775 /var/log/snort
sudo chown -R snort:snort /var/log/snort

sudo systemctl enable --now snort3-nic.service
sudo systemctl enable --now snort3