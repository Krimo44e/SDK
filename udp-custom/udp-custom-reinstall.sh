#!/bin/bash

cd
rm -rf /root/udp
mkdir -p /root/udp

# Set system timezone to Africa/Casablanca (GMT+1 with DST adjustments)
echo -e "Configuring system timezone: Africa/Casablanca" | lolcat
ln -fs /usr/share/zoneinfo/Africa/Casablanca /etc/localtime


# install udp-custom
echo -e "Downloading UDP-Custom Binary..." | lolcat
wget -q https://raw.githubusercontent.com/Krimo44e/SDK/refs/heads/main/udp-custom/udp-custom-linux-amd64 -O /root/udp/udp-custom
chmod +x /root/udp/udp-custom

echo -e "Downloading Default Config..." | lolcat
wget -q https://raw.githubusercontent.com/Krimo44e/SDK/refs/heads/main/udp-custom/config.json -O /root/udp/config.json
chmod 644 /root/udp/config.json

if [ -z "$1" ]; then
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP-Custom by ePro Dev. Team

[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
else
cat <<EOF > /etc/systemd/system/udp-custom.service
[Unit]
Description=UDP-Custom by ePro Dev. Team

[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server -exclude $1
WorkingDirectory=/root/udp/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF
fi

echo start service udp-custom
systemctl start udp-custom &>/dev/null

echo enable service udp-custom
systemctl enable udp-custom &>/dev/null

echo -e "[✔] UDP-Custom installation completed successfully." | lolcat
sleep 2
reboot