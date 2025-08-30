#!/bin/bash
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
purple="\e[0;33m"
# ===================
clear
# // Exporting IP Address Information
export IP=$( curl -sS icanhazip.com )

# // Clear Data
clear
clear && clear && clear
clear;clear;clear

clear
# Banner
set -euo pipefail

TITLE="EissamiXR TMD"
SUBTITLE="Welcome to EissamiXR TMD Installation Script (V4.5 Stable Edition)"
SLOGAN="Seamless Setup • Stable Performance • Future in Motion"

print_banner() {
  if command -v figlet >/dev/null 2>&1; then
    figlet -f standard "$TITLE"        | lolcat
  elif command -v toilet >/dev/null 2>&1; then
    toilet -f standard "$TITLE"        | lolcat
  else
    echo -e "$TITLE"              | lolcat
  fi

  echo -e "✨ $SUBTITLE ✨"        | lolcat
  echo -e "🚀 $SLOGAN 🚀"           | lolcat
}

print_banner

# echo -e "----------------------------------------------------------" | lolcat
# echo -e "[INFO] Welcome To EissamiXR TMD Installation Script (V4.5 Stable Edition)." | lolcat
# echo -e "[INFO] Checking OS Architecture..." | lolcat
# echo -e "----------------------------------------------------------" | lolcat
# echo -e "[INFO] Author : EissamiXR®" | lolcat
# echo -e "[INFO] Telegram : @EissamiXR" | lolcat
# echo -e "----------------------------------------------------------" | lolcat
# echo ""


echo -e ""
echo -e "[INFO] Checking OS Architecture..." | lolcat
sleep 2
# // Checking Os Architecture
if [[ $(uname -m | awk '{print $1}') == "x86_64" ]]; then
    echo -e "[✔] Architecture Supported ( $(uname -m) )." | lolcat
else
    echo -e "[✘] Architecture Not Supported ( $(uname -m) )." | lolcat
    exit 1
fi

# // Checking System
if [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "ubuntu" ]]; then
    echo -e "[✔] Operating System Supported ( $( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/\"//g' | sed 's/PRETTY_NAME//g' ) )." | lolcat
elif [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "debian" ]]; then
    echo -e "[✔] Operating System Supported ( $( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/\"//g' | sed 's/PRETTY_NAME//g' ) )." | lolcat
else
    echo -e "[✘] Operating System Not Supported ( $( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/\"//g' | sed 's/PRETTY_NAME//g' ) )." | lolcat
    exit 1
fi

# // Validate Successful
echo ""
read -p "$(echo -e '[INFO] Press Enter To Start Installation...' | lolcat) " _
echo ""
clear
if [ "${EUID}" -ne 0 ]; then
		echo -e "[✘] You Need To Run This Script As Root." | lolcat
		exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo -e "[✘] OpenVZ Is Not Supported." | lolcat
		exit 1
fi
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'

clear
apt install ruby -y >/dev/null 2>&1
gem install lolcat >/dev/null 2>&1
apt install wondershaper -y >/dev/null 2>&1
clear
# REPO
REPO="https://raw.githubusercontent.com/Krimo44e/SDK/refs/heads/main/"
# Detect primary network interface for vnstat-related steps
NET="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' || echo eth0)"
export NET


####
start=$(date +%s)
secs_to_human() {
    echo "Installation Time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}
### Status
function print_ok() {
    echo -e "[✔] $1" | lolcat
}
function print_install() {
    echo -e "[INFO] $1" | lolcat
    sleep 1
}
function print_error() {
    echo -e "[✘] $1" | lolcat
}
function print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "[✔] $1 Installed Successfully" | lolcat
        sleep 2
    fi
}

### Check Root
function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root User Detected. Starting Installation Process"
    else
        print_error "Current User Is Not Root. Please Switch To Root And Run This Script Again"
    fi
}

# Create Xray Directory
print_install "Creating Xray Directory..."
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1
# // Ram Information
mem_used=0
mem_total=0
while IFS=":" read -r a b; do
case $a in
    "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
    "Shmem") ((mem_used+=${b/kB}))  ;;
    "MemFree" | "Buffers" | "Cached" | "SReclaimable")
    mem_used="$((mem_used-=${b/kB}))"
;;
esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
export tanggal=`date -d "0 days" +"%d-%m-%Y - %X" `
export OS_Name=$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME//g' | sed 's/=//g' | sed 's/"//g' )
export Kernel=$( uname -r )
export Arch=$( uname -m )
export IP=$( curl -s https://ipinfo.io/ip/ )

# Change Environment System
function first_setup(){
    timedatectl set-timezone Africa/Casablanca
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Xray Directory"
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
        echo -e "[INFO] Setting Up Dependencies For $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/\"//g' | sed 's/PRETTY_NAME//g')..." | lolcat
        sudo apt update -y
        apt-get install --no-install-recommends software-properties-common -y
        add-apt-repository ppa:vbernat/haproxy-2.0 -y
        apt-get -y install haproxy=2.0.\*
    elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
        echo -e "[INFO] Setting Up Dependencies For $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/\"//g' | sed 's/PRETTY_NAME//g')..." | lolcat
        curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
        echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \
            http://haproxy.debian.net buster-backports-1.8 main \
            >/etc/apt/sources.list.d/haproxy.list
        sudo apt-get update -y
        apt-get -y install haproxy=1.8.\*
    else
        echo -e "[✘] Your Os Is Not Supported ( $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/\"//g' | sed 's/PRETTY_NAME//g') )." | lolcat
        exit 1
    fi
}

# GEO PROJECT
clear
function nginx_install() {
    # // Checking System
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
        print_install "Setting Up Nginx For $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/\"//g' | sed 's/PRETTY_NAME//g')"
        sudo apt-get install nginx -y
    elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
        print_success "Setting Up Nginx For $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/\"//g' | sed 's/PRETTY_NAME//g')"
        apt -y install nginx
    else
        echo -e "[✘] Your Os Is Not Supported ( $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/\"//g' | sed 's/PRETTY_NAME//g') )." | lolcat
    fi
}

# Update and remove packages
function base_package() {
    clear
    print_install "Installing Required Packages..."
    apt install zip pwgen openssl netcat socat cron bash-completion -y
    apt install figlet -y
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y
    systemctl enable chronyd >/dev/null 2>&1
    systemctl restart chronyd >/dev/null 2>&1
    systemctl enable chrony >/dev/null 2>&1
    systemctl restart chrony >/dev/null 2>&1
    chronyc sourcestats -v >/dev/null 2>&1
    chronyc tracking -v >/dev/null 2>&1
    apt install ntpdate -y
    ntpdate pool.ntp.org
    apt install sudo -y
    apt install ruby -y
    gem install lolcat >/dev/null 2>&1
    sudo apt-get clean all
    sudo apt-get autoremove -y
    sudo apt-get install -y debconf-utils
    sudo apt-get remove --purge exim4 -y
    sudo apt-get remove --purge ufw firewalld -y
    sudo apt-get install -y --no-install-recommends software-properties-common
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential ca-certificates iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa
    print_success "Required Packages"
}

clear
# Domain input function
# function pasang_domain() {
# echo -e ""
# clear
# echo -e "[INFO] Domain Setup." | lolcat
# echo -e "[INFO] 1) Enter Your Own Domain." | lolcat
# echo -e "[INFO] 2) Use A Random Domain." | lolcat
# read -p "$(echo -e 'Please Select 1–2 Or Any Other Key For Random: ' | lolcat)" host
# echo ""
# if [[ $host == "1" ]]; then
#     echo -e "[INFO] Please Enter Your Subdomain." | lolcat
#     read -p "$(echo -e 'Subdomain: ' | lolcat)" host1
#     echo "IP=" >> /var/lib/kyt/ipvps.conf
#     echo $host1 > /etc/xray/domain
#     echo $host1 > /root/domain
#     echo ""
# elif [[ $host == "2" ]]; then
#     # install cf
#     wget ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh
#     rm -f /root/cf.sh
#     clear
# else
#     print_install "Random Subdomain/Domain Will Be Used"
#     clear
# fi
# }
function pasang_domain() {
  echo -e ""
  clear
  echo -e "[INFO] Cloudflare Domain Setup" | lolcat
  echo -e "[INFO] 1) Type Your Own Domain" | lolcat
  echo -e "[INFO] 2) Use Script Domain" | lolcat
  read -r -p "$(echo -e 'Please Select [1–2] Or Any Other Key For Random: ' | lolcat)" host
  echo ""

  case "$host" in
    1)
      # Ask for subdomain until it looks valid
      while :; do
        echo -e "[INFO] Please Enter Your Subdomain (E.g., sub.example.com)." | lolcat
        read -r -p "$(echo -e 'Subdomain: ' | lolcat)" host1
        host1="${host1##*( )}"; host1="${host1%%*( )}"  # trim spaces

        # Light domain check (labels 1–63 chars, dots allowed, TLD 2+ letters)
        if [[ -n "$host1" && "$host1" =~ ^([a-zA-Z0-9-]{1,63}\.)+[A-Za-z]{2,63}$ ]]; then
          mkdir -p /var/lib/kyt >/dev/null 2>&1
          echo "IP=" >> /var/lib/kyt/ipvps.conf
          echo "$host1" > /etc/xray/domain
          echo "$host1" > /root/domain
          echo -e "[✔] Domain Saved: $host1" | lolcat
          echo ""
          break
        else
          echo -e "[✘] Invalid Domain Format. Please Try Again." | lolcat
        fi
      done
      ;;
    2)
      echo -e "[INFO] Generating Script Domain..." | lolcat
      # Fetch generator to a known path, run, then clean up
      if wget -qO /root/cf.sh "${REPO}files/cf.sh"; then
        chmod +x /root/cf.sh && /root/cf.sh
        rm -f /root/cf.sh
      else
        echo -e "[✘] Failed To Download cf.sh. Using Placeholder Domain." | lolcat
        rnd="auto-$RANDOM.example.net"
        mkdir -p /var/lib/kyt >/dev/null 2>&1
        echo "IP=" >> /var/lib/kyt/ipvps.conf
        echo "$rnd" > /etc/xray/domain
        echo "$rnd" > /root/domain
        echo -e "[✔] Using Placeholder Domain: $rnd" | lolcat
      fi
      clear
      ;;
    *)
      echo -e "[INFO] Random Subdomain/Domain Will Be Used." | lolcat
      # Optional fallback so later steps don’t fail if no domain generator is present
      if [[ ! -s /etc/xray/domain ]]; then
        rnd="auto-$RANDOM.example.net"
        mkdir -p /var/lib/kyt >/dev/null 2>&1
        echo "IP=" >> /var/lib/kyt/ipvps.conf
        echo "$rnd" > /etc/xray/domain
        echo "$rnd" > /root/domain
        echo -e "[✔] Using Placeholder Domain: $rnd" | lolcat
      fi
      clear
      ;;
  esac
}


clear
# Install SSL
function pasang_ssl() {
clear
print_install "Installing SSL Certificate On Domain..."
rm -rf /etc/xray/xray.key
rm -rf /etc/xray/xray.crt
domain=$(cat /root/domain)
STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
rm -rf /root/.acme.sh
mkdir /root/.acme.sh
systemctl stop $STOPWEBSERVER >/dev/null 2>&1
systemctl stop nginx >/dev/null 2>&1
curl -fsSL https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
chmod 777 /etc/xray/xray.key
print_success "SSL Certificate"
}

function make_folder_xray() {
rm -rf /etc/vmess/.vmess.db
rm -rf /etc/vless/.vless.db
rm -rf /etc/trojan/.trojan.db
rm -rf /etc/shadowsocks/.shadowsocks.db
rm -rf /etc/ssh/.ssh.db
rm -rf /etc/bot/.bot.db
rm -rf /etc/user-create/user.log
mkdir -p /etc/bot
mkdir -p /etc/xray
mkdir -p /etc/vmess
mkdir -p /etc/vless
mkdir -p /etc/trojan
mkdir -p /etc/shadowsocks
mkdir -p /etc/ssh
mkdir -p /usr/bin/xray/
mkdir -p /var/log/xray/
mkdir -p /var/www/html
mkdir -p /etc/kyt/limit/vmess/ip
mkdir -p /etc/kyt/limit/vless/ip
mkdir -p /etc/kyt/limit/trojan/ip
mkdir -p /etc/kyt/limit/ssh/ip
mkdir -p /etc/limit/vmess
mkdir -p /etc/limit/vless
mkdir -p /etc/limit/trojan
mkdir -p /etc/limit/ssh
mkdir -p /etc/user-create
chmod +x /var/log/xray
touch /etc/xray/domain
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /etc/vmess/.vmess.db
touch /etc/vless/.vless.db
touch /etc/trojan/.trojan.db
touch /etc/shadowsocks/.shadowsocks.db
touch /etc/ssh/.ssh.db
touch /etc/bot/.bot.db
echo "& plughin Account" >>/etc/vmess/.vmess.db
echo "& plughin Account" >>/etc/vless/.vless.db
echo "& plughin Account" >>/etc/trojan/.trojan.db
echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
echo "& plughin Account" >>/etc/ssh/.ssh.db
echo "echo -e 'VPS Config User Account'" >> /etc/user-create/user.log
}
# Install Xray
function install_xray() {
clear
print_install "Installing Xray Core (Latest)..."
domainSock_dir="/run/xray"; ! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
chown www-data.www-data $domainSock_dir

# Fetch Latest Xray Version
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version

# Fetch Server Config
wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1
wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1
domain=$(cat /etc/xray/domain)
IPVS=$(cat /etc/xray/ipvps)
print_success "Xray Core"

# Settings Up Nginx/Haproxy Config
clear
curl -s ipinfo.io/city >>/etc/xray/city
curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
print_install "Applying Configuration Packages..."
wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1
sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
sudo curl -fsSL https://raw.githubusercontent.com/Krimo44e/SDK/refs/heads/main/config/nginx.conf -o /etc/nginx/nginx.conf

cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem >/dev/null 2>&1

# Set Permission
chmod +x /etc/systemd/system/runn.service

# Create Service
rm -rf /etc/systemd/system/xray.service.d
cat >/etc/systemd/system/xray.service <<EOF
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
print_success "Configuration Packages"
}

function ssh(){
clear
print_install "Setting SSH Password Policy..."
wget -O /etc/pam.d/common-password "${REPO}files/password"
chmod +x /etc/pam.d/common-password

DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
# debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

# go to root
cd

# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Permissions
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# set time GMT +7 (kept as-is per original logic)
# ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
print_success "SSH Password Policy"
}

function udp_mini(){
clear
print_install "Installing UDP-Mini - IP & Quota Limit Service..."
wget -q https://raw.githubusercontent.com/Krimo44e/SDK/refs/heads/main/config/fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel

# Installing UDP Mini
mkdir -p /usr/local/kyt/
wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
chmod +x /usr/local/kyt/udp-mini
wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"
systemctl disable udp-mini-1
systemctl stop udp-mini-1
systemctl enable udp-mini-1
systemctl start udp-mini-1
systemctl disable udp-mini-2
systemctl stop udp-mini-2
systemctl enable udp-mini-2
systemctl start udp-mini-2
systemctl disable udp-mini-3
systemctl stop udp-mini-3
systemctl enable udp-mini-3
systemctl start udp-mini-3
print_success "UDP-Mini & IP-Quota Limit Service"
}

function ssh_slow(){
clear
print_install "Installing SlowDNS Server Module..."
wget -q -O /tmp/nameserver "${REPO}files/nameserver" >/dev/null 2>&1
chmod +x /tmp/nameserver
bash /tmp/nameserver | tee /root/install.log
print_success "SlowDNS Server Module"
}

clear
function ins_SSHD(){
clear
print_install "Installing SSHD Config..."
wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
chmod 700 /etc/ssh/sshd_config
/etc/init.d/ssh restart
systemctl restart ssh
/etc/init.d/ssh status
print_success "SSHD Config"
}

clear
# function ins_dropbear(){
# clear
# print_install "Installing Dropbear"
# apt-get install dropbear -y > /dev/null 2>&1
# wget -q -O /etc/default/dropbear https://raw.githubusercontent.com/Krimo44e/SDK/refs/heads/main/config/dropbear.conf
# chmod +x /etc/default/dropbear
# /etc/init.d/dropbear restart
# /etc/init.d/dropbear status
# print_success "Dropbear"
# }
function ins_dropbear(){
clear
print_install "Installing Dropbear..."
apt-get install dropbear -y
wget -q -O /etc/default/dropbear https://raw.githubusercontent.com/Krimo44e/SDK/refs/heads/main/config/dropbear.conf
chmod +x /etc/default/dropbear
/etc/init.d/dropbear restart
/etc/init.d/dropbear status
print_success "Dropbear"
}


function ins_udpSSH(){
clear
print_install "Installing UDP-Custom..."
wget -q https://raw.githubusercontent.com/Krimo44e/SDK/refs/heads/main/udp-custom/udp-custom.sh
chmod +x udp-custom.sh
bash udp-custom.sh
rm -fr udp-custom.sh
print_success "UDP-Custom"
}

clear
function ins_vnstat(){
clear
print_install "Installing Vnstat..."
apt -y install vnstat > /dev/null 2>&1
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev > /dev/null 2>&1
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
/etc/init.d/vnstat status
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
print_success "Vnstat"
}

function ins_openvpn(){
clear
print_install "Installing OpenVPN..."
wget -q https://raw.githubusercontent.com/Krimo44e/SDK/refs/heads/main/config/openvpn && chmod +x openvpn && ./openvpn
/etc/init.d/openvpn restart
print_success "OpenVPN"
}

function ins_backup(){
clear
print_install "Installing Wondershaper..."
# Install Wondershaper
cd /bin
git clone  https://github.com/magnific0/wondershaper.git
cd wondershaper
sudo make install
cd
rm -rf wondershaper
echo > /home/limit
}

clear
function ins_swab(){
clear
print_install "Installing 1Gb Swap..."
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1

# Create 1G Swap
dd if=/dev/zero of=/swapfile bs=1024 count=1048576
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

# Sync Time
chronyd -q 'server 0.id.pool.ntp.org iburst'
chronyc sourcestats -v >/dev/null 2>&1
chronyc tracking -v >/dev/null 2>&1

wget ${REPO}files/bbr.sh &&  chmod +x bbr.sh && ./bbr.sh
print_success "1Gb Swap"
}

function ins_Fail2ban(){
clear
print_install "Configuring Banner And Security..."
# (Fail2ban commented as in original)
# Install DDOS Flate
if [ -d '/usr/local/ddos' ]; then
	echo
	echo
	echo -e "[✘] Please Uninstall The Previous Version First." | lolcat
	exit 0
else
	mkdir /usr/local/ddos
fi

clear
# banner
echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear

# Change Banner
wget -O /etc/kyt.txt https://raw.githubusercontent.com/Krimo44e/SDK/refs/heads/main/files/issue.net
print_success "Banner And Security"
}

function ins_epro(){
clear
print_install "Installing ePro Websocket Proxy..."
wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
wget -O /usr/bin/tun.conf "${REPO}config/tun.conf" >/dev/null 2>&1
wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1
chmod +x /etc/systemd/system/ws.service
chmod +x /usr/bin/ws
chmod 644 /usr/bin/tun.conf
systemctl disable ws
systemctl stop ws
systemctl enable ws
systemctl start ws
systemctl restart ws
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
wget -O /usr/sbin/ftvpn "${REPO}files/ftvpn" >/dev/null 2>&1
chmod +x /usr/sbin/ftvpn
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# remove unnecessary files
cd
apt autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
print_success "ePro Websocket Proxy"
}

function noobzvpn(){
clear
print_install "Installing NoobzVPN..."
wget "${REPO}/noobzvpns.zip"
unzip noobzvpns.zip
cd noobzvpns
bash install.sh
rm noobzvpns.zip
systemctl restart noobzvpns
print_success "NoobzVPN"
}

function ins_restart(){
clear
print_install "Restarting All Packages..."
# init.d restarts
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/vnstat restart
# systemd
systemctl restart haproxy
/etc/init.d/cron restart
systemctl daemon-reload
systemctl start netfilter-persistent
systemctl enable --now nginx
systemctl enable --now xray
systemctl enable --now rc-local
systemctl enable --now dropbear
systemctl enable --now openvpn
systemctl enable --now cron
systemctl enable --now haproxy
systemctl enable --now netfilter-persistent
systemctl enable --now ws
systemctl enable --now fail2ban
# echo "unset HISTFILE" >> /etc/profile
cd
rm -f /root/openvpn
rm -f /root/key.pem
rm -f /root/cert.pem
print_success "All Packages Restarted -"
}

# Install Menu
function menu(){
    clear
    print_install "Installing Menu Packages..."
    wget ${REPO}menu/menu.zip
    unzip menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu
    rm -rf menu.zip
}

# Create Default Menu
# function profile(){
# clear
# cat >/root/.profile <<EOF
# # ~/.profile: executed by Bourne-compatible login shells.
# if [ "\$BASH" ]; then
#     if [ -f ~/.bashrc ]; then
#         . ~/.bashrc
#     fi
# fi
# mesg n || true
# menu
# EOF
# mkdir -p /root/.info
# curl -sS "ipinfo.io/org?token=7a814b6263b02c" > /root/.info/.isp
# cat >/etc/cron.d/xp_all <<-END
# 		SHELL=/bin/sh
# 		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# 		2 0 * * * root /usr/local/sbin/xp
#                 2 0 * * * root /usr/local/sbin/menu
# 	END
# 	cat >/etc/cron.d/logclean <<-END
# 		SHELL=/bin/sh
# 		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# 		*/20 * * * * root /usr/local/sbin/clearlog
# 		END
#     chmod 644 /root/.profile

#     cat >/etc/cron.d/daily_reboot <<-END
# 		SHELL=/bin/sh
# 		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# 		0 5 * * * root /sbin/reboot
# 	END
#     cat >/etc/cron.d/limit_ip <<-END
# 		SHELL=/bin/sh
# 		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# 		*/2 * * * * root /usr/local/sbin/limit-ip
#         END
#     cat >/etc/cron.d/lim-ip-ssh <<-END
# 		SHELL=/bin/sh
# 		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# 		*/1 * * * * root /usr/local/sbin/limit-ip-ssh
# 	END
#     cat >/etc/cron.d/limit_ip2 <<-END
# 		SHELL=/bin/sh
# 		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# 		*/2 * * * * root /usr/bin/limit-ip
# 	END
#     echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
#     echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
#     service cron restart
#     cat >/home/daily_reboot <<-END
# 		5
# 	END
# curl -sS "ipinfo.io/city?token=7a814b6263b02c" > /root/.info/.city
# cat >/etc/systemd/system/rc-local.service <<EOF
# [Unit]
# Description=/etc/rc.local
# ConditionPathExists=/etc/rc.local
# [Service]
# Type=forking
# ExecStart=/etc/rc.local start
# TimeoutSec=0
# StandardOutput=tty
# RemainAfterExit=yes
# SysVStartPriority=99
# [Install]
# WantedBy=multi-user.target
# EOF

# echo "/bin/false" >>/etc/shells
# echo "/usr/sbin/nologin" >>/etc/shells
# cat >/etc/rc.local <<EOF
# #!/bin/sh -e
# # rc.local
# # By default this script does nothing.
# iptables -I INPUT -p udp --dport 5300 -j ACCEPT
# iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
# systemctl restart netfilter-persistent
# exit 0
# EOF

# chmod +x /etc/rc.local

# AUTOREB=$(cat /home/daily_reboot)
# SETT=11
# if [ $AUTOREB -gt $SETT ]; then
#     TIME_DATE="PM"
# else
#     TIME_DATE="AM"
# fi
# print_success "Menu Packages"
# }

function profile(){
clear
cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "\$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF
mkdir -p /root/.info
curl -sS "ipinfo.io/org?token=7a814b6263b02c" > /root/.info/.isp
cat >/etc/cron.d/xp_all <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		2 0 * * * root /usr/local/sbin/xp
                2 0 * * * root /usr/local/sbin/menu
	END
	# (removed logclean cron: */20 clearlog)
    chmod 644 /root/.profile

    # (removed daily_reboot cron: 0 5 * * * reboot)

    cat >/etc/cron.d/limit_ip <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/2 * * * * root /usr/local/sbin/limit-ip
        END
    cat >/etc/cron.d/lim-ip-ssh <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/1 * * * * root /usr/local/sbin/limit-ip-ssh
	END
    cat >/etc/cron.d/limit_ip2 <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		*/2 * * * * root /usr/bin/limit-ip
	END
    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
    service cron restart

    # (removed helper file /home/daily_reboot)
curl -sS "ipinfo.io/city?token=7a814b6263b02c" > /root/.info/.city
cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

chmod +x /etc/rc.local

# (removed AUTOREB/SETT/TIME_DATE block tied to helper file)

print_success "Profile Configuration"
}


# Restart services after install
function enable_services(){
clear
print_install "Enabling Services..."
systemctl daemon-reload
systemctl start netfilter-persistent
systemctl enable --now rc-local
systemctl enable --now cron
systemctl enable --now netfilter-persistent
systemctl restart nginx
systemctl restart xray
systemctl restart cron
systemctl restart haproxy
print_success "Services Enabled -"
clear
}

# Install Script Function
function instal(){
clear
first_setup
nginx_install
base_package
make_folder_xray
pasang_domain
# password_default
pasang_ssl
install_xray
ssh
udp_mini
ssh_slow
ins_udpSSH
ins_SSHD
ins_dropbear
ins_vnstat
ins_openvpn
ins_backup
ins_swab
ins_Fail2ban
ins_epro
noobzvpn
ins_restart
menu
profile
enable_services
# restart_system
}
instal
echo ""
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain
# sudo hostnamectl set-hostname EissamiXR
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname EissamiXR
print_banner() {
  if command -v figlet >/dev/null 2>&1; then
    figlet -f standard "$TITLE"        | lolcat
  elif command -v toilet >/dev/null 2>&1; then
    toilet -f standard "$TITLE"        | lolcat
  else
    echo -e "$TITLE"              | lolcat
  fi

  echo -e "✨ $SUBTITLE ✨"        | lolcat
  echo -e "🚀 $SLOGAN 🚀"           | lolcat
}

print_banner
echo ""
echo "--------------------------------------------------------------------------------------"
echo ""
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH                 : 22, 53, 2222, 2269"  | tee -a log-install.txt
echo "   - SSH Websocket           : 80" | tee -a log-install.txt
echo "   - SSH SSL Websocket       : 443" | tee -a log-install.txt
echo "   - Stunnel5                : 222, 777" | tee -a log-install.txt
echo "   - Dropbear                : 109, 143" | tee -a log-install.txt
echo "   - Badvpn                  : 7100-7300" | tee -a log-install.txt
echo "   - Nginx                   : 81" | tee -a log-install.txt
echo "   - XRAY  Vmess TLS         : 443" | tee -a log-install.txt
echo "   - XRAY  Vmess None TLS    : 80" | tee -a log-install.txt
echo "   - XRAY  Vless TLS         : 443" | tee -a log-install.txt
echo "   - XRAY  Vless None TLS    : 80" | tee -a log-install.txt
echo "   - Trojan GRPC             : 443" | tee -a log-install.txt
echo "   - Trojan WS               : 443" | tee -a log-install.txt
echo "   - Trojan GO               : 443" | tee -a log-install.txt
echo "   - Sodosok WS/GRPC         : 443" | tee -a log-install.txt
echo "   - SLOWDNS                 : 53"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone                : Africa/Casablanca (GMT +1)"  | tee -a log-install.txt
echo "   - Fail2Ban                : [ON]"  | tee -a log-install.txt
echo "   - Dflate                  : [ON]"  | tee -a log-install.txt
echo "   - IPtables                : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot             : [ON]"  | tee -a log-install.txt
echo "   - IPv6                    : [OFF]"  | tee -a log-install.txt
echo "   - Autobackup Data" | tee -a log-install.txt
echo "   - AutoKill Multi Login User" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Fully automatic script" | tee -a log-install.txt
echo "   - VPS settings" | tee -a log-install.txt
echo "   - Admin Control" | tee -a log-install.txt
echo "   - Change port" | tee -a log-install.txt
echo "   - Restore Data" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo ""
echo ""
echo "--------------------------------------------------------------------------------------"
echo ""
echo "==============================-[ SCRIPT BY EissamiXR ]-==============================="
echo -e ""
echo ""
echo "" | tee -a log-install.txt
echo "Everything is Running OK... Thank You for Using EissamiXR Script!!"
sleep 1
echo -ne "[✔ COMPLETED ] SCRIPT INSTALLATION FINISHED, SYSTEM WILL REBOOT NOW"
reboot