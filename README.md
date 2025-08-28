
## 🚀 EissamiXR - MultiProtocol VPN Manager

Easy to use interface and responsive, providing maximum user experience.


### Install Instructions
➽ Debian 10 & 11 (recommended)   
  

1.  :    
<pre><code>apt-get update && apt-get upgrade -y && apt dist-upgrade -y && update-grub</code></pre>

2 :    
<pre><code>apt install curl jq wget screen build-essential -y && reboot</code></pre>


### Ubuntu 18-20.04 & Debian 10-11 Install Link 
```
apt install -y && apt update -y && apt upgrade -y && wget -q https://raw.githubusercontent.com/Krimo44e/SDK/refs/heads/main/setup.sh && chmod +x setup.sh && ./setup.sh
```

## UPDATE SCRIPT
```
wget -q https://raw.githubusercontent.com/Krimo44e/SDK/refs/heads/main/update.sh && chmod +x update.sh && ./update.sh
```

### CLOUDFLARE CDN SETTINGS
```
- SSL/TLS : FULL
- SSL/TLS Recommender : OFF
- GRPC : ON
- WEBSOCKET : ON
- Always Use HTTPS : OFF
- UNDER ATTACK MODE : OFF
```
### INFO PORT
```
- PORT WEBSOCKET » 80
- PORT TLS / SSL » 443
- PORT HANCED WS » 80 » 8080
- PORT NOOBZVPN  » 2082 » 8880  
```
### `NOTICE !`
```
If You Get Service Off Status
Please Restart Service.
If Service Status Still Off
Please Reboot your VPS
```

### TELEGRAM BOT SETUP

- Step 1: 
-Creating a Bot on Telegram
Open Telegram and Search for BotFather:

Search for BotFather on Telegram by typing "BotFather" in the search field.
Select BotFather (the official account with a blue check mark).
Creating a New Bot:

Send a message /start to BotFather to get started.
Send a message /newbot to create a new bot.
Follow the instructions to provide a name and username for your bot.
Once completed, BotFather will provide a bot API token. Save this token because it will be used in your script.

- Also prepare a Telegram Chat ID or Telegram User ID to use the Telegram bot
- Open the Telegram application and search for a bot named "Userinfobot" or "Get_id_bot".
- 

Click "Start" to start the bot.
The bot will automatically send a message containing your chat ID.




### GET ROOT ACCESS OF YOUR VPS

``````

  wget -qO- -O aksesroot.sh https://raw.githubusercontent.com/Krimo44e/SDK/refs/heads/main/aksesroot.sh && bash aksesroot.sh

```````




### REINSTALL SCRIPT

```
curl -O https://raw.githubusercontent.com/Krimo44e/SDK/refs/heads/main/reinstall.sh
chmod +x reinstall.sh
bash reinstall.sh debian 11 --password YOUR_PASSWORD
```

### INSTALL HAPROXY - DEBIAN 11

```
sudo apt install -t bullseye-backports haproxy

sed -i "s#xxx#https://raw.githubusercontent.com/hokagelegend9999/alpha.v2/refs/heads/main/#g" /etc/haproxy/haproxy.cfg

sudo systemctl restart haproxy

sudo systemctl status haproxy
```
