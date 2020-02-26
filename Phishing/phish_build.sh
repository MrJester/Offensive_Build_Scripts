#!/bin/bash

#**************************************************************************#
#  Filename: phish_build.sh             (Created: 2020-02-26)              #
#                                       (Updated: YYYY-MM-DD)              #
#  Info:                                                                   #
#    Installs, configures, and deploys a phishing server with GoPhish.     #
#    Script based off this initial script:                                 #
#          https://github.com/n0pe-sled/Postfix-Server-Setup               #
#                                                                          #
#    Script Functions on Ubuntu 19.10, GoPhish 0.9.0                       #
#                                                                          #
#  Author:                                                                 #
#    Ryan Hays                                                             #
#**************************************************************************#
# TODO:
#


# Setup a log file to catch all output
exec > >(tee -ia /var/log/phish_build.log)
exec 2> >(tee -ia /var/log/phish_build_err.log)


##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal


##### Setup some global vars
STAGE=0
TOTAL=$(grep '(${STAGE}/${TOTAL})' $0 | wc -l);(( TOTAL-- ))
STARTTIME=$(date +%s)
export STAGING_KEY="RANDOM"
export DEBIAN_FRONTEND="noninteractive"


##### PRE CHECKS #####
##### Check if we are running as root - else this script will fail (hard!)
if [[ "${EUID}" -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" This script must be ${RED}run as root${RESET}" 1>&2
  echo -e ' '${RED}'[!]'${RESET}" Quitting..." 1>&2
  sleep 10
  exit 1
else
  echo -e " ${BLUE}[*]${RESET} ${BOLD}Phish Server Build Script${RESET}"
  sleep 3
fi

##### Fix display output for GUI programs (when connecting via SSH)
export DISPLAY=:0.0
export TERM=xterm

##### Change nameserver
echo 'nameserver 1.1.1.1' > /etc/resolv.conf

##### Check Internet access
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Checking ${GREEN}Internet access${RESET}"
#--- Can we ping google?
for i in {1..10}; do ping -c 1 -W ${i} www.google.com &>/dev/null && break; done
#--- Run this, if we can't
if [[ "$?" -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" ${RED}Possible DNS issues${RESET}(?)" 1>&2
  echo -e ' '${RED}'[!]'${RESET}" Will try and use ${YELLOW}DHCP${RESET} to 'fix' the issue" 1>&2
  chattr -i /etc/resolv.conf 2>/dev/null
  dhclient -r
  #--- Second interface causing issues?
  ip addr show eth1 &>/dev/null
  [[ "$?" == 0 ]] \
    && route delete default gw 192.168.155.1 2>/dev/null
  #--- Request a new IP
  dhclient
  dhclient eth0 2>/dev/null
  dhclient wlan0 2>/dev/null
  dhclient eth1 2>/dev/null
  #--- Wait and see what happens
  sleep 15s
  _TMP="true"
  _CMD="$(ping -c 1 8.8.8.8 &>/dev/null)"
  if [[ "$?" -ne 0 && "$_TMP" == "true" ]]; then
    _TMP="false"
    echo -e ' '${RED}'[!]'${RESET}" ${RED}No Internet access${RESET}" 1>&2
    echo -e ' '${RED}'[!]'${RESET}" You will need to manually fix the issue, before re-running this script" 1>&2
    sleep 10
    exit 1
  fi
  _CMD="$(ping -c 1 www.google.com &>/dev/null)"
  if [[ "$?" -ne 0 && "$_TMP" == "true" ]]; then
    _TMP="false"
    echo -e ' '${RED}'[!]'${RESET}" ${RED}Possible DNS issues${RESET}(?)" 1>&2
    echo -e ' '${RED}'[!]'${RESET}" You will need to manually fix the issue, before re-running this script" 1>&2
    sleep 10
    exit 1
  fi
  if [[ "$_TMP" == "false" ]]; then
    (dmidecode | grep -iq virtual) && echo -e " ${YELLOW}[i]${RESET} VM Detected"
    (dmidecode | grep -iq virtual) && echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Try switching network adapter mode${RESET} (e.g. NAT/Bridged)"
    echo -e ' '${RED}'[!]'${RESET}" Quitting..." 1>&2
    sleep 10
    exit 1
  fi
else
  echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Detected Internet access${RESET}" 1>&2
fi

CONTINUE='N'
read -p "Before continuing with this script make sure you have two servers setup Phishing and a Redirector along with those required IPs. You should also have the DNS entries also specified within your configuraiton.  Continue (y/N): " -r CONTINUE
if [[ "${CONTINUE^^}" == "N" ]]; then
  exit
fi

read -p "Enter your hostname/primary domain name eg: mail.example.com: " -r PRIDOMAIN

##### FUNCTIONS #####
##### Initial Ubuntu Config
if [[ ! -f /root/.phish_firstrun ]]; then
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Initial Ubuntu Configuration${RESET}"
  echo -e "\n\n ${BLUE}[*]${RESET} Installing Updates${RESET}"
  touch /root/.phish_firstrun

  apt-get -qq update > /dev/null 2>&1
  apt-get -qq -y upgrade > /dev/null 2>&1
  apt-get -qq -y dist-upgrade > /dev/null 2>&1
  apt-get -qq -y autoremove > /dev/null 2>&1

  apt-get install -qq -y nmap git \
  || echo -e "\n\n ${RED}[!] Issue with apt install${RESET}"

  update-rc.d nfs-common disable > /dev/null 2>&1
  update-rc.d rpcbind disable > /dev/null 2>&1

  cat <<-EOF >> /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.eth0.disable_ipv6 = 1
net.ipv6.conf.eth1.disable_ipv6 = 1
net.ipv6.conf.ppp0.disable_ipv6 = 1
net.ipv6.conf.tun0.disable_ipv6 = 1
EOF

  sysctl -p > /dev/null 2>&1

  echo -e "\n\n ${BLLUE}[*]${RESET} Changing Hostname${RESET}"

  cat <<-EOF > /etc/hosts
127.0.1.1 $PRIDOMAIN $PRIDOMAIN
127.0.0.1 localhost
EOF

  cat <<-EOF > /etc/hostname
$PRIDOMAIN
EOF

  echo -e "\n\n ${BLUE}[*]${RESET} The System will now reboot!${RESET}"
  echo -e "\n ${BLUE}{*]${RESET} Please rerun this script after the system comes back online${RESET}"
  sleep 5
  reboot
else
  rm -rf /root/.phish_firstrun > /dev/null 2>&1
  echo -e "${BLUE}[*] First run of the script already performed skipping this step.${RESET}"

  ##### SSH Configuration
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}SSH Configuration${RESET}"
  systemctl stop ssh.service > /dev/null 2>&1
  mkdir /etc/ssh/default_keys > /dev/null 2>&1
  mv /etc/ssh/ssh_host_* /etc/ssh/default_keys/
  dpkg-reconfigure openssh-server > /dev/null 2>&1
  systemctl enable ssh.service > /dev/null 2>&1
  systemctl start ssh.service > /dev/null 2>&1


  ##### SSL Configuration
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}SSL Configuration${RESET}"
  git clone -q -b master https://github.com/certbot/certbot.git /opt/letsencrypt \
	|| echo -e "${RED}[!] Issue when git cloning${RESET}" 1>&2

	pushd /opt/letsencrypt >/dev/null
	SECDOMAINS=()
	i=0
	while; do
	  read -p "Enter any secondary domains needed for engagement eg: website.example.com. Enter done to exit: " -r domain
	  if [[ "$domain" != "done" ]]; then
	    SECDOMAINS[$i]=$domain
	  else
	    break
	  fi
	  ((i++))
	done
	CLI_CMD="./certbot-auto certonly --standalone -d ${PRIDOMAIN}"
	for x in "${SECDOMAINS[@]}"; do
	  CLI_CMD="$CLI_CMD -d $x"
	done
	CLI_CMD="$CLI_CMD -n --register-unsafely-without-email --agree-tos"
  ${CLI_CMD}
  popd >/dev/null


  ##### GoPhish Installation
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}GoPhish Installation${RESET}"
  apt-get install -qq -y unzip \
  || echo -e "\n\n ${RED}[!] Issue with apt install${RESET}"
  rm -rf /opt/gophish
	wget -L -O '/tmp/gophish.zip' https://github.com/gophish/gophish/releases/download/v0.9.0/gophish-v0.9.0-linux-64bit.zip >/dev/null
	unzip -qq /tmp/gophish.zip -d /opt/gophish

	pushd /opt/gophish
	read -p "Enter the phishing domain being used: " -r PHISH_DOMAIN
  sed -i 's/"listen_url": "127.0.0.1:3333"/"listen_url": "0.0.0.0:3333"/g' config.json
  ssl_cert="/etc/letsencrypt/live/${PHISH_DOMAIN}/fullchain.pem"
  ssl_key="/etc/letsencrypt/live/${PHISH_DOMAIN}/privkey.pem"
  cp $ssl_cert ${PHISH_DOMAIN}.crt
  cp $ssl_key ${PHISH_DOMAIN}.key
  sed -i "s/0.0.0.0:80/0.0.0.0:443/g" config.json
  sed -i "s/gophish_admin.crt/${PHISH_DOMAIN}.crt/g" config.json
  sed -i "s/gophish_admin.key/${PHISH_DOMAIN}.key/g" config.json
  sed -i 's/"use_tls" : false/"use_tls" : true/g' config.json
  sed -i "s/example.crt/${PHISH_DOMAIN}.crt/g" config.json
  sed -i "s/example.key/${PHISH_DOMAIN}.key/g" config.json
  popd >/dev/null


  ##### Postfix, Dovecot Installation
  (( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Postfix & Dovecot Installation${RESET}"
  echo 'opendmarc opendmarc/dbconfig-install boolean false'|debconf-set-selection
  apt-get install -qq -y dovecot-imapd dovecot-lmtpd postfix postgrey postfix-policyd-spf-python opendkim opendkim-tools opendmarc mailutils \
  || echo -e "\n\n ${RED}[!] Issue with apt install${RESET}"

  ### Configuring Postfix
  reap -p "Enter the IP Address of the phishing redirector: " -r RED_IP
  cat <<-EOF > /etc/postfix/main.cf
smtpd_banner = \$myhostname ESMTP \$mail_name (Debian/GNU)
biff = no
append_dot_mydomain = no
readme_directory = no
smtpd_tls_cert_file=/etc/letsencrypt/live/${PRIDOMAIN}/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/${PRIDOMAIN}/privkey.pem
smtpd_tls_security_level = may
smtp_tls_security_level = encrypt
smtpd_tls_session_cache_database = btree:\/etc/postfix/smtpd_scache
smtp_tls_session_cache_database = btree:\/etc/postfix/smtp_scache
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = ${PRIDOMAIN}
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
mydestination = ${PRIDOMAIN}, localhost.com, , localhost
relayhost = ${RED_IP}:25
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_command = procmail -a "\$EXTENSION"
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = ipv4
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:12301,inet:localhost:54321
non_smtpd_milters = inet:12301,inet:localhost:54321
EOF

	cat <<-EOF >> /etc/postfix/master.cf
submission inet n       -       -       -       -       smtpd
-o syslog_name=postfix/submission
-o smtpd_tls_wrappermode=no
-o smtpd_tls_security_level=encrypt
-o smtpd_sasl_auth_enable=yes
-o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
-o milter_macro_daemon_name=ORIGINATING
-o smtpd_sasl_type=dovecot
-o smtpd_sasl_path=private/auth
EOF


	### Opendkim
	mkdir -p "/etc/opendkim/keys/${PRIDOMAIN}" >/dev/null 2>&1
	cp /etc/opendkim.conf /etc/opendkim.conf.orig

	cat <<-EOF > /etc/opendkim.conf
domain								*
AutoRestart						Yes
AutoRestartRate				10/1h
Umask									0002
Syslog								Yes
SyslogSuccess					Yes
LogWhy								Yes
Canonicalization			relaxed/simple
ExternalIgnoreList		refile:/etc/opendkim/TrustedHosts
InternalHosts					refile:/etc/opendkim/TrustedHosts
KeyFile								/etc/opendkim/keys/${PRIDOMAIN}/mail.private
Selector							mail
Mode									sv
PidFile								/var/run/opendkim/opendkim.pid
SignatureAlgorithm		rsa-sha256
UserID								opendkim:opendkim
Socket								inet:12301@localhost
EOF

	cat <<-EOF > /etc/opendkim/TrustedHosts
127.0.0.1
localhost
${PRIDOMAIN}
EOF

	cd "/etc/opendkim/keys/${PRIDOMAIN}" || exit
	opendkim-genkey -s mail -d "${PRIDOMAIN}"
	echo 'SOCKET="inet:12301"' >> /etc/default/opendkim
	chown -R opendkim:opendkim /etc/opendkim


	### OpenDMARC
	cat <<-EOF > /etc/opendmarc.conf
AuthservID ${PRIDOMAIN}
PidFile /var/run/opendmarc.pid
RejectFailures false
Syslog true
TrustedAuthservIDs ${PRIDOMAIN}
Socket  inet:54321@localhost
UMask 0002
UserID opendmarc:opendmarc
IgnoreHosts /etc/opendmarc/ignore.hosts
HistoryFile /var/run/opendmarc/opendmarc.dat
EOF

	mkdir "/etc/opendmarc/"
	echo "localhost" > /etc/opendmarc/ignore.hosts
	chown -R opendmarc:opendmarc /etc/opendmarc

	echo 'SOCKET="inet:54321"' >> /etc/default/opendmarc


	### Dovecot
 	cat <<-EOF > /etc/dovecot/dovecot.conf
disable_plaintext_auth = no
mail_privileged_group = mail
mail_location = mbox:~/mail:INBOX=/var/mail/%u

userdb {
  driver = passwd
}

passdb {
  args = %s
  driver = pam
}

protocols = " imap"

protocol imap {
  mail_plugins = " autocreate"
}

plugin {
  autocreate = Trash
  autocreate2 = Sent
  autosubscribe = Trash
  autosubscribe2 = Sent
}

service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }
}

ssl=required
ssl_cert = </etc/letsencrypt/live/${PRIDOMAIN}/fullchain.pem
ssl_key = </etc/letsencrypt/live/${PRIDOMAIN}/privkey.pem
EOF

	### Service Restart
	service postfix restart
	service opendkim restart
	service opendmarc restart
	service dovecot restart

  ##### Displaying DNS Records to Create

  EXTIP=$(curl -s http://ipinfo.io/ip)
	DOMAIN=$(ls /etc/opendkim/keys/ | head -1)
	FIELDS=$(echo "${DOMAIN}" | tr '.' '\n' | wc -l)
	DKIM_R=$(cut -d '"' -f 2 "/etc/opendkim/keys/${DOMAIN}/mail.txt" | tr -d "[:space:]")

	if [[ $FIELDS -eq 2 ]]; then
		cat <<-EOF > dnsentries.txt
DNS Entries for ${DOMAIN}:
====================================================================
Record Type: A
Host: @
Value: ${EXTIP}
TTL: 5 min

Record Type: TXT
Host: @
Value: v=spf1 ip4:${EXTIP} -all
TTL: 5 min

Record Type: TXT
Host: mail._domainkey
Value: ${DKIM_R}
TTL: 5 min

Record Type: TXT
Host: ._dmarc
Value: v=DMARC1; p=reject
TTL: 5 min

Change Mail Settings to Custom MX and Add New Record
Record Type: MX
Host: @
Value: ${DOMAIN}
Priority: 10
TTL: 5 min
EOF
		cat dnsentries.txt
	else
		prefix=$(echo "${DOMAIN}" | rev | cut -d '.' -f 3- | rev)
		cat <<-EOF > dnsentries.txt
DNS Entries for ${DOMAIN}:
====================================================================
Record Type: A
Host: ${prefix}
Value: ${EXTIP}
TTL: 5 min

Record Type: TXT
Host: ${prefix}
Value: v=spf1 ip4:${EXTIP} -all
TTL: 5 min

Record Type: TXT
Host: mail._domainkey.${prefix}
Value: ${DKIM_R}
TTL: 5 min

Record Type: TXT
Host: ._dmarc
Value: v=DMARC1; p=reject
TTL: 5 min

Change Mail Settings to Custom MX and Add New Record
Record Type: MX
Host: ${prefix}
Value: ${DOMAIN}
Priority: 10
TTL: 5 min
EOF
		cat dnsentries.txt
	fi
fi
