#!/bin/bash

#**************************************************************************#
#  Filename: c2_server_build.sh             (Created: 2020-02-28)          #
#                                           (Updated: YYYY-MM-DD)          #
#  Info:                                                                   #
#    Installs, configures, and deploys a command and control server.       #
#    Allows the user to pick from the following C2 Software:               #
#           - Posh C2                                                      #
#                                                                          #
#    Script has been tested and working on the following:                  #
#       Operating System                                                   #
#           Ubuntu 19.10                                                   #
#                                                                          #
#  Author:                                                                 #
#    Ryan Hays                                                             #
#**************************************************************************#
# TODO:
#   - Convert this to a SaltStack deployment
#   - Add an alias to update redirector IP
#**************************************************************************#

# Setup a log file to catch all output
exec > >(tee -ia /var/log/c2_server_build.log)
exec 2> >(tee -ia /var/log/c2_server_build_err.log)


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
AVAIL_C2=(posh msf)


##### PRE CHECKS #####
##### Check if we are running as root - else this script will fail (hard!)
if [[ "${EUID}" -ne 0 ]]; then
  echo -e " ${RED}[!]${RESET} This script must be ${RED}run as root${RESET}"
  echo -e " ${RED}[!]${RESET} Quitting..."
  exit 1
else
  echo -e " ${BLUE}[*]${RESET} ${BOLD}Phish Server Build Script${RESET}"
  sleep 3
fi

##### Checks for valid C2 framewokr provided
if [ "$1" == "" ]; then
  echo -e " ${RED}[!]${RESET} You must specify a type of C2 framework to deploy."
  echo -e " ${RED}[!]${RESET} Available Frameworks: "
  echo -e "     ${YELLOW}[i]${RESET} posh     PoshC2 - https://github.com/nettitude/PoshC2"
  echo -e "     ${YELLOW}[i]${RESET} msf      Metasploit - https://github.com/rapid7/metasploit-framework"
  exit 1
fi
C2SERVER=${1^^}

##### Fix display output for GUI programs (when connecting via SSH)
export DISPLAY=:0.0
export TERM=xterm

##### Change nameserver
echo 'nameserver 1.1.1.1' > /etc/resolv.conf

##### Check Internet access
(( STAGE++ )); echo -e "\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Checking ${GREEN}Internet access${RESET}"
#--- Can we ping google?
for i in {1..10}; do ping -c 1 -W ${i} www.google.com &>/dev/null && break; done
#--- Run this, if we can't
if [[ "$?" -ne 0 ]]; then
  echo -e "\n ${RED}[!]${RESET} ${RED}Possible DNS issues${RESET}(?)" 1>&2
  echo -e "\n ${RED}[!]${RESET} Will try and use ${YELLOW}DHCP${RESET} to 'fix' the issue" 1>&2
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
    echo -e "\n ${RED}[!]${RESET} ${RED}No Internet access${RESET}" 1>&2
    echo -e "\n ${RED}[!]${RESET} You will need to manually fix the issue, before re-running this script" 1>&2
    sleep 10
    exit 1
  fi
  _CMD="$(ping -c 1 www.google.com &>/dev/null)"
  if [[ "$?" -ne 0 && "$_TMP" == "true" ]]; then
    _TMP="false"
    echo -e "\n ${RED}[!]${RESET} ${RED}Possible DNS issues${RESET}(?)" 1>&2
    echo -e "\n ${RED}[!]${RESET} You will need to manually fix the issue, before re-running this script" 1>&2
    sleep 10
    exit 1
  fi
  if [[ "$_TMP" == "false" ]]; then
    (dmidecode | grep -iq virtual) && echo -e " ${YELLOW}[i]${RESET} VM Detected"
    (dmidecode | grep -iq virtual) && echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Try switching network adapter mode${RESET} (e.g. NAT/Bridged)"
    echo -e "\n ${RED}[!]${RESET} Quitting..." 1>&2
    sleep 10
    exit 1
  fi
else
  echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Detected Internet access${RESET}" 1>&2
fi


echo -e " ${BLUE}[*]${RESET} ${BOLD}Enter your hostname/primary domain name eg: c2.example.com: ${RESET}"
read -r PRIDOMAIN

##### FUNCTIONS #####
##### Initial Ubuntu Config
if [[ ! -f /root/.c2_firstrun ]]; then
  (( STAGE++ )); echo -e "\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Initial Ubuntu Configuration${RESET}"
  echo -e "\n ${YELLOW}[i]${RESET} ${YELLOW}Installing Updates${RESET}"
  touch /root/.c2_firstrun

  ### Perfomring system updates
  apt-get -qq update >/dev/null 2>&1
  apt-get -qq -y upgrade >/dev/null 2>&1
  apt-get -qq -y dist-upgrade >/dev/null 2>&1
  apt-get -qq -y autoremove >/dev/null 2>&1

  ### Disabling IPv6
  update-rc.d nfs-common disable >/dev/null 2>&1
  update-rc.d rpcbind disable >/dev/null 2>&1

  cat <<-EOF >> /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.eth0.disable_ipv6 = 1
net.ipv6.conf.eth1.disable_ipv6 = 1
net.ipv6.conf.ppp0.disable_ipv6 = 1
net.ipv6.conf.tun0.disable_ipv6 = 1
EOF

  sysctl -p >/dev/null 2>&1

  ### Updating hostname
  cat <<-EOF > /etc/hosts
127.0.1.1 $PRIDOMAIN $PRIDOMAIN
127.0.0.1 localhost
EOF

  cat <<-EOF > /etc/hostname
$PRIDOMAIN
EOF

  ### Bash Aliases
  cat <<-EOF > /root/.bash_aliases
## grep aliases
alias grep="grep --color=always"
alias ngrep="grep -n"

alias egrep="egrep --color=auto"

alias fgrep="fgrep --color=auto"

## Checksums
alias sha1="openssl sha1"
alias md5="openssl md5"

## List open ports
alias ports="netstat -tulanp"

## Get external IP address
alias ipx="curl -s http://ipinfo.io/ip"

## Directory navigation aliases
alias ..="cd .."
alias ...="cd ../.."
alias ....="cd ../../.."
alias .....="cd ../../../.."

## Update the OS
alias update-os='apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y && apt autoremove -y'

## Extract file
## Extract file, example. "ex package.tar.bz2"
ex() {
  if [[ -f \$1 ]]; then
    case \$1 in
      *.tar.bz2) tar xjf \$1 ;;
      *.tar.gz)  tar xzf \$1 ;;
      *.bz2)     bunzip2 \$1 ;;
      *.rar)     rar x \$1 ;;
      *.gz)      gunzip \$1  ;;
      *.tar)     tar xf \$1  ;;
      *.tbz2)    tar xjf \$1 ;;
      *.tgz)     tar xzf \$1 ;;
      *.zip)     unzip \$1 ;;
      *.Z)       uncompress \$1 ;;
      *.7z)      7z x \$1 ;;
      *)         echo \$1 cannot be extracted ;;
    esac
  else
    echo \$1 is not a valid file
  fi
}

## openvas
alias openvas="openvas-stop; openvas-start; sleep 3s; xdg-open https://127.0.0.1:9392/ >/dev/null 2>&1"
EOF

  echo -e "\n ${YELLOW}[i]${RESET} ${YELLOW}The System will now reboot!${RESET}"
  echo -e "\n ${YELLOW}[i]${RESET} ${YELLOW}Please rerun this script after the system comes back online.${RESET}"
  sleep 5
  reboot
else
  rm -rf /root/.c2_firstrun >/dev/null 2>&1
  echo -e "\n ${YELLOW}[i]${RESET} ${YELLOW}First run of the script already performed skipping this step.${RESET}"

  ##### SSH Configuration
  (( STAGE++ )); echo -e "\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}SSH Configuration${RESET}"
  systemctl stop ssh.service >/dev/null 2>&1
  mkdir /etc/ssh/default_keys >/dev/null 2>&1
  mv /etc/ssh/ssh_host_* /etc/ssh/default_keys/
  dpkg-reconfigure openssh-server >/dev/null 2>&1
  sed -i "s/PermitRootLogin yes/PermitRootLogin without-password/g" /etc/ssh/sshd_config
  systemctl enable ssh.service >/dev/null 2>&1
  systemctl start ssh.service >/dev/null 2>&1

  case $C2SERVER in
    POSH)
      curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | bash
      ;;
    MSF)
      apt-get install -qq -y autoconf bison build-essential curl git-core libapr1 libaprutil1 libcurl4-openssl-dev \
      libgmp3-dev libpcap-dev libpq-dev libreadline6-dev libsqlite3-dev libssl-dev libsvn1 libtool libxml2 libxml2-dev \
      libxslt-dev libyaml-dev locate ncurses-dev openssl postgresql postgresql-contrib wget xsel zlib1g \
      zlib1g-dev >/dev/null 2>&1 \
      || echo -e "\n ${RED}[!] Issue with apt install${RESET}"
      pushd /tmp
      wget -O - https://apt.metasploit.com/metasploit-framework.gpg.key | apt-key add -
      wget --quiet -L -O msfinstall https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb
      chmod 755 msfinstall
      ./msfinstall

      update-rc.d postgresql enable
      sudo -u postgres msfdb init --user postgres --password password

      popd >/dev/null
      ;;
  esac
fi

##### CLEANUP #####
##### Clean the system
(( STAGE++ )); echo -e "\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Cleaning${RESET} the system"
#--- Clean package manager
for FILE in clean autoremove; do apt-get -y -qq "${FILE}"; done
apt-get -y -qq purge $(dpkg -l | tail -n +6 | egrep -v '^(h|i)i' | awk '{print $2}')   # Purged packages
#--- Update slocate database
updatedb
#--- Reset folder location
cd ~/ &>/dev/null
#--- Remove any history files (as they could contain sensitive info)
history -c 2>/dev/null
for i in $(cut -d: -f6 /etc/passwd | sort -u); do
[[ -e "${i}" ]] && find "${i}" -type f -name '.*_history' -delete
done

##### Time taken
FINISHTIME=$(date +%s)

cat dnsentries.txt
echo -e "\n ${YELLOW}[i]${RESET} Time (roughly) taken: ${YELLOW}$(( $(( FINISHTIME - STARTTIME )) / 60 )) minutes${RESET}"
echo -e "\n ${YELLOW}[i]${RESET} Please reboot the system now to ensure all changes are taken. ${YELLOW}${RESET}"