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

CONTINUE='N'
echo -e " ${BLUE}[*]${RESET} ${BOLD}Before continuing with this script make sure you have two servers setup Phishing and a Redirector along with\n those required IPs. You should also have the DNS entries also specified within your configuraiton.\nContinue (y/N): ${RESET}"
read -r CONTINUE
if [[ "${CONTINUE^^}" == "N" ]]; then
  exit
fi

echo -e " ${BLUE}[*]${RESET} ${BOLD}Enter your hostname/primary domain name eg: c2.example.com: ${RESET}"
read -r PRIDOMAIN

##### FUNCTIONS #####
##### Initial Ubuntu Config
if [[ ! -f /root/.phish_firstrun ]]; then
  (( STAGE++ )); echo -e "\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Initial Ubuntu Configuration${RESET}"
  echo -e "\n ${YELLOW}[i]${RESET} ${YELLOW}Installing Updates${RESET}"
  touch /root/.phish_firstrun

  ### Perfomring system updates
  apt-get -qq update >/dev/null 2>&1
  apt-get -qq -y upgrade >/dev/null 2>&1
  apt-get -qq -y dist-upgrade >/dev/null 2>&1
  apt-get -qq -y autoremove >/dev/null 2>&1
fi