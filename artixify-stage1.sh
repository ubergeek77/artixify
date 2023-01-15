#!/bin/bash

# Exit on error
set -e

#####################################################################
###                                                               ###
###                           artixify                            ###
###                                                               ###
### Provision a new Artix installation, on this server, right now ###
###                                                               ###
#####################################################################

# !!     Please edit artixify.env to configure your new server       !! #
# !!                                                                 !! #
# !! Alternatively, you can manually edit the default settings below !! #

# Check the shell we are running with, exit if not bash
CURRENT_SHELL="$(ps -o args= -p "$$" | cut -f1 -d' ')"
if ! case $CURRENT_SHELL in *bash) ;; *) false ;; esac then
	echo "This script must be run with bash." >&2
	exit 1
fi

# Only run this script as root
if [ "$(id -u)" -ne 0 ]; then
	echo 'This script must be run as root.' >&2
	exit 1
fi

# Utility function for setting default variables
# $1 - The environment variable to set to a default value
# $2 - The default value
default_env() {
	_CHECK_ENV="$1"
	shift 1
	if [[ -z "${!_CHECK_ENV}" ]]; then
		eval $_CHECK_ENV="'$@'"
		export $_CHECK_ENV
	fi
}

if [[ -f ./artixify.env ]]; then
	source ./artixify.env || true
fi

##########################################################
################# BEGIN SETTINGS SECTION #################
##########################################################

# HOW TO USE:
# - Edit any default_env statement to whatever setting you like
# - Alternatively, place your settings in artixify.env next to this script
#   - If you do so, they will take precedent over the default_env statements
#   - You may use bash notation in artixify.env (like for arrays)

############################
### takeover.sh settings ###
############################

# The version of Alpine to use as a rootfs
default_env ALPINE_VERSION "3.17.1"

# The Alpine version string with only the major/minor fields
default_env ALPINE_MAJOR_MINOR "$(echo $ALPINE_VERSION | awk -F '.' '{ print $1"."$2 }')"

# The URL to use for downloading, here for configuration in case they change servers or something
default_env ALPINE_URL "https://dl-cdn.alpinelinux.org/alpine/v$ALPINE_MAJOR_MINOR/releases/x86_64/alpine-minirootfs-${ALPINE_VERSION}-x86_64.tar.gz"

# The URL to use to download a static version of busybox
default_env BUSYBOX_STATIC_URL "https://busybox.net/downloads/binaries/1.28.1-defconfig-multiarch/busybox-x86_64"

#####################
### User Settings ###
#####################

# Required; this user will be added to sudo group and will be the first SSH user
default_env NEW_USER "artix"

# Required; the password to use for the new account
default_env NEW_PASS "artix"

# Optional
# If set, will fill NEW_PUBKEY_STRING with the contents of the file specified
default_env NEW_PUBKEY_PATH ""

# Required; the SSH public key for the new account, in ~/.ssh/authorized_keys format
# Example:
# NEW_PUBKEY_STRING="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOVdSQsfxi6jUDILrK35SOcwIxys4cettzc4x4MOzUi0 comment"
# The new server will be installed with password authentication disabled,
# so you MUST provide a public key for which you have the private key for!
default_env NEW_PUBKEY_STRING ""

# Optional; UID to use when creating the user
default_env NEW_UID ""

# Optional; GID to use when creating the user
default_env NEW_GID ""

# Optional; If set to 1, the password will need to be changed on first login
default_env FORCE_PASS_CHANGE "1"

# Optional; list of groups to add the new user to (space separated)
# Can provide in group:gid format to specify new gid
# Groups will be created if they do not exist (existing groups will not be modified)
# Add via bash array +=("") notation
if [[ -z "$NEW_GROUPS" ]]; then
	declare -a NEW_GROUPS=()
	# NEW_GROUPS+=("example")
	# NEW_GROUPS+=("group:1001")
fi

########################
### Network Settings ###
########################

# Optional; the primary wired interface to use
# If unset, "eth0" will be used
# Be careful! Even on the same hardware, some distros name interfaces differently
# i.e. ens3 on Ubuntu is eth0 on Artix
default_env WIRED_IFACE ""

# Optional; the hostname to use for the new system
default_env NEW_HOSTNAME "artix"

# Optional; the DNS servers to add to resolv.conf
# Add via bash array +=("") notation
if [[ -z "${DNS_SERVERS}" ]]; then
	declare -a DNS_SERVERS=()
	DNS_SERVERS+=("1.1.1.1")
	DNS_SERVERS+=("1.0.0.1")
fi

# Optional; timezone in Zoneinfo format
# If unset, defaults to America/Chicago
default_env TIMEZONE ""

# Optional; The static IP to configure the server with
# REQUIRES IPV4_NETMASK and IPV4_GATEWAY to be set!
default_env IPV4_STATIC ""

# Optional; The netmask to configure the server with
default_env IPV4_NETMASK ""

# Optional; The gateway to configure the server with
default_env IPV4_GATEWAY ""

# Optional; The static IPv6 to configure the server with
# REQUIRES IPV6_PREFIX and IPV6_GATEWAY to be set!
default_env IPV6_STATIC ""

# Optional; The IPv6 prefix length to configure the server with
default_env IPV6_PREFIX ""

# Optional; The IPv6 gateway to configure the server with
default_env IPV6_GATEWAY ""

#####################
### Disk Settings ###
#####################

# Required; the block device to partition
default_env BLOCK_DEVICE "/dev/sda"

# Optional; whether or not to make a swap partition (1 for enabled)
default_env MAKE_SWAP "1"

# Optional; the size of the new swap partition in fdisk format +/-size{K,M,G,T,P} i.e 1024M, 2G
# If unset, but MAKE_SWAP==1, a swap size of 1024M will be used
default_env SWAP_SIZE "4096M"

########################
### Package Settings ###
########################

# These are all the Artix/Arch packages that will be installed to the new system

# Strictly necessary, bare-bones packages
export CORE_PKGS="artools-base base base-devel bash chrony chrony-runit connman-runit dhcpcd dhcpcd-runit elogind-runit git grub iptables iptables-runit linux linux-firmware openssh openssh-runit os-prober runit"

# Common packages that are more or less expected to have
export COMMON_PKGS="cronie cronie-runit lsof syslog-ng syslog-ng-runit unzip vi vim wget which"

# Miscellaneous packages that are typically useful, especially for developers
export UTIL_PKGS="bash-completion less man-db man-pages pacman-contrib tmux util-linux"

# Security related packages
export SECURITY_PKGS="fail2ban fail2ban-runit ufw ufw-runit"

# Combine the above package lists
export BASESTRAP_PKGS="${CORE_PKGS} ${COMMON_PKGS} ${UTIL_PKGS} ${SECURITY_PKGS}"

# Specify your own packages here; feel free to delete or add any as you like
default_env EXTRA_PKGS "bind-tools gnu-netcat jq neofetch net-tools nmap whois"

# Optional; the git repositories, if any, to install via PKGBUILD (i.e. AUR packages)
# Add via bash array +=("") notation
if [[ -z "${PKGBUILD_REPOS}" ]]; then
	declare -a PKGBUILD_REPOS=()
	PKGBUILD_REPOS+=("https://aur.archlinux.org/yay.git")
	PKGBUILD_REPOS+=("https://aur.archlinux.org/rsv.git")
	PKGBUILD_REPOS+=("https://github.com/ubergeek77/svlogger.git")
fi

# The runit services that are included in BASESTRAP_PKGS
# that will be enabled by default
# This is not intended to be modified;
# Please use CUSTOM_SVC to define your own services to enable by default
export DEFAULT_SVC="chrony connmand cronie dhcpcd fail2ban ip6tables iptables sshd syslog-ng ufw"

# Optional; additional runit services to configure to run at boot (space-separated)
default_env CUSTOM_SVC ""

##########################################################
################## END SETTINGS SECTION ##################
##########################################################

######################
### Commands Check ###
######################

# List of commands this script needs in order to continue
declare -a REQUIRED_CMDS=()
REQUIRED_CMDS+=("awk")
REQUIRED_CMDS+=("chmod")
REQUIRED_CMDS+=("chroot")
REQUIRED_CMDS+=("cp")
REQUIRED_CMDS+=("cut")
REQUIRED_CMDS+=("git")
REQUIRED_CMDS+=("grep")
REQUIRED_CMDS+=("lsblk")
REQUIRED_CMDS+=("mkdir")
REQUIRED_CMDS+=("mount")
REQUIRED_CMDS+=("sh")
REQUIRED_CMDS+=("sha256sum")
REQUIRED_CMDS+=("ssh-keygen")
REQUIRED_CMDS+=("swapoff")
REQUIRED_CMDS+=("tar")
REQUIRED_CMDS+=("wget")
REQUIRED_CMDS+=("telinit")

declare -a MISSING_CMDS=()
for c in "${REQUIRED_CMDS[@]}"; do
	if ! command -v "$c" >/dev/null 2>&1; then
		MISSING_CMDS+=("$c")
	fi
done

if [ ${#MISSING_CMDS[@]} -ge 1 ]; then
	echo "The following commands are required for this script to run:" >&2
	for c in "${MISSING_CMDS[@]}"; do
		echo "   $c" >&2
		if [[ "$c" == "telinit" ]]; then
			echo " * Please ensure your init system supports the 'telinit u' command"
		fi
	done
	echo "Please install them, then try again." >&2
	exit 1
fi

#########################
### Utility Functions ###
#########################

# Print the info about this script
print_info() {
	echo "╔══════════════════════════════════════════════════════════╗"
	echo "║ artixify - automatic Artix Linux installer by ubergeek77 ║"
	echo "╠══════════════════════════════════════════════════════════╣"
	echo "║                    Init system: runit                    ║"
	echo "║                 Installer version: 1.1.0                 ║"
	echo "║              Last updated: Jan. 14th, 2023               ║"
	echo "╚══════════════════════════════════════════════════════════╝"
	echo
}

# Ask for confirmation
confirm() {
	while :; do
		read -rp "$1 [Y/N]> " yn
		case $yn in
		[Yy]*) break ;;
		[Nn]*)
			echo "Cancelling installation at user request"
			exit 1
			;;
		*) echo "Please answer yes or no." ;;
		esac
	done
}

# Detect the presence of snaps via the list of mounts
check_snaps() {
	while read -r line; do
		if [[ "$line" == *snap* ]]; then
			SNAP_MOUNTS_FOUND="true"
			break
		fi
	done < <(lsblk)
}

# Check if a string is a valid Linux username or group
name_valid() {
	[[ "$1" =~ ^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)$ ]]
}

# Check if a string is a valid UID/GID
id_valid() {
	ID_CHECK=$1
	((ID_CHECK >= 1000 && ID_CHECK <= 60000))
}

# Return 0 or 1 depending on if EFI mode is available
efi_available() {
	[[ -d /sys/firmware/efi ]]
}

# Function that checks if a hostname is valid
# Shamelessly stolen from:
# https://www.unix.com/shell-programming-and-scripting/266435-check-valid-hostnames-2.html
hostname_valid() {
	VALID=$(echo "$1" | awk '{if($0 !~ /^\./ &&  $0 !~ /\.$/ && $0 !~ /^[[:digit:]]/ && $0 !~ /^-/ && $0 !~ /-$/ && $0 !~ /[[:space:]]/ && $0 !~ /[[:cntrl:]]/){
num=split($0, A,".");
if(num<=3){
              for(i=1;i<=num;i++){
                                      if(length(A[i])>63){exit}
                                      Q=Q?Q+length(A[i]):length(A[i])
                                 };
              if(length(Q)<=189) {
                                      print 1
                                 }
          }
}
}')

	if [[ "${VALID}" == "1" ]]; then
		return 1
	else
		return 0
	fi
}

ipv4_valid() {
	local ip=$1
	local stat=1

	if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		OIFS=$IFS
		IFS='.'
		ip=($ip)
		IFS=$OIFS
		[[ ${ip[0]} -le 255 && ${ip[1]} -le 255 &&
			${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
		stat=$?
	fi
	return $stat
}

ipv6_valid() {
	regex='^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$'
	var="$1"

	if [[ $var =~ $regex ]]; then
		return 0
	else
		return 1
	fi
}

ipv6_prefix_length_valid() {
	if [ $1 -le 128 ]; then
		return 0
	else
		return 1
	fi
}

# Check and make sure required variables are present and sane
# Set defaults for missing optional variables
precheck_vars() {
	# Declare an array to store all the error messages
	declare -a VAR_ISSUES=()

	# Username must exist
	if [[ -z "${NEW_USER}" ]]; then
		VAR_ISSUES+=("'NEW_USER' is not set")
	elif ! name_valid "${NEW_USER}"; then
		VAR_ISSUES+=("'NEW_USER': \"${NEW_USER}\" does not follow the Linux system name rules")
	fi

	# Password must exist
	if [[ -z "${NEW_PASS}" ]]; then
		VAR_ISSUES+=("'NEW_PASS' is not set")
	fi

	# UID must be blank or in a valid range
	if [[ -n "${NEW_UID}" ]] && ! id_valid "${NEW_UID}"; then
		VAR_ISSUES+=("'NEW_UID': \"${NEW_UID}\" is outside the allowed range of 1000-60000")
	fi

	# GID must be blank or in a valid range
	if [[ -n "${NEW_GID}" ]] && ! id_valid "${NEW_GID}"; then
		VAR_ISSUES+=("'NEW_GID': \"${NEW_GID}\" is outside the allowed range of 1000-60000")
	fi

	# Check each additional group for validity
	for g in "${NEW_GROUPS[@]}"; do
		# Split out the group ID if it exists
		THIS_GROUP="$(echo "$g" | cut -f1 -d:)"
		THIS_GID="$(echo "$g" | cut -f2 -d:)"

		if ! name_valid "${THIS_GROUP}"; then
			VAR_ISSUES+=("'NEW_GROUPS[@]': group \"${THIS_GROUP}\" does not follow the Linux system name rules")
		fi

		# Check the group ID if it existed
		if [[ "${THIS_GID}" != "${THIS_GROUP}" ]]; then
			if ! id_valid "${THIS_GID}"; then
				VAR_ISSUES+=("'NEW_GROUPS[@]': group id \"${THIS_GROUP}\" for group \"${THIS_GROUP}\" is outside the allowed range of 1000-60000")
			fi
		fi
	done

	# Set default timezone if it's missing
	if [[ -z "${TIMEZONE}" ]]; then
		TIMEZONE="America/Chicago"
	fi

	# Set default hostname if it's missing
	if [[ -z "${NEW_HOSTNAME}" ]]; then
		NEW_HOSTNAME="artixlinux"
	fi

	# Validate hostname
	if [[ "$(hostname_valid "${NEW_HOSTNAME}")" == "1" ]]; then
		VAR_ISSUES+=("'NEW_HOSTNAME': \"${NEW_HOSTNAME}\" does not follow the Linux system hostname rules")
	fi

	# Set default interface name if it's missing
	if [[ -z "${WIRED_IFACE}" ]]; then
		WIRED_IFACE="eth0"
	fi

	# Make sure a block device was specified
	if [[ -z "${BLOCK_DEVICE}" ]]; then
		VAR_ISSUES+=("'BLOCK_DEVICE' is not set")
	elif [[ ! -b "${BLOCK_DEVICE}" ]]; then
		VAR_ISSUES+=("'BLOCK_DEVICE': \"${BLOCK_DEVICE}\" is not a block device")
	fi

	# If MAKE_SWAP==1, validate the swap size
	if [[ "${MAKE_SWAP}" == "1" ]]; then
		# Set the default swap size if it's not set
		if [[ -z "${SWAP_SIZE}" ]]; then
			SWAP_SIZE="1024M"
		fi

		# Validate the swap size
		if ! (echo "${SWAP_SIZE}" | grep -Eq "^([0-9])+([KMGTP])?$"); then
			VAR_ISSUES+=("'SWAP_SIZE': \"${SWAP_SIZE}\" is not valid fdisk notation")
		fi
	fi

	# Make sure we have at least one DNS server, and that all provided servers are valid
	if [ ${#DNS_SERVERS[@]} -lt 1 ]; then
		VAR_ISSUES+=("'DNS_SERVERS': You must specify at least one DNS server")
	else
		for d in "${DNS_SERVERS[@]}"; do
			if ! ipv4_valid $d && ! ipv6_valid $d; then
				VAR_ISSUES+=("'DNS_SERVERS': $d is not a valid IPv4 or IPv6 address")
			fi
		done
	fi

	# If IPV4_STATIC was set, validate it, and also validate the netmask and gateway
	if [[ -n "${IPV4_STATIC}" ]]; then
		if ! ipv4_valid "${IPV4_STATIC}"; then
			VAR_ISSUES+=("'IPV4_STATIC': \"${IPV4_STATIC}\" is not valid IPv4 address")
		fi
		if ! ipv4_valid "${IPV4_GATEWAY}"; then
			VAR_ISSUES+=("'IPV4_GATEWAY': \"${IPV4_GATEWAY}\" is not valid IPv4 address")
		fi
		if ! ipv4_valid "${IPV4_NETMASK}"; then
			VAR_ISSUES+=("'IPV4_NETMASK': \"${IPV4_NETMASK}\" is not valid IPv4 address")
		fi
	fi

	# If IPV6_STATIC was set, validate it, and also validate the prefix length and gateway
	if [[ -n "${IPV6_STATIC}" ]]; then
		if ! ipv6_valid "${IPV6_STATIC}"; then
			VAR_ISSUES+=("'IPV6_STATIC': \"${IPV6_STATIC}\" is not valid IPv6 address")
		fi
		if ! ipv6_prefix_length_valid "${IPV6_PREFIX}"; then
			VAR_ISSUES+=("'IPV6_PREFIX': \"${IPV6_PREFIX}\" is not valid IPv6 prefix")
		fi
		if ! ipv6_valid "${IPV6_GATEWAY}"; then
			VAR_ISSUES+=("'IPV6_GATEWAY': \"${IPV6_GATEWAY}\" is not valid IPv6 address")
		fi
	fi

	# Load the public key from a file if necessary
	if [[ -z "${NEW_PUBKEY_STRING}" ]] && [[ -n "${NEW_PUBKEY_PATH}" ]] && [[ -f "${NEW_PUBKEY_PATH}" ]]; then
		NEW_PUBKEY_STRING="$(cat ${NEW_PUBKEY_PATH})"
	fi

	# Verify the public key was provided and is a valid public key
	if [[ -z "${NEW_PUBKEY_STRING}" ]]; then
		VAR_ISSUES+=("'NEW_PUBKEY_STRING': not set, must contain a valid SSH public key")
	else
		if ! echo "${NEW_PUBKEY_STRING}" | ssh-keygen -l -f - >/dev/null; then
			VAR_ISSUES+=("'NEW_PUBKEY_STRING': provided public key failed verification, is not a valid public key")
		fi
	fi

	# If there were any issues, print all of them
	if [ ${#VAR_ISSUES[@]} -ge 1 ]; then
		echo
		echo "There were errors with your script configuration:"
		for i in "${VAR_ISSUES[@]}"; do
			echo "   * $i"
		done
		echo
		echo "Please correct the above errors, then try again."
		echo
		echo "To update any installation variables, edit the config variables at the top of $0"
		exit 1
	fi
}

show_summary() {
	if [[ "${NO_SUMMARY}" != "1" ]]; then
		while true; do
			# Create some display variables for the summary
			if [[ -z "${NEW_UID}" ]]; then
				FMT_UID="default"
			else
				FMT_UID="${NEW_UID}"
			fi

			if [[ -z "${NEW_GID}" ]]; then
				FMT_GID="default"
			else
				FMT_GID="${NEW_GID}"
			fi

			if [[ "${FORCE_PASS_CHANGE}" == "1" ]]; then
				FMT_PASS_CHANGE="Yes"
			else
				FMT_PASS_CHANGE="No"
			fi

			if [ ${#NEW_GROUPS[@]} -ge 1 ]; then
				for g in "${NEW_GROUPS[@]}"; do
					FMT_GROUPS="${FMT_GROUPS}, $g"
				done
				FMT_GROUPS="${FMT_GROUPS::-2}"
			else
				FMT_GROUPS="No additional groups"
			fi

			if [ ${#DNS_SERVERS[@]} -ge 1 ]; then
				for d in "${DNS_SERVERS[@]}"; do
					FMT_DNS="${FMT_DNS},$d"
				done
				FMT_DNS="${FMT_DNS:1}"
			else
				FMT_DNS="ERROR - NO DNS SERVERS"
			fi

			if [[ -z "${IPV4_STATIC}" ]]; then
				FMT_IPV4="Autodetect"
			else
				FMT_IPV4="${IPV4_STATIC}"
			fi

			if [[ -z "${IPV4_GATEWAY}" ]]; then
				FMT_IPV4_GATEWAY="Autodetect"
			else
				FMT_IPV4_GATEWAY="${IPV4_GATEWAY}"
			fi

			if [[ -z "${IPV4_NETMASK}" ]]; then
				FMT_IPV4_NETMASK="Autodetect"
			else
				FMT_IPV4_NETMASK="${IPV4_NETMASK}"
			fi

			if [[ -z "${IPV6_STATIC}" ]]; then
				FMT_IPV6="Autodetect"
			else
				FMT_IPV6="${IPV6_STATIC}"
			fi

			if [[ -z "${IPV6_PREFIX}" ]]; then
				FMT_IPV6_PFX_LEN="Autodetect"
			else
				FMT_IPV6_PFX_LEN="${IPV6_PREFIX}"
			fi

			if [[ -z "${IPV6_GATEWAY}" ]]; then
				FMT_IPV6_GATEWAY="Autodetect"
			else
				FMT_IPV6_GATEWAY="${IPV6_GATEWAY}"
			fi

			if [[ "${MAKE_SWAP}" == "1" ]]; then
				FMT_SWAP="${SWAP_SIZE}"
			else
				FMT_SWAP="No"
			fi

			if efi_available; then
				FMT_BOOTMODE="EFI"
			else
				FMT_BOOTMODE="Legacy"
			fi

			echo
			echo "╔════════════════════════════════════╗"
			echo "║      Pre-Installation Summary:     ║"
			echo "╠════════════════════════════════════╝"
			echo "║        Username: ${NEW_USER}"
			echo "║ Expire Password: ${FMT_PASS_CHANGE}"
			echo "║             UID: ${FMT_UID}"
			echo "║             GID: ${FMT_GID}"
			echo "║          Groups: ${FMT_GROUPS}"
			echo "║        Timezone: ${TIMEZONE}"
			echo "║     DNS Servers: ${FMT_DNS}"
			echo "║        Hostname: ${NEW_HOSTNAME}"
			echo "║    IPv4 Address: ${FMT_IPV4}"
			echo "║    IPv4 Gateway: ${FMT_IPV4_GATEWAY}"
			echo "║    IPv4 Netmask: ${FMT_IPV4_NETMASK}"
			echo "║    IPv6 Address: ${FMT_IPV6}"
			echo "║    IPv6  Prefix: ${FMT_IPV6_PFX_LEN}"
			echo "║    IPv6 Gateway: ${FMT_IPV6_GATEWAY}"
			echo "║ Wired Interface: ${WIRED_IFACE}"
			echo "║  Swap Partition: ${FMT_SWAP}"
			echo "║    Block Device: ${BLOCK_DEVICE}"
			echo "║       Boot Mode: ${FMT_BOOTMODE}"
			echo "╚═════════════════════════════════════"
			echo "Your new Artix Linux server will be installed with the above configuration."
			echo
			echo "To change any of these values, edit artixify.env, or this script's configuration section"
			echo
			read -rp "Is this configuration correct? [Y/N]> " yn
			case $yn in
			[Yy]*) break ;;
			[Nn]*)
				echo "Cancelling installation at user request"
				exit 1
				;;
			*) echo "Please answer yes or no." ;;
			esac
		done
	fi
}

# Show a summary, and warn the user that the disk will be completely deleted
# Skip this warning if environment variable NO_WARN==1
# I tried my best to align the boxes, but most people only use 3-letter disks anwyay :)
display_super_obnoxious_warning() {
	if [[ "${NO_WARN}" != "1" ]]; then
		while true; do
			echo
			echo "╔═════════════════════════╗"
			echo "║ Boot Device Information ║"
			echo "╚═════════════════════════╝"
			echo "* Artix Linux will be installed to ${BLOCK_DEVICE}"
			if efi_available; then
				echo "* Artix Linux will boot from ${BLOCK_DEVICE} in EFI mode."
			else
				echo "* Artix Linux will boot from ${BLOCK_DEVICE} in legacy mode (non-EFI)."
			fi
			echo "* The block device ${BLOCK_DEVICE} has the following status:"
			echo
			lsblk "${BLOCK_DEVICE}"
			echo
			echo "╔═════════════════════════════════════════════════════════════════════════════════════╗"
			echo "║   !! WARNING !! WARNING !! WARNING !! WARNING !! WARNING !! WARNING !! WARNING !!   ║"
			echo "╠═════════════════════════════════════════════════════════════════════════════════════╣"
			echo "║                                                                                     ║"
			echo "║      If you proceed, all data on the following device will be COMPLETELY WIPED!     ║"
			printf '║ %48s' "*** ${BLOCK_DEVICE} ***"
			echo "                                    ║"
			printf '║%61s' "This includes any partitions on ${BLOCK_DEVICE}!"
			echo "                        ║"
			printf '║%59s' "ALL DATA ON ${BLOCK_DEVICE} WILL BE DELETED!"
			echo "                          ║"
			echo "║                                                                                     ║"
			echo "╚═════════════════════════════════════════════════════════════════════════════════════╝"
			echo
			echo "Do you wish to proceed with the installation, which will DELETE all data on ${BLOCK_DEVICE} in the process?"
			read -rp "Proceed? [Y/N]> " yn
			case $yn in
			[Yy]*) break ;;
			[Nn]*)
				echo "Cancelling installation at user request"
				exit 1
				;;
			*) echo "Please answer yes or no." ;;
			esac
		done
	fi
}

#############################
### Begin Install Process ###
#############################

# Print info message
print_info

# Pre-check input variables to insure the install goes smoothly
precheck_vars

# Print the summary
show_summary

# Pretty self explanatory
display_super_obnoxious_warning
echo

# Disable swap
echo "Disabling swap..."
echo
swapoff -a

# Detect and purge snaps as necessary
SNAP_MOUNTS_FOUND="false"
check_snaps
if [[ "$SNAP_MOUNTS_FOUND" == "true" ]]; then
	echo "Found snap mountpoints on this system. They must be removed before continuing."
	if command -v apt >/dev/null 2>&1; then
		confirm "Use apt to purge snap from this system?"
		echo "Purging snapd..."
		apt remove --purge -y snapd gnome-software-plugin-snap
	else
		echo "This system does not appear to contain apt, so snap cannot be automatically purged."
		echo "You may proceed with the installation anyway, but you may have issues writing to the disk."
		confirm "Continue with installation?"
	fi
fi

# Create a tmpfs for takeover.sh
mkdir /takeover
mount -o size=256M -t tmpfs none /takeover/

# Clone takeover.sh to the tmpfs
git clone https://github.com/marcan/takeover.sh /takeover/

# Download busybox and verify it works
wget "${BUSYBOX_STATIC_URL}" -O /takeover/busybox
chmod +x /takeover/busybox
/takeover/busybox true

# Download an alpine image and verify it
wget "${ALPINE_URL}"
wget "${ALPINE_URL}.sha256"
sha256sum -c alpine-*.sha256

# Extract the Alpine image to the tmpfs
tar -xvf ./alpine-*.tar.gz -C /takeover/

# Write /etc/resolv.conf to the Alpine rootfs so it can go online
if [[ "$(declare -p DNS_SERVERS 2>/dev/null)" =~ "declare -a" ]] && [ ${#DNS_SERVERS[@]} -ge 1 ]; then
	for d in "${DNS_SERVERS[@]}"; do
		echo "nameserver $d" >>/takeover/etc/resolv.conf
	done
else
	(
		echo "nameserver 1.1.1.1"
		echo "nameserver 1.0.0.1"
	) >>/takeover/etc/resolv.conf
fi

# Use chroot to update Alpine and install dependencies
chroot /takeover/ /bin/sh -lc 'apk update && apk upgrade'
chroot /takeover/ /bin/sh -lc 'apk add bash cfdisk coreutils curl e2fsprogs file gawk gcc git grep gzip lsof mount musl-dev openssh sed shadow tar umount util-linux-misc wget wipefs xz zstd'

# Takeover hardcodes passwd to /bin/passwd, need to link
chroot /takeover/ /bin/sh -lc 'ln -s /usr/bin/passwd /bin/passwd'

# Compile fakeinit
chroot /takeover/ /bin/sh -lc 'gcc /fakeinit.c -o /fakeinit'

# Write all environment variables to a file
(
	echo "NEW_USER=\"${NEW_USER}\""
	echo "NEW_PASS=\"${NEW_PASS}\""
	echo "NEW_UID=\"${NEW_UID}\""
	echo "NEW_GID=\"${NEW_GID}\""
	echo "FORCE_PASS_CHANGE=\"${FORCE_PASS_CHANGE}\""
	echo "TIMEZONE=\"${TIMEZONE}\""
	echo "NEW_HOSTNAME=\"${NEW_HOSTNAME}\""
	echo "WIRED_IFACE=\"${WIRED_IFACE}\""
	echo "BLOCK_DEVICE=\"${BLOCK_DEVICE}\""
	echo "MAKE_SWAP=\"${MAKE_SWAP}\""
	echo "SWAP_SIZE=\"${SWAP_SIZE}\""
	echo "CORE_PKGS=\"${CORE_PKGS}\""
	echo "COMMON_PKGS=\"${COMMON_PKGS}\""
	echo "UTIL_PKGS=\"${UTIL_PKGS}\""
	echo "SECURITY_PKGS=\"${SECURITY_PKGS}\""
	echo "BASESTRAP_PKGS=\"${BASESTRAP_PKGS}\""
	echo "EXTRA_PKGS=\"${EXTRA_PKGS}\""
	echo "DEFAULT_SVC=\"${DEFAULT_SVC}\""
	echo "IPV4_STATIC=\"${IPV4_STATIC}\""
	echo "IPV4_GATEWAY=\"${IPV4_GATEWAY}\""
	echo "IPV4_NETMASK=\"${IPV4_NETMASK}\""
	echo "IPV6_STATIC=\"${IPV6_STATIC}\""
	echo "IPV6_PREFIX=\"${IPV6_PREFIX}\""
	echo "IPV6_GATEWAY=\"${IPV6_GATEWAY}\""
	echo "NEW_PUBKEY_STRING=\"${NEW_PUBKEY_STRING}\""
) >>/takeover/artixify.env

# Write array-like environment variables to a file,
# use set to get the correct notation
{
	set | grep -e ^NEW_GROUPS=
	set | grep -e ^DNS_SERVERS=
	set | grep -e ^PKGBUILD_REPOS=
} >>/takeover/artixify.env

# Copy the stage2 script to the tmpfs
cp ./artixify-stage2.sh /takeover
chmod +x /takeover/artixify-stage2.sh

# Inject artixify-stage2 into the takeover script
# In case of weird issues where the user re-runs the script, only do this if it's not in the script
if ! grep -q 'artixify-stage2.sh' /takeover/takeover.sh; then
	sed -i '/^\.\/busybox echo "Starting secondary sshd"/i nohup ./busybox chroot . sh -c "nohup bash -c \\"nohup /artixify-stage2.sh >>/artixify.log 2>&1 &\\">/dev/null 2>&1 &" >/dev/null 2>&1 &' /takeover/takeover.sh
fi

# Validate that the script got added
if ! grep -q 'artixify-stage2.sh' /takeover/takeover.sh; then
	echo "ERROR: artixify-stage2 was not properly added to takeover.sh" >&2
	echo "This is likely due to a takeover.sh update" >&2
	echo "Cannot continue!" >&2
	exit 1
fi

# Have the end of the takeover.sh write to a file that we are ready for stage2
# In case of weird issues where the user re-runs the script, only do this if it's not already in the script
if ! grep -q 'artixify.wait' /takeover/takeover.sh; then
	echo "/busybox echo ready > /artixify.wait" >>/takeover/takeover.sh
fi

# Write an empty file to /takeover/artixify.wait
echo >/takeover/artixify.wait

# Disable the OK prompts in takeover.sh, replace them with short sleeps
# Yes, he really has it in the script two different ways
sed -i -e '/read a/,+3d' /takeover/takeover.sh
sed -i 's|./busybox echo -n "> "||g' /takeover/takeover.sh
sed -i "s|./busybox echo \"Type 'OK' to continue\"|sleep 1|g" /takeover/takeover.sh
sed -i "s|./busybox echo \"Type OK to continue\"|sleep 1|g" /takeover/takeover.sh

# Make takeover.sh use a temporary password
sed -i 's|./busybox echo "Please set a root password for sshd"||g' /takeover/takeover.sh
sed -i 's|./busybox chroot . /bin/passwd|echo "root:$TEMP_SSH_PASSWORD" \| ./busybox chroot . /usr/sbin/chpasswd|g' /takeover/takeover.sh

# Create a password for the temporary shell session
TEMP_SSH_PASSWORD="$(cat /dev/urandom | tr -dc '[:alnum:]' | head -c 20)"
export TEMP_SSH_PASSWORD

clear
echo
echo "takeover.sh is about to run"
echo
echo "This SSH server will be killed, and a new SSH server will run on port 80"
echo "A temporary password has been created for the SSH server on port 80:"
echo
echo "   * TEMPORARY SSH PASSWORD: $TEMP_SSH_PASSWORD"
echo
echo "Please take note of this password now, in case you lose access to this window."
echo
echo "To monitor the progress of artixify, run:"
echo "   ssh -p 80 root@this-server tail -f /artixify.log"
echo
echo "This is your LAST WARNING - if you continue, the disk will be wiped,"
echo "and you will be unable to SSH back into the server the normal way."
echo
echo "If you are unable to log in to the new install for any reason (install failed, you lost your SSH key, etc),"
echo "then you will have NO CHOICE but to reprovision this server via your provider."
echo
echo "ONLY CONTINUE IF YOU ARE ABLE TO RESET THIS SERVER VIA YOUR SERVER PROVIDER"
echo
confirm "Continue the installation?"

# Execute takeover
echo ""
echo ""
echo "!!! BEGINNING TAKEOVER !!!"
echo ""
echo ""
sh /takeover/takeover.sh
