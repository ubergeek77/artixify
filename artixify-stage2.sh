#!/bin/bash

echo "Entering stage2..."

# Return 0 or 1 depending on if EFI mode is available
efi_available() {
	[[ -d /sys/firmware/efi ]]
}

# Wait for the status file, or for 600 seconds (10 minutes)
echo "Waiting for stage1 to complete..."
wait=0
while [ $wait -le 600 ]; do
	# Check the status file
	if [[ "$(cat /artixify.wait)" == "ready" ]]; then
		break
	fi
	wait=$((wait + 1))
	sleep 1
done

# Check if stage1 completed properly or not
if [[ "$(cat /artixify.wait)" == "ready" ]]; then
	echo "stage1 complete, executing stage2"
else
	echo "ERROR: stage1 did not finish. Canceling installation before we do any damage." >&2
	exit 1
fi

# Load the environment variables from stage1
source /artixify.env

# Clone artix-bootstrap
git clone https://gitea.artixlinux.org/artix/artix-bootstrap

# Try to unmount /old_root up to 10 times
# If it fails to unmount, abort installation
retries=0
while :; do
	if [ $retries -ge 10 ]; then
		echo "Ultimately failed to unmount /old_root" >&2
		echo "Installation cannot continue." >&2
		exit 1
	fi

	# Somewhat-ungracefully kill every process using /old_root
	echo "Terminating all old processes..."
	kill -9 $(lsof -t /old_root/)

	# Sleep to give processes time to exit
	echo "Waiting 10 seconds for disk to be released..."
	sleep 10

	# Attempt to recursively unmount /old_root
	echo "Unmounting /old_root/..."
	umount -R /old_root/proc
	umount -R /old_root/sys
	umount -R /old_root/dev
	umount -R /old_root

	# If it's still mounted, sleep then try again
	if mountpoint -q /old_root/; then
		echo "/old_root/ is still mounted... waiting 10 seconds then trying again" >&2
	else
		echo "Successfully unmounted /old_root"
		break
	fi
	sleep 10
	retries=$((retries + 1))
done

# Wipe any existing partition tables
wipefs -a -f "${BLOCK_DEVICE}"

# Create variables for partition numbers
# These will be incremented at each step to get the correct numbers
EFI_PARTNUM="0"
SWAP_PARTNUM="0"
ROOT_PARTNUM="0"

# If EFI is available, have fdisk create an EFI partition
if efi_available; then
	EFI_PARTNUM=$((EFI_PARTNUM + 1))
	SWAP_PARTNUM=$((SWAP_PARTNUM + 1))
	ROOT_PARTNUM=$((ROOT_PARTNUM + 1))
	FDISK_CMD="n:p:::+512M:y:"
fi

# If swap was enabled, have fdisk create a swap partition
if [[ "${MAKE_SWAP}" == "1" ]]; then
	SWAP_PARTNUM=$((SWAP_PARTNUM + 1))
	ROOT_PARTNUM=$((ROOT_PARTNUM + 1))
	FDISK_CMD="${FDISK_CMD}n:p:::+${SWAP_SIZE}:y:"
fi

# Add fdisk commands for making the root partition
ROOT_PARTNUM=$((ROOT_PARTNUM + 1))
FDISK_CMD="${FDISK_CMD}n:p::::y:w"

# Run fdisk with the generated commands
echo "Partitioning disk ${BLOCK_DEVICE}..."
(awk -v RS=':' '1' <<<"${FDISK_CMD}") | fdisk "${BLOCK_DEVICE}"

# Create a variable to handle adding a p to partitons if needed
# Check if the first logical device exists with our current naming scheme
# If it doesn't try adding a p and continuing
export NVME_P=""
if [[ ! -b "${BLOCK_DEVICE}1" ]]; then
	export NVME_P="p"
fi

# If EFI mode is available, format the EFI partition as FAT32
if efi_available; then
	echo "Formatting EFI partition..."
	mkfs.fat -F 32 "${BLOCK_DEVICE}${NVME_P}${EFI_PARTNUM}"
	fatlabel "${BLOCK_DEVICE}${NVME_P}${EFI_PARTNUM}" BOOT
fi

# If MAKE_SWAP==1, format the swap partition and set it as active
if [[ "${MAKE_SWAP}" == "1" ]]; then
	echo "Formatting swap partition..."
	mkswap -L SWAP -f "${BLOCK_DEVICE}${NVME_P}${SWAP_PARTNUM}"
	swapon "${BLOCK_DEVICE}${NVME_P}${SWAP_PARTNUM}"
fi

# Format the root partition as ext4
echo "Formatting root partition..."
mkfs.ext4 -L ROOT -F "${BLOCK_DEVICE}${NVME_P}${ROOT_PARTNUM}"

# Check if the right partition is bootable, and enable it if not
BOOTABLE_PARTNUM="1"
if efi_available; then
	BOOTABLE_PARTNUM="${EFI_PARTNUM}"
	FMT_BOOTABLE="EFI"
else
	BOOTABLE_PARTNUM="${ROOT_PARTNUM}"
	FMT_BOOTABLE="root"
fi

if ! fdisk -l | grep "${BLOCK_DEVICE}${NVME_P}${BOOTABLE_PARTNUM}" | grep -q \*; then
	echo "Marking ${FMT_BOOTABLE} partition as bootable..."
	FDISK_CMD="a:${BOOTABLE_PARTNUM}:y:w"
	(awk -v RS=':' '1' <<<"${FDISK_CMD}") | fdisk "${BLOCK_DEVICE}"
fi

# Mount the root partition to /mnt
echo "Mounting root partition..."
mount "${BLOCK_DEVICE}${NVME_P}${ROOT_PARTNUM}" /mnt

# If EFI mode is available, mount the EFI partition to /mnt/boot
# Also add "efibootmgr" to BASESTRAP_PKGS
if efi_available; then
	echo "Mounting EFI partition..."
	mkdir -p /mnt/boot
	mount "${BLOCK_DEVICE}${NVME_P}${EFI_PARTNUM}" /mnt/boot
	BASESTRAP_PKGS="${BASESTRAP_PKGS} efibootmgr"
fi

# Bootstrap the mounted filesystem with Artix
echo "Boostrapping Artix..."
cd ./artix-bootstrap
./artix-bootstrap.sh -i runit /mnt

# Bind mount proc/sys/dev since we need them for some commands
mount --rbind /proc /mnt/proc/
mount --rbind /sys /mnt/sys/
mount --rbind /dev /mnt/dev/

# Sync pacman databases and keys in base system
echo "Updating base system databases and keys..."
chroot /mnt /bin/bash -c "pacman -Syy --noconfirm && pacman -Fy --noconfirm && pacman -Sy --noconfirm artix-keyring"

# This may have been handled by basestrap, but do a full pacman upgrade for good measure
echo "Ensuring base system packages are up to date..."
chroot /mnt /bin/bash -c "pacman -Syu --noconfirm"

# Install BASESTRAP_PKGS
chroot /mnt /bin/bash -c "pacman -S --noconfirm $BASESTRAP_PKGS"

# If the user specified additional packages, install them
if [[ -n "${EXTRA_PKGS}" ]]; then
	echo "Installing user-requested packages..."
	chroot /mnt /bin/bash -c "pacman -S --noconfirm ${EXTRA_PKGS}"
fi

# Create /etc/fstab
# Use -L labels instead of -U UUIDs because cloud UUIDs can change
echo "Creating /etc/fstab..."
chroot /mnt /bin/bash -c "fstabgen -L / >>/etc/fstab"

# Set the timezone
echo "Setting timezone..."
TIMEZONE_PATH="/mnt/usr/share/zoneinfo/${TIMEZONE}"
if [[ "$(file -b "${TIMEZONE_PATH}" | head -c 13)" != "timezone data" ]]; then
	echo "ERROR: Not a timezone file: ${TIMEZONE_PATH}"
	echo "Using safe default: America/Chicago"
	TIMEZONE_PATH="/mnt/usr/share/zoneinfo/America/Chicago"
fi
chroot /mnt /bin/bash -c "ln -sf ${TIMEZONE_PATH} /etc/localtime && hwclock --systohc"

# Set the hostname and hosts records on the system
echo "Setting hostname and hosts records..."
echo "${NEW_HOSTNAME}" >/mnt/etc/hostname

# Add hosts records
{
	echo "# Static table lookup for hostnames."
	echo "# See hosts(5) for details."
	echo "127.0.0.1        localhost"
	echo "::1              localhost"
	echo "127.0.1.1        ${NEW_HOSTNAME}.localdomain  ${NEW_HOSTNAME}"
} >/mnt/etc/hosts

# Set the DNS servers the user wanted
if [[ "$(declare -p DNS_SERVERS 2>/dev/null)" =~ "declare -a" ]] && [ ${#DNS_SERVERS[@]} -ge 1 ]; then
	echo "Setting DNS servers..."
	for d in "${DNS_SERVERS[@]}"; do
		echo "nameserver $d" >>/mnt/etc/resolv.conf
	done
else
	{
		echo "nameserver 1.1.1.1"
		echo "nameserver 1.0.0.1"
	} >>/mnt/etc/resolv.conf
fi

# Prevent dhcpcd from highjacking /etc/resolv.conf
echo "nohook resolv.conf" >>/mnt/etc/dhcpcd.conf

# Also prevent connman from highjacking /etc/resolv.conf
echo 'OPTS="--nodnsproxy"' >>/mnt/etc/runit/sv/connmand/conf
if ! grep -q '[global]' /mnt/var/lib/connman/settings; then
	echo '[global]' >>/mnt/var/lib/connman/settings
fi
if ! grep -q '^DNS=' /mnt/var/lib/connman/settings; then
	sed -i '/^\[global\]/a DNS=off' /mnt/var/lib/connman/settings
else
	sed -i 's|DNS=.*|DNS=off|' /mnt/var/lib/connman/settings
fi

# Generate locale
echo 'en_US.UTF-8 UTF-8' >>/mnt/etc/locale.gen
echo 'export LANG="en_US.UTF-8"' >>/mnt/etc/locale.conf
echo 'export LC_COLLATE="C"' >>/mnt/etc/locale.conf
chroot /mnt /bin/bash -c "locale-gen"

# Set the configured interface in dhcpcd config
echo "Configuring dhcpcd..."
sed -i "s|OPTS=\"\"|OPTS=\"${WIRED_IFACE}\"|g" /mnt/etc/runit/sv/dhcpcd/conf

# See if we have enough information to configure connman
IPV4_CONFIGURABLE="false"
if [[ -n "${IPV4_STATIC}" ]] && [[ -n "${IPV4_GATEWAY}" ]] && [[ -n "${IPV4_NETMASK}" ]]; then
	IPV4_CONFIGURABLE="true"
fi

IPV6_CONFIGURABLE="false"
if [[ -n "${IPV6_STATIC}" ]] && [[ -n "${IPV6_PREFIX}" ]] && [[ -n "${IPV6_GATEWAY}" ]]; then
	IPV6_CONFIGURABLE="true"
fi

ANY_CONFIGURABLE="false"
if [[ "${IPV4_CONFIGURABLE}" == "true" ]] || [[ "${IPV6_CONFIGURABLE}" == "true" ]]; then
	ANY_CONFIGURABLE="true"
fi

if [[ -n "${WIRED_IFACE}" ]] && [[ "${ANY_CONFIGURABLE}" == "true" ]]; then
	echo "Configuring connman..."
	mkdir -p /mnt/var/lib/connman
	{
		echo "[service_${WIRED_IFACE}]"
		echo "Type = ethernet"
		if [[ "${IPV4_CONFIGURABLE}" == "true" ]]; then
			echo "IPv4 = ${IPV4_STATIC}/${IPV4_NETMASK}/${IPV4_GATEWAY}"
		fi
		if [[ "${IPV6_CONFIGURABLE}" == "true" ]]; then
			echo "IPv6 = ${IPV6_STATIC}/${IPV6_PREFIX}/${IPV6_GATEWAY}"
		fi
	} >/mnt/var/lib/connman/static.config
fi

# Generate a string to run to add the non-root user
USERADD_CMD="useradd -m \"${NEW_USER}\""

# Add the UID to the command if it was provided
if [[ -n "${NEW_UID}" ]]; then
	USERADD_CMD="${USERADD_CMD} -u ${NEW_UID}"
fi

# Add the GID to the command if it was provided
if [[ -n "${NEW_GID}" ]]; then
	USERADD_CMD="${USERADD_CMD} -g ${NEW_GID}"
fi

# Create a non-root user
echo "Creating user \"${NEW_USER}\"..."
chroot /mnt /bin/bash -c "${USERADD_CMD}"

# Set the user password
echo "Setting default password for user \"${NEW_USER}\"..."
chroot /mnt /bin/bash -c "echo \"${NEW_USER}:${NEW_PASS}\" | chpasswd"

# Expire the password if configured
if [[ "${FORCE_PASS_CHANGE}" == "1" ]]; then
	echo "Marking password for user \"${NEW_USER}\" as expired"
	chroot /mnt /bin/bash -c "passwd --expire \"${NEW_USER}\""
fi

# Add the user to any additional groups as configured
if [[ "$(declare -p NEW_GROUPS 2>/dev/null)" =~ "declare -a" ]] && [ ${#NEW_GROUPS[@]} -ge 1 ]; then
	echo "Adding user to user-specified groups..."
	for g in "${NEW_GROUPS[@]}"; do
		# Split out group ID if it exists
		THIS_GROUP="$(echo "$g" | cut -f1 -d:)"
		THIS_GID="$(echo "$g" | cut -f2 -d:)"
		if [[ "${THIS_GID}" == "${THIS_GROUP}" ]]; then
			# There was no GID set for this group
			unset THIS_GID
		fi

		# Create the group only if it doesn't exist
		# Create it with the desired GID if provided
		if ! chroot /mnt /bin/bash -c "getent group ${THIS_GROUP}" >/dev/null; then
			echo "Group \"${THIS_GROUP}\" does not exist; it will be created"
			GROUPADD_CMD="groupadd"
			if [[ -n "${THIS_GID}" ]]; then
				GROUPADD_CMD="${GROUPADD_CMD} -g ${THIS_GID}"
			fi

			chroot /mnt /bin/bash -c "${GROUPADD_CMD} ${THIS_GROUP}"
		fi

		# Add the user to the group
		echo "Adding user \"${NEW_USER}\" to group \"${THIS_GROUP}\""
		chroot /mnt /bin/bash -c "usermod -aG ${THIS_GROUP} ${NEW_USER}"
	done
fi

# Check if the sudo group exists. Create it if not.
# This check is done after custom groups, to allow the user to specify
# a custom GID for the sudo group
if ! chroot /mnt /bin/bash -c "getent group sudo" >/dev/null; then
	echo "Creating sudo group..."
	chroot /mnt /bin/bash -c "groupadd sudo"
fi

# If the user is not already in the `sudo` group (from custom user groups above), add them to it
if ! chroot /mnt /bin/bash -c "id -Gn ${NEW_USER} | grep -q '\bsudo\b'"; then
	echo "Adding ${NEW_USER} to sudo group..."
	chroot /mnt /bin/bash -c "usermod -aG sudo ${NEW_USER}"
fi

# Enable sudo group
sed -i 's|^# %sudo|%sudo|' /mnt/etc/sudoers

# Verify rule was enabled, and add manually if necessary
if ! grep -q '^%sudo' /mnt/etc/sudoers; then
	echo '%sudo   ALL=(ALL) ALL' >>/mnt/etc/sudoers
fi

# Get the path to the new user's home directory
NEW_USER_HOME="$(chroot /mnt bash -c "eval echo ~$NEW_USER")"

# Check if neofetch is installed
# If it is, write a default config and modify it
if chroot /mnt /bin/bash -c "command -v neofetch >/dev/null 2>&1"; then
	echo "Configuring neofetch to start on boot..."
	mkdir -p /mnt/${NEW_USER_HOME}/.config/neofetch
	chroot /mnt bash -c "neofetch --print_config > ${NEW_USER_HOME}/.config/neofetch/config.conf"
	chroot /mnt bash -c "chown -R ${NEW_USER}:${NEW_USER} ${NEW_USER_HOME}/.config"

	# Disable less useful statements
	sed -i 's| info "Host" model| #&|' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's| info "Shell" shell| #&|' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's| info "Resolution" resolution| #&|' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's| info "DE" de| #&|' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's| info "WM" wm| #&|' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's| info "WM Theme" wm_theme| #&|' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's| info "Theme" theme| #&|' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's| info "Icons" icons| #&|' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's| info "Terminal" term| #&|' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's| info "Terminal Font" term_font| #&|' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's| info "GPU" gpu| #&|' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf

	# Enable useful statements
	sed -i -E 's/ #( info "Disk" disk)/\1/' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i -E 's/ #( info "Local IP" local_ip)/\1/' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i -E 's/ #( info "CPU Usage" cpu_usage)/\1/' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf

	# Change some settings
	sed -i 's|memory_percent="off"|memory_percent="on"|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|cpu_display="off"|cpu_display="barinfo"|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|memory_display="off"|memory_display="barinfo"|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|disk_display="off"|disk_display="barinfo"|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|bar_char_elapsed="-"|bar_char_elapsed="="|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|bar_char_total="="|bar_char_total="-"|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|separator=":"|separator=":\t"|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf

	# dylanaraps refuses to add alignment to neofetch: https://github.com/dylanaraps/neofetch/pull/1734
	# I also don't really want to maintain a separate version of neofetch just to add it
	# So, this is a very scuffed approximation of alignment for the items I care about
	sed -i 's|info "OS" distro|info "       OS" distro|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|info "Host" model|info "     Host" model|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|info "Kernel" kernel|info "   Kernel" kernel|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|info "Uptime" uptime|info "   Uptime" uptime|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|info "Packages" packages|info " Packages" packages|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|info "CPU" cpu|info "      CPU" cpu|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|info "Memory" memory|info "   Memory" memory|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|info "CPU Usage" cpu_usage|info "CPU Usage" cpu_usage|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|info "Disk" disk|info " Disk" disk|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf
	sed -i 's|info "Local IP" local_ip|info " Local IP" local_ip|g' /mnt/${NEW_USER_HOME}/.config/neofetch/config.conf

	# Run neofetch on login for the default user
	echo 'echo; neofetch' >>/mnt/${NEW_USER_HOME}/.bashrc
	chroot /mnt bash -c "chown ${NEW_USER}:${NEW_USER} ${NEW_USER_HOME}/.bashrc"
fi

# Add the desired SSH key to authorized_keys
mkdir -p /mnt/${NEW_USER_HOME}/.ssh
echo "${NEW_PUBKEY_STRING}" >>/mnt/${NEW_USER_HOME}/.ssh/authorized_keys
chroot /mnt bash -c "chown -R ${NEW_USER}:${NEW_USER} ${NEW_USER_HOME}/.ssh"
chroot /mnt bash -c "chmod 700 ${NEW_USER_HOME}/.ssh"
chroot /mnt bash -c "chmod 600 ${NEW_USER_HOME}/.ssh/authorized_keys"

# Configure sshd, comment any existing configs first
sed -i 's|^PermitRootLogin|#&|' /mnt/etc/ssh/sshd_config
sed -i 's|^PasswordAuthentication|#&|' /mnt/etc/ssh/sshd_config

# Add the new configs
{
	echo 'PermitRootLogin no'
	echo 'PasswordAuthentication no'
} >>/mnt/etc/ssh/sshd_config

# Configure grub, comment any existing configs first
sed -i 's|^GRUB_TIMEOUT=.*|#&|' /mnt/etc/default/grub
sed -i 's|^GRUB_HIDDEN_TIMEOUT=.*|#&|' /mnt/etc/default/grub
sed -i 's|^GRUB_TIMEOUT_STYLE=.*|#&|' /mnt/etc/default/grub
sed -i 's|^GRUB_HIDDEN_TIMEOUT_QUIET=.*|#&|' /mnt/etc/default/grub

# Add the new configs
{
	echo 'GRUB_TIMEOUT=0'
	echo 'GRUB_HIDDEN_TIMEOUT=0'
	echo 'GRUB_TIMEOUT_STYLE=hidden'
	echo 'GRUB_HIDDEN_TIMEOUT_QUIET=true'
} >>/mnt/etc/default/grub

# Install grub
echo "Installing grub..."

# Install differently in EFI mode
GRUB_INSTALL_CMD="grub-install --recheck ${BLOCK_DEVICE}"
if efi_available; then
	GRUB_INSTALL_CMD="grub-install --efi-directory=/boot --bootloader-id=grub ${BLOCK_DEVICE}"
fi
chroot /mnt /bin/bash -c "${GRUB_INSTALL_CMD}"
chroot /mnt /bin/bash -c "grub-mkconfig -o /boot/grub/grub.cfg"

# Link default services and any user enabled services
# Only do this if we have services to enable
if [[ -n "${DEFAULT_SVC}${CUSTOM_SVC}" ]]; then
	ENABLED_SVC="${DEFAULT_SVC} ${CUSTOM_SVC}"
	for svc in ${ENABLED_SVC}; do
		echo "Enabling service \"$svc\""
		chroot /mnt /bin/bash -c "ln -s /etc/runit/sv/$svc /etc/runit/runsvdir/default"
	done
fi

# Make SVDIR set for the entire system
mkdir -p /mnt/etc/profile.d
echo "SVDIR=/run/runit/service" >/mnt/etc/profile.d/svdir.sh

# Install PKGBUILD packages if any
if [[ "$(declare -p PKGBUILD_REPOS 2>/dev/null)" =~ "declare -a" ]] && [ ${#PKGBUILD_REPOS[@]} -ge 1 ]; then
	# Need a non-root user for this; create a temporary one with NOPASSWD sudo privileges
	echo "Creating a temporary non-root user for makepkg..."
	TEMP_USER="$(mktemp -u XXXXXXXX | tr '[:upper:]' '[:lower:]')"
	chroot /mnt /bin/bash -c "useradd -m -N ${TEMP_USER:?}"
	chroot /mnt /bin/bash -c "echo \"${TEMP_USER:?} ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers.d/${TEMP_USER:?}"

	# For each PKGBUILD, download, build, and install
	for pkgbuildrepo in "${PKGBUILD_REPOS[@]}"; do
		chroot /mnt /bin/bash -c "su - ${TEMP_USER:?} -c 'cd && rm -rf ./build'"
		chroot /mnt /bin/bash -c "su - ${TEMP_USER:?} -c 'cd && git clone $pkgbuildrepo ./build && cd ./build && makepkg --syncdeps --rmdeps --install --noconfirm'"
	done

	# When done, remove the temporary user, its sudo entry, and the home directory of the temporary user
	chroot /mnt /bin/bash -c "userdel ${TEMP_USER:?} && rm /etc/sudoers.d/${TEMP_USER:?} && rm -rf /home/${TEMP_USER:?}"
fi

# Unmount /mnt/boot if it was mounted
if mountpoint -q /mnt/boot; then
	echo "Unmounting /mnt/boot..."
	umount -R /mnt/boot
fi

# Unmount /mnt/proc
if mountpoint -q /mnt/proc; then
	echo "Unmounting /mnt/proc..."
	umount -R /mnt/proc
fi

# Unmount /mnt/sys
if mountpoint -q /mnt/sys; then
	echo "Unmounting /mnt/sys..."
	umount -R /mnt/sys
fi

# Unmount /mnt/dev
if mountpoint -q /mnt/dev; then
	echo "Unmounting /mnt/dev..."
	umount -R /mnt/dev
fi

# Swapoff the swap partition if it was on
if [[ "${MAKE_SWAP}" == "1" ]]; then
	echo "Turning off swap..."
	swapoff "${BLOCK_DEVICE}${NVME_P}${SWAP_PARTNUM}"
fi

# Copy the log to the new system
echo "Copying install log to new system /var/log..."
mkdir -p /mnt/var/log
cp /artixify.log /mnt/var/log/artixify.log
chmod 600 /mnt/var/log/artixify.log

# Recursively unmount /mnt
echo "Unmounting /mnt..."
umount -R /mnt

echo "Installation complete!"
echo
echo "Rebooting in 10 seconds..."
sleep 10
reboot -f
