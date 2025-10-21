#!/bin/bash
# CIS Hardening Script for Ubuntu 24.04
# Author: Behnam0x
# Date: $(date +%Y-%m-%d)

# =====================[ GLOBAL VARIABLES ]=====================
USE_TIMESTAMP=true  # Set to false to reuse the same log folder

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_LOG_DIR="/home/${SUDO_USER:-$(whoami)}/setup_logs"

if [ "$USE_TIMESTAMP" = true ]; then
  LOG_DIR="$BASE_LOG_DIR/$TIMESTAMP"
  mkdir -p "$LOG_DIR/section_logs"

  # 🧹 Keep only the 6 most recent timestamped log folders
  cd "$BASE_LOG_DIR"
  ls -dt */ | tail -n +7 | xargs -r rm -rf
else
  LOG_DIR="$BASE_LOG_DIR"
  rm -rf "$LOG_DIR/section_logs"/*
  > "$LOG_DIR/main.log"
  > "$LOG_DIR/all_errors.log"
  mkdir -p "$LOG_DIR/section_logs"
fi

CURRENT_SECTION=""


# =====================[ LOGGING FUNCTIONS ]=====================
start_section() {
    CURRENT_SECTION="$1"
    echo "[$(date '+%H:%M:%S')] Starting SECTION $CURRENT_SECTION" | tee -a "$LOG_DIR/main.log"
    mkdir -p "$LOG_DIR/section_logs/$CURRENT_SECTION"
}

log_success() {
    echo "  [✓] $1" | tee -a "$LOG_DIR/section_logs/$CURRENT_SECTION/success.log"
}

log_error() {
    echo "  [✗] $1" | tee -a "$LOG_DIR/section_logs/$CURRENT_SECTION/error.log"
}

log_message() {
    echo "  [ℹ] $1" | tee -a "$LOG_DIR/section_logs/$CURRENT_SECTION/info.log"
}


run_command() {
    local cmd="$1"
    local desc="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] EXEC: $desc" >> "$LOG_DIR/section_logs/$CURRENT_SECTION/details.log"
    echo "COMMAND: $cmd" >> "$LOG_DIR/section_logs/$CURRENT_SECTION/details.log"
    if eval "$cmd" >> "$LOG_DIR/section_logs/$CURRENT_SECTION/details.log" 2>&1; then
        log_success "$desc"
    else
        log_error "$desc"
    fi
}
# =====================[ ARGUMENT PARSING ]=====================
TARGET_SECTION=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --section)
      TARGET_SECTION="$2"
      shift 2
      ;;
    *)
      echo "❌ Unknown option: $1"
      echo "Usage: $0 [--section <section_number>]"
      exit 1
      ;;
  esac
done




########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "1.1" ]]; then
  # =====================[ SECTION 1.1.1: Disable Filesystem Kernel Modules ]=====================
  start_section "1.1.1"

  disable_module() {
    local mod="$1"
    local conf="/etc/modprobe.d/${mod}.conf"
    local bin_false
    bin_false="$(readlink -f /bin/false)"

    # Check if module exists
    if ! modinfo "$mod" &>/dev/null; then
      log_message "1.1.1.x Module $mod not found — skipping remediation"
      return
    fi

    # Unload module if loaded
    if lsmod | grep -q "^$mod"; then
      run_command "modprobe -r $mod 2>/dev/null || true" "1.1.1.x Unload $mod with modprobe"
      run_command "rmmod $mod 2>/dev/null || true" "1.1.1.x Remove $mod with rmmod"
    fi

    # Add install directive
    if ! grep -qE "^\s*install\s+$mod\s+$bin_false" "$conf" 2>/dev/null; then
      run_command "echo 'install $mod $bin_false' >> $conf" "1.1.1.x Add install directive for $mod"
    fi

    # Add blacklist directive
    if ! grep -qE "^\s*blacklist\s+$mod" "$conf" 2>/dev/null; then
      run_command "echo 'blacklist $mod' >> $conf" "1.1.1.x Add blacklist directive for $mod"
    fi
  }

  # CIS 1.1.1.1 – 1.1.1.9: Disable common filesystem modules
  for mod in cramfs freevxfs hfs hfsplus jffs2 squashfs udf usb-storage overlayfs; do
    disable_module "$mod"
  done

  # CIS 1.1.1.9: Remove related user-space tools
  for pkg in cramfs-utils squashfs-tools; do
    if dpkg -l | grep -qw "$pkg"; then
      run_command "apt purge -y $pkg" "1.1.1.9 Remove $pkg package"
    else
      log_message "1.1.1.9 Package $pkg not installed — skipping purge"
    fi
  done

  # =====================[ SECTION 1.1.1.10: Disable Unused Filesystem Modules with Known CVEs ]=====================
  start_section "1.1.1.10"

  # List of high-risk modules to disable if unused
  for mod in afs ceph cifs exfat ext fat fscache fuse gfs2 nfs_common nfsd smbfs_common; do
    # Check if module exists and is not in use
    if modinfo "$mod" &>/dev/null && ! lsmod | grep -q "^$mod"; then
      disable_module "$mod"
    else
      log_message "1.1.1.10 Module $mod is loaded or not found — review manually before disabling"
    fi
  done

 # =====================[ SECTION 1.1.2: Configure Filesystem Partitions ]=====================
 start_section "1.1.2"
 
 # Helper function to enforce mount options in /etc/fstab
 enforce_mount_option() {
   local mount_point="$1"
   local option="$2"
   local checklist="$3"
   run_command "sed -i \"[[:space:]]${mount_point}[[:space:]]/ s/defaults/defaults,${option}/\" /etc/fstab" "${checklist} Set ${option} on ${mount_point}"
 }
 
 # /tmp
 enforce_mount_option "/tmp" "nodev" "1.1.2.1.2"
 enforce_mount_option "/tmp" "nosuid" "1.1.2.1.3"
 enforce_mount_option "/tmp" "noexec" "1.1.2.1.4"
 
 # /dev/shm
 enforce_mount_option "/dev/shm" "nodev" "1.1.2.2.2"
 enforce_mount_option "/dev/shm" "nosuid" "1.1.2.2.3"
 enforce_mount_option "/dev/shm" "noexec" "1.1.2.2.4"
 
 # /home
 enforce_mount_option "/home" "nodev" "1.1.2.3.2"
 enforce_mount_option "/home" "nosuid" "1.1.2.3.3"
 
 # /var
 enforce_mount_option "/var" "nodev" "1.1.2.4.2"
 enforce_mount_option "/var" "nosuid" "1.1.2.4.3"
 
 # /var/tmp
 enforce_mount_option "/var/tmp" "nodev" "1.1.2.5.2"
 enforce_mount_option "/var/tmp" "nosuid" "1.1.2.5.3"
 enforce_mount_option "/var/tmp" "noexec" "1.1.2.5.4"
 
 # /var/log
 enforce_mount_option "/var/log" "nodev" "1.1.2.6.2"
 enforce_mount_option "/var/log" "nosuid" "1.1.2.6.3"
 enforce_mount_option "/var/log" "noexec" "1.1.2.6.4"
 
 # /var/log/audit
 enforce_mount_option "/var/log/audit" "nodev" "1.1.2.7.2"
 enforce_mount_option "/var/log/audit" "nosuid" "1.1.2.7.3"
 enforce_mount_option "/var/log/audit" "noexec" "1.1.2.7.4"
 
 # Apply all mount changes
 run_command "mount -a" "Apply updated mount options from /etc/fstab"
fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "1.2" ]]; then

 # =====================[ SECTION 1.2.1.1: Ensure GPG keys are configured ]=====================
 start_section "1.2.1.1"
 
 # Check for configured GPG keys in APT keyring
 if apt-key list 2>/dev/null | grep -q "pub"; then
   log_message "1.2.1.1 GPG keys are present in apt-key keyring"
 else
   log_message "1.2.1.1 No GPG keys found in apt-key keyring — manual review required"
 fi
 
 # Check for trusted.gpg.d key files
 if [ -n "$(find /etc/apt/trusted.gpg.d/ -type f -name '*.gpg')" ]; then
   log_message "1.2.1.1 GPG key files found in /etc/apt/trusted.gpg.d/"
 else
   log_message "1.2.1.1 No GPG key files found in /etc/apt/trusted.gpg.d/ — manual review required"
 fi
 
 # Manual remediation reminder
 log_message "1.2.1.1 Manual remediation: Ensure GPG keys are configured according to site policy"
 
 # =====================[ SECTION 1.2.1.2: Ensure package manager repositories are configured ]=====================
 start_section "1.2.1.2"
 
 # List configured APT repositories
 run_command "grep -h ^deb /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null" "1.2.1.2 List configured APT repositories"
 
 # Manual remediation reminder
 log_message "1.2.1.2 Manual remediation: Review and configure repositories according to site policy"
 
 # =====================[ SECTION 1.2.2.1: Ensure updates and security patches are installed ]=====================
 start_section "1.2.2.1"
 
 # Update package lists
 run_command "apt update" "1.2.2.1 Refresh package index"
 
 # Upgrade installed packages
 run_command "apt upgrade -y" "1.2.2.1 Apply standard package upgrades"
 
 # Optional: Perform full distribution upgrade if allowed by site policy
 run_command "apt dist-upgrade -y" "1.2.2.1 Apply full distribution upgrade (site policy dependent)"
 
 # Manual remediation reminder
 log_message "1.2.2.1 Manual review: Confirm updates and patches align with site policy"
fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "1.3" ]]; then

 # =====================[ SECTION 1.3.1.1: Ensure AppArmor is installed ]=====================
 start_section "1.3.1.1"
 
 # Install AppArmor and utilities
 run_command "apt install -y apparmor apparmor-utils" "1.3.1.1 Install AppArmor and apparmor-utils"
 
 # =====================[ SECTION 1.3.1.2: Ensure AppArmor is enabled in GRUB ]=====================
 start_section "1.3.1.2"
 
 # Define required GRUB parameters
 grub_file="/etc/default/grub"
 required_params="apparmor=1 security=apparmor"
 
 # Ensure GRUB_CMDLINE_LINUX includes required parameters
 if grep -q '^GRUB_CMDLINE_LINUX=' "$grub_file"; then
   if ! grep -q "$required_params" "$grub_file"; then
     run_command "sed -i '/^GRUB_CMDLINE_LINUX=/ s/\"\$/ $required_params\"/' $grub_file" "1.3.1.2 Add AppArmor parameters to GRUB_CMDLINE_LINUX"
   else
     log_message "1.3.1.2 GRUB already contains AppArmor parameters"
   fi
 else
   run_command "echo 'GRUB_CMDLINE_LINUX=\"$required_params\"' >> $grub_file" "1.3.1.2 Insert GRUB_CMDLINE_LINUX with AppArmor parameters"
 fi
 
 # Update GRUB configuration
 run_command "update-grub" "1.3.1.2 Apply GRUB configuration changes"
 
 # =====================[ SECTION 1.3.1.3: Ensure AppArmor profiles are in enforce mode ]=====================
 start_section "1.3.1.3"
 
 # Set all AppArmor profiles to enforce mode
 run_command "aa-enforce /etc/apparmor.d/*" "1.3.1.3 Set all AppArmor profiles to enforce mode"
 
 # Optional: To use complain mode instead, replace the above line with:
 # run_command "aa-complain /etc/apparmor.d/*" "1.3.1.3 Set all AppArmor profiles to complain mode"
 
 
 # =====================[ SECTION 1.3.1.4: Ensure all AppArmor profiles are enforcing ]=====================
 start_section "1.3.1.4"
 
 # Set all AppArmor profiles to enforce mode
 run_command "aa-enforce /etc/apparmor.d/*" "1.3.1.4 Set all AppArmor profiles to enforce mode"
fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "1.4" ]]; then
 # =====================[ SECTION 1.4.1: Ensure bootloader password is set ]=====================
 start_section "1.4.1"
 
 # === Replace these values with your actual username and encrypted password ===
 GRUB_USER="adminuser"
 GRUB_PASSWORD_HASH="grub.pbkdf2.sha512.10000.XXXXXXXXXXXXXXXX"
 
 # Create custom GRUB config file for password protection
 CUSTOM_GRUB_FILE="/etc/grub.d/01_password"
 
 run_command "echo 'exec tail -n +2 \$0' > $CUSTOM_GRUB_FILE" "1.4.1 Create GRUB password config header"
 run_command "echo 'set superusers=\"$GRUB_USER\"' >> $CUSTOM_GRUB_FILE" "1.4.1 Set GRUB superuser"
 run_command "echo 'password_pbkdf2 $GRUB_USER $GRUB_PASSWORD_HASH' >> $CUSTOM_GRUB_FILE" "1.4.1 Set GRUB password hash"
 
 # Ensure boot entry is unrestricted if needed
 run_command "sed -i 's/^CLASS=.*/CLASS=\"--class gnu-linux --class gnu --class os --unrestricted\"/' /etc/grub.d/10_linux" "1.4.1 Add --unrestricted to GRUB boot entry"
 
 # Update GRUB configuration
 run_command "update-grub" "1.4.1 Apply GRUB configuration changes"
 
 # =====================[ SECTION 1.4.2: Ensure access to bootloader config is configured ]=====================
 start_section "1.4.2"
 
 # Set ownership to root:root
 run_command "chown root:root /boot/grub/grub.cfg" "1.4.2 Set ownership of grub.cfg to root:root"
 
 # Set permissions to remove execute and restrict read/write
 run_command "chmod u-x,go-rwx /boot/grub/grub.cfg" "1.4.2 Set secure permissions on grub.cfg"
fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "1.5" ]]; then
 # =====================[ SECTION 1.5.1: Ensure ASLR is enabled ]=====================
 start_section "1.5.1"
 
 # Set ASLR parameter in persistent sysctl config
 run_command "printf '%s\\n' 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/60-kernel_sysctl.conf" "1.5.1 Add ASLR setting to /etc/sysctl.d/60-kernel_sysctl.conf"
 
 # Apply ASLR setting immediately
 run_command "sysctl -w kernel.randomize_va_space=2" "1.5.1 Apply ASLR setting to running kernel"
 
 # =====================[ SECTION 1.5.2: Ensure ptrace_scope is restricted ]=====================
 start_section "1.5.2"
 
 # Set ptrace_scope value (adjust to 2 or 3 if required by site policy)
 run_command "printf '%s\\n' 'kernel.yama.ptrace_scope = 1' >> /etc/sysctl.d/60-kernel_sysctl.conf" "1.5.2 Add ptrace_scope setting to /etc/sysctl.d/60-kernel_sysctl.conf"
 
 # Apply ptrace_scope setting immediately
 run_command "sysctl -w kernel.yama.ptrace_scope=1" "1.5.2 Apply ptrace_scope setting to running kernel"
 
 # =====================[ SECTION 1.5.3: Ensure core dumps are restricted ]=====================
 start_section "1.5.3"
 
 LIMITS_FILE="/etc/security/limits.d/99-core-dump.conf"
 SYSCTL_FILE="/etc/sysctl.d/60-fs_sysctl.conf"
 
 # Create limits file if it doesn't exist
 if [ ! -f "$LIMITS_FILE" ]; then
   run_command "touch $LIMITS_FILE" "1.5.3 Create $LIMITS_FILE"
 fi
 
 # Add core dump restriction to limits file
 run_command "grep -q '^\\* hard core 0' $LIMITS_FILE || echo '* hard core 0' >> $LIMITS_FILE" "1.5.3 Set core dump limit in limits.d"
 
 # Add fs.suid_dumpable to sysctl config
 run_command "printf '\\n%s\\n' 'fs.suid_dumpable = 0' >> $SYSCTL_FILE" "1.5.3 Add fs.suid_dumpable setting to $SYSCTL_FILE"
 
 # Apply setting immediately
 run_command "sysctl -w fs.suid_dumpable=0" "1.5.3 Apply fs.suid_dumpable setting to running kernel"
 
 # If systemd-coredump is installed, restrict its behavior
 if [ -f /etc/systemd/coredump.conf ]; then
   run_command "sed -i 's/^#*Storage=.*/Storage=none/' /etc/systemd/coredump.conf" "1.5.3 Set Storage=none in coredump.conf"
   run_command "sed -i 's/^#*ProcessSizeMax=.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf" "1.5.3 Set ProcessSizeMax=0 in coredump.conf"
   run_command "systemctl daemon-reload" "1.5.3 Reload systemd to apply coredump restrictions"
 else
   log_message "1.5.3 systemd-coredump not installed — skipping coredump.conf configuration"
 fi
 
 # =====================[ SECTION 1.5.4: Ensure prelink is not installed ]=====================
 start_section "1.5.4"
 
 # If prelink is installed, undo prelinking and remove the package
 if dpkg -l | grep -qw prelink; then
   run_command "prelink -ua" "1.5.4 Undo prelinking of binaries"
   run_command "apt purge -y prelink" "1.5.4 Remove prelink package"
 else
   log_message "1.5.4 Prelink is not installed — no action needed"
 fi
 
 # =====================[ SECTION 1.5.5: Ensure automatic error reporting is disabled ]=====================
 start_section "1.5.5"
 
 # Disable apport in its config file
 run_command "sed -i 's/^enabled=.*/enabled=0/' /etc/default/apport || echo 'enabled=0' >> /etc/default/apport" "1.5.5 Set enabled=0 in /etc/default/apport"
 
 # Stop and mask the apport service
 run_command "systemctl stop apport.service" "1.5.5 Stop apport service"
 run_command "systemctl mask apport.service" "1.5.5 Mask apport service to prevent restart"
 
 # Optional: Remove apport package entirely
 run_command "apt purge -y apport" "1.5.5 Remove apport package"
fi

###################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "1.6" ]]; then
  # =====================[ SECTION 1.6: Configure Command Line Warning Banners ]=====================
  start_section "1.6"

  # =====================[ 1.6.2 & 1.6.3: Local and Remote Login Warning Banners ]=====================
  BANNER=$(cat <<'EOF'
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║                  ⚠️  AUTHORIZED ACCESS ONLY  ⚠️                          ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝

This system is restricted to authorized users. Unauthorized access, use, or
modification is strictly prohibited and may result in disciplinary action,
civil liability, and/or criminal prosecution.

All activities on this system are subject to monitoring and logging. By
proceeding, you acknowledge and consent to such monitoring.

──────────────────────────────────────────────────────────────────────────────
📜 Legal Notice:
Use of this system constitutes consent to security testing and monitoring.
All data and actions are logged. Violations will be investigated and prosecuted.

🔐 Security Guidelines:
1. Never share your login credentials.
2. Immediately report any suspicious activity to IT Security.
──────────────────────────────────────────────────────────────────────────────
EOF
  )

  run_command "echo \"$BANNER\" > /etc/issue" "1.6.2 Set /etc/issue banner (local login)"
  run_command "echo \"$BANNER\" > /etc/issue.net" "1.6.3 Set /etc/issue.net banner (remote login)"

  # =====================[ 1.6.1: Message of the Day Configuration ]=====================
  run_command "mkdir -p /etc/update-motd.d" "1.6.1 Ensure MOTD directory exists"
  run_command "find /etc/update-motd.d/ -type f ! -name '00-custom' -exec chmod -x {} \;" "1.6.1 Disable default MOTD scripts"

  # Create custom MOTD script
  cat <<'EOF' > /etc/update-motd.d/00-custom
#!/bin/bash

# Color definitions
BOLD='\033[1m'
RESET='\033[0m'
FG_GREEN='\033[38;5;40m'
FG_YELLOW='\033[38;5;226m'
FG_RED='\033[38;5;196m'

# System info
HOSTNAME=$(hostname)
USER=$(whoami)
LAST_LOGIN=$(last -i "$USER" | grep -m 1 "$USER" | awk '{print $1, "from", $3, "at", $5, $6, $7}')
MEMORY=$(free -h | awk '/Mem:/ {print $3 "/" $2}')
DISK=$(df -h / | awk 'NR==2 {print $3 "/" $2 " used"}')
UPTIME=$(uptime -p)
FULL_DATE=$(date "+%A, %d %B %Y — %H:%M:%S")

# Banner
echo -e "${FG_GREEN}${BOLD}"
echo "╔════════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                                ║"
echo "║        🖥️  Welcome to ${HOSTNAME} — Secure Access Only               ║"
echo "║                                                                                ║"
echo "╚════════════════════════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# System summary
echo -e "${FG_YELLOW}${BOLD}📅 Last Login:${RESET}     ${LAST_LOGIN}"
echo -e "${FG_YELLOW}${BOLD}⏱️ Uptime:${RESET}         ${UPTIME}"
echo -e "${FG_YELLOW}${BOLD}📍 Hostname:${RESET}       ${HOSTNAME}"
echo -e "${FG_YELLOW}${BOLD}🧠 Memory Usage:${RESET}   ${MEMORY}"
echo -e "${FG_YELLOW}${BOLD}📦 Disk Usage:${RESET}     ${DISK}"
echo -e "${FG_YELLOW}${BOLD}👤 Logged in as:${RESET}   ${USER}"
echo -e "${FG_YELLOW}${BOLD}📆 Current Date:${RESET}   ${FULL_DATE}"
echo

# Mounted filesystems
echo -e "${FG_YELLOW}${BOLD}🗂️ Mounted Filesystems:${RESET}"
printf "%-25s %-10s %-10s %-10s %-10s\n" "Mount Point" "Size" "Used" "Avail" "Use%"
df -h --output=target,size,used,avail,pcent | awk 'NR>1 {printf "%-25s %-10s %-10s %-10s %-10s\n", $1, $2, $3, $4, $5}'
echo

# Reminder
echo -e "${FG_RED}${BOLD}🔐 Reminder:${RESET} Unauthorized access is prohibited. All activity is monitored."
EOF

  run_command "chmod +x /etc/update-motd.d/00-custom" "1.6.1 Make MOTD script executable"
  run_command "/etc/update-motd.d/00-custom > /etc/motd" "1.6.1 Pipe MOTD output to /etc/motd"

  # =====================[ 1.6.4, 1.6.5, 1.6.6: File Permissions and Ownership ]=====================
  run_command "chmod 644 /etc/issue /etc/issue.net /etc/update-motd.d/00-custom /etc/motd" "1.6.4–1.6.6 Set banner file permissions"
  run_command "chown root:root /etc/issue /etc/issue.net /etc/update-motd.d/00-custom /etc/motd" "1.6.4–1.6.6 Set banner file ownership"

  # =====================[ MOTD Interference and PAM Configuration ]=====================
  run_command "systemctl disable motd-news.service" "1.6.x Disable motd-news service"
  run_command "systemctl mask motd-news.service" "1.6.x Mask motd-news service"
  run_command "rm -f /run/motd.dynamic" "1.6.x Remove dynamic MOTD"

  run_command "sed -i '/pam_motd.so/d' /etc/pam.d/sshd && echo 'session optional pam_motd.so motd=/etc/motd' >> /etc/pam.d/sshd" "1.6.x Configure PAM to show MOTD"
fi

#####################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "1.7" ]]; then
  # =====================[ SECTION 1.7: GDM Configuration ]=====================
  start_section "1.7"

  # =====================[ SECTION 1.7.1: Ensure GDM is removed ]=====================
  start_section "1.7.1"
  if dpkg -l | grep -qw gdm3; then
    run_command "apt purge -y gdm3" "1.7.1 Remove gdm3 package"
    run_command "apt autoremove -y gdm3" "1.7.1 Autoremove gdm3 dependencies"
  else
    log_message "1.7.1 gdm3 is not installed — no action needed"
  fi

  # =====================[ Skip 1.7.2–1.7.9 if GDM is not installed ]=====================
  if dpkg -l | grep -qw gdm3; then
    # Ensure dconf CLI is installed
    if ! command -v dconf &>/dev/null; then
      run_command "apt update && apt install -y dconf-cli" "1.7.x Install dconf-cli"
    fi

    # =====================[ SECTION 1.7.2: Ensure GDM login banner is configured ]=====================
    start_section "1.7.2"
    BANNER_TEXT="Authorized uses only. All activity may be monitored and reported"
    GDM_PROFILE="gdm"
    GDM_PROFILE_FILE="/etc/dconf/profile/${GDM_PROFILE}"
    GDM_DB_DIR="/etc/dconf/db/${GDM_PROFILE}.d"
    GDM_KEYFILE="${GDM_DB_DIR}/01-banner-message"

    if [ "$XDG_SESSION_TYPE" = "x11" ] || [ "$XDG_SESSION_TYPE" = "wayland" ]; then
      run_command "gsettings set org.gnome.login-screen banner-message-text '${BANNER_TEXT}'" "1.7.2 Set GDM banner text via gsettings"
      run_command "gsettings set org.gnome.login-screen banner-message-enable true" "1.7.2 Enable GDM banner via gsettings"
    else
      log_message "1.7.2 Not in graphical session — applying system-wide dconf configuration"
      run_command "mkdir -p /etc/dconf/profile" "1.7.2 Ensure /etc/dconf/profile exists"
      if [ ! -f "${GDM_PROFILE_FILE}" ]; then
        run_command "echo -e 'user-db:user\nsystem-db:${GDM_PROFILE}\nfile-db:/usr/share/${GDM_PROFILE}/greeter-dconf-defaults' > ${GDM_PROFILE_FILE}" "1.7.2 Create GDM profile file"
      fi
      run_command "mkdir -p ${GDM_DB_DIR}" "1.7.2 Ensure GDM dconf database directory exists"
      cat <<EOF > "${GDM_KEYFILE}"
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='${BANNER_TEXT}'
EOF
      run_command "dconf update" "1.7.2 Apply dconf changes"
    fi

    # =====================[ SECTION 1.7.3: Ensure GDM disable-user-list option is enabled ]=====================
    start_section "1.7.3"
    GDM_KEYFILE="${GDM_DB_DIR}/00-login-screen"

    if [ "$XDG_SESSION_TYPE" = "x11" ] || [ "$XDG_SESSION_TYPE" = "wayland" ]; then
      run_command "gsettings set org.gnome.login-screen disable-user-list true" "1.7.3 Set disable-user-list via gsettings"
    else
      log_message "1.7.3 Not in graphical session — applying system-wide dconf configuration"
      run_command "mkdir -p /etc/dconf/profile" "1.7.3 Ensure /etc/dconf/profile exists"
      if [ ! -f "${GDM_PROFILE_FILE}" ]; then
        run_command "echo -e 'user-db:user\nsystem-db:${GDM_PROFILE}\nfile-db:/usr/share/${GDM_PROFILE}/greeter-dconf-defaults' > ${GDM_PROFILE_FILE}" "1.7.3 Create GDM profile file"
      fi
      run_command "mkdir -p ${GDM_DB_DIR}" "1.7.3 Ensure GDM dconf database directory exists"
      cat <<EOF > "${GDM_KEYFILE}"
[org/gnome/login-screen]
# Do not show the user list
disable-user-list=true
EOF
      run_command "dconf update" "1.7.3 Apply dconf changes"
    fi

    # =====================[ SECTION 1.7.4: Ensure GDM screen locks when the user is idle ]=====================
    start_section "1.7.4"
    IDLE_DELAY="900"
    LOCK_DELAY="5"
    DCONF_DB="local"
    DCONF_PROFILE="/etc/dconf/profile/user"
    DCONF_DB_DIR="/etc/dconf/db/${DCONF_DB}.d"
    DCONF_KEYFILE="${DCONF_DB_DIR}/00-screensaver"

    if [ "$XDG_SESSION_TYPE" = "x11" ] || [ "$XDG_SESSION_TYPE" = "wayland" ]; then
      run_command "gsettings set org.gnome.desktop.screensaver lock-delay ${LOCK_DELAY}" "1.7.4 Set lock-delay via gsettings"
      run_command "gsettings set org.gnome.desktop.session idle-delay ${IDLE_DELAY}" "1.7.4 Set idle-delay via gsettings"
    else
      log_message "1.7.4 Not in graphical session — applying system-wide dconf configuration"
      run_command "mkdir -p /etc/dconf/profile" "1.7.4 Ensure /etc/dconf/profile exists"
      if ! grep -q "system-db:${DCONF_DB}" "${DCONF_PROFILE}" 2>/dev/null; then
        run_command "echo -e 'user-db:user\nsystem-db:${DCONF_DB}' >> ${DCONF_PROFILE}" "1.7.4 Add ${DCONF_DB} to dconf profile"
      fi
      run_command "mkdir -p ${DCONF_DB_DIR}" "1.7.4 Ensure dconf database directory exists"
      cat <<EOF > "${DCONF_KEYFILE}"
[org/gnome/desktop/session]
idle-delay=uint32 ${IDLE_DELAY}
[org/gnome/desktop/screensaver]
lock-delay=uint32 ${LOCK_DELAY}
EOF
      run_command "dconf update" "1.7.4 Apply dconf changes"
    fi

    # =====================[ SECTION 1.7.5: Ensure GDM screen locks cannot be overridden ]=====================
    start_section "1.7.5"

    DCONF_DB="local"
    LOCK_DIR="/etc/dconf/db/${DCONF_DB}.d/locks"
    LOCK_FILE="${LOCK_DIR}/00-screensaver"

    run_command "mkdir -p ${LOCK_DIR}" "1.7.5 Ensure dconf lock directory exists"
    run_command "echo '/org/gnome/desktop/session/idle-delay' > ${LOCK_FILE}" "1.7.5 Lock idle-delay setting"
    run_command "echo '/org/gnome/desktop/screensaver/lock-delay' >> ${LOCK_FILE}" "1.7.5 Lock lock-delay setting"
    run_command "dconf update" "1.7.5 Apply dconf changes"

    # =====================[ SECTION 1.7.6: Disable GDM automatic mounting of removable media ]=====================
    start_section "1.7.6"

    DCONF_KEYFILE="/etc/dconf/db/${DCONF_DB}.d/00-media-automount"

    if [ "$XDG_SESSION_TYPE" = "x11" ] || [ "$XDG_SESSION_TYPE" = "wayland" ]; then
      run_command "gsettings set org.gnome.desktop.media-handling automount false" "1.7.6 Disable automount via gsettings"
      run_command "gsettings set org.gnome.desktop.media-handling automount-open false" "1.7.6 Disable automount-open via gsettings"
    else
      log_message "1.7.6 Not in graphical session — applying system-wide dconf configuration"
      run_command "mkdir -p /etc/dconf/profile" "1.7.6 Ensure /etc/dconf/profile exists"
      if ! grep -q "system-db:${DCONF_DB}" "${DCONF_PROFILE}" 2>/dev/null; then
        run_command "echo -e '\nuser-db:user\nsystem-db:${DCONF_DB}' >> ${DCONF_PROFILE}" "1.7.6 Add ${DCONF_DB} to dconf profile"
      fi
      run_command "mkdir -p ${DCONF_DB_DIR}" "1.7.6 Ensure dconf database directory exists"
      cat <<EOF > "${DCONF_KEYFILE}"
[org/gnome/desktop/media-handling]
automount=false
automount-open=false
EOF
      run_command "dconf update" "1.7.6 Apply dconf changes"
    fi

    # =====================[ SECTION 1.7.7: Lock GDM automount settings ]=====================
    start_section "1.7.7"

    LOCK_FILE="/etc/dconf/db/${DCONF_DB}.d/locks/00-media-automount"
    run_command "mkdir -p ${LOCK_DIR}" "1.7.7 Ensure dconf lock directory exists"
    run_command "echo '/org/gnome/desktop/media-handling/automount' > ${LOCK_FILE}" "1.7.7 Lock automount setting"
    run_command "echo '/org/gnome/desktop/media-handling/automount-open' >> ${LOCK_FILE}" "1.7.7 Lock automount-open setting"
    run_command "dconf update" "1.7.7 Apply dconf changes"

    # =====================[ SECTION 1.7.8: Ensure GDM autorun-never is enabled ]=====================
    start_section "1.7.8"

    DCONF_KEYFILE="/etc/dconf/db/${DCONF_DB}.d/00-media-autorun"

    if [ "$XDG_SESSION_TYPE" = "x11" ] || [ "$XDG_SESSION_TYPE" = "wayland" ]; then
      run_command "gsettings set org.gnome.desktop.media-handling autorun-never true" "1.7.8 Set autorun-never via gsettings"
    else
      log_message "1.7.8 Not in graphical session — applying system-wide dconf configuration"
      run_command "mkdir -p /etc/dconf/profile" "1.7.8 Ensure /etc/dconf/profile exists"
      if ! grep -q "system-db:${DCONF_DB}" "${DCONF_PROFILE}" 2>/dev/null; then
        run_command "echo -e '\nuser-db:user\nsystem-db:${DCONF_DB}' >> ${DCONF_PROFILE}" "1.7.8 Add ${DCONF_DB} to dconf profile"
      fi
      run_command "mkdir -p ${DCONF_DB_DIR}" "1.7.8 Ensure dconf database directory exists"
      cat <<EOF > "${DCONF_KEYFILE}"
[org/gnome/desktop/media-handling]
autorun-never=true
EOF
      run_command "dconf update" "1.7.8 Apply dconf changes"
    fi

    # =====================[ SECTION 1.7.9: Lock GDM autorun-never setting ]=====================
    start_section "1.7.9"

    LOCK_FILE="/etc/dconf/db/${DCONF_DB}.d/locks/00-media-autorun"
    run_command "mkdir -p ${LOCK_DIR}" "1.7.9 Ensure dconf lock directory exists"
    run_command "echo '/org/gnome/desktop/media-handling/autorun-never' > ${LOCK_FILE}" "1.7.9 Lock autorun-never setting"
    run_command "dconf update" "1.7.9 Apply dconf changes"
  else
    log_message "GDM is not installed — skipping sections 1.7.5 to 1.7.9"
  fi

  # =====================[ SECTION 1.7.10: Ensure XDMCP is not enabled ]=====================
  start_section "1.7.10"

  GDM_CONF="/etc/gdm/custom.conf"
  if [ -f "$GDM_CONF" ]; then
    if grep -Pq '^\s*

\[xdmcp\]

' "$GDM_CONF" && grep -Pq '^\s*Enable\s*=\s*true\b' "$GDM_CONF"; then
      run_command "sed -ri '/^\s*Enable\s*=\s*true\b/ s/^/# /' ${GDM_CONF}" "1.7.10 Comment out Enable=true in [xdmcp] block"
    else
      log_message "1.7.10 XDMCP is not enabled — no action needed"
    fi
  else
    log_message "1.7.10 GDM config file not found — skipping"
  fi
fi 

######################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "2.1" ]]; then
  # =====================[ SECTION 2.1: Disable Unused Services ]=====================
  start_section "2.1"

  # List of services to disable/remove
  SERVICES=(
    autofs avahi-daemon isc-dhcp-server bind9 dnsmasq smbd vsftpd dovecot nfs-server ypserv cups rpcbind rsync snmpd telnet.socket
    tftp.socket squid apache2 xinetd x11-common postfix
  )

  for svc in "${SERVICES[@]}"; do
    if systemctl list-unit-files | grep -q "^${svc}"; then
      if systemctl is-enabled "$svc" &>/dev/null || systemctl is-active "$svc" &>/dev/null; then
        run_command "systemctl stop $svc" "2.1 Stop service: $svc"
        run_command "systemctl disable $svc" "2.1 Disable service: $svc"
        run_command "systemctl mask $svc" "2.1 Mask service: $svc"
      else
        log_message "2.1 Service $svc is already inactive/disabled"
      fi
    else
      log_message "2.1 Service $svc not found — skipping"
    fi
  done

  # List of packages to remove (if not required)
  PACKAGES=(
    autofs avahi-daemon isc-dhcp-server bind9 dnsmasq samba vsftpd dovecot-core nfs-common nis cups rpcbind rsync snmp telnetd
    tftpd-hpa squid apache2 x11-common postfix
  )

  for pkg in "${PACKAGES[@]}"; do
    if dpkg -l | grep -qw "$pkg"; then
      run_command "apt purge -y $pkg" "2.1 Remove package: $pkg"
    else
      log_message "2.1 Package $pkg is not installed — skipping"
    fi
  done

  # =====================[ SECTION 2.1.21: Configure MTA for Local-Only Mode ]=====================
  start_section "2.1.21"

  if dpkg -l | grep -qw postfix; then
    POSTFIX_CONF="/etc/postfix/main.cf"
    SETTING="inet_interfaces = loopback-only"

    if grep -q "^inet_interfaces" "$POSTFIX_CONF"; then
      run_command "sed -i 's/^inet_interfaces.*/${SETTING}/' $POSTFIX_CONF" "2.1.21 Update inet_interfaces to loopback-only"
    else
      run_command "echo '${SETTING}' >> $POSTFIX_CONF" "2.1.21 Add inet_interfaces = loopback-only to postfix config"
    fi

    run_command "systemctl restart postfix" "2.1.21 Restart postfix service"
  else
    log_message "2.1.21 Postfix is not installed — skipping"
  fi

  # =====================[ SECTION 2.1.22: Restrict Network-Listening Services ]=====================
  start_section "2.1.22"

  declare -A SERVICES_PACKAGES=(
    [telnet]="telnetd"
    [ftp]="vsftpd"
    [tftp]="tftpd-hpa"
    [rsync]="rsync"
    [rpcbind]="rpcbind"
    [cups]="cups"
    [samba]="samba"
    [nfs-server]="nfs-common"
    [postfix]="postfix"
    [apache2]="apache2"
    [squid]="squid"
    [xinetd]="xinetd"
  )

  for svc in "${!SERVICES_PACKAGES[@]}"; do
    pkg="${SERVICES_PACKAGES[$svc]}"

    if systemctl list-unit-files | grep -q "^${svc}" || systemctl list-unit-files | grep -q "^${svc}.socket"; then
      if systemctl is-active "${svc}.service" &>/dev/null || systemctl is-active "${svc}.socket" &>/dev/null; then
        run_command "systemctl stop ${svc}.service ${svc}.socket" "2.1.22 Stop ${svc} service and socket"
      fi

      if dpkg -l | grep -qw "$pkg"; then
        run_command "apt purge -y $pkg" "2.1.22 Remove package: $pkg"
      else
        run_command "systemctl mask ${svc}.service ${svc}.socket" "2.1.22 Mask ${svc} service and socket"
      fi
    else
      log_message "2.1.22 ${svc} service not found or inactive — no action needed"
    fi
  done
fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "2.2" ]]; then
  # =====================[ SECTION 2.2: Remove Unused Client Tools ]=====================
  start_section "2.2"

  CLIENT_PACKAGES=(
    nis            # 2.2.1 NIS client
    rsh-client     # 2.2.2 rsh client
    talk           # 2.2.3 talk client
    telnet         # 2.2.4 telnet client
    ldap-utils     # 2.2.5 LDAP client
    ftp            # 2.2.6 FTP client
  )

  for pkg in "${CLIENT_PACKAGES[@]}"; do
    if dpkg -l | grep -qw "$pkg"; then
      run_command "apt purge -y $pkg" "2.2 Remove client package: $pkg"
    else
      log_message "2.2 Package $pkg is not installed — no action needed"
    fi
  done
fi

if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "2.3" ]]; then
  # =====================[ SECTION 2.3: Time Synchronization ]=====================
  start_section "2.3"

  # === Choose your preferred time sync daemon ===
  TIME_SYNC_DAEMON="chrony"  # Options: chrony or systemd-timesyncd

  if [[ "$TIME_SYNC_DAEMON" == "chrony" ]]; then
    # ---------------------[ Chrony Setup ]---------------------
    run_command "apt update && apt install -y chrony" "2.3 Install chrony"

    # Disable systemd-timesyncd
    if systemctl is-active systemd-timesyncd.service &>/dev/null; then
      run_command "systemctl stop systemd-timesyncd.service" "2.3 Stop systemd-timesyncd"
    else
      log_message "2.3 systemd-timesyncd is not active — no need to stop"
    fi
    run_command "systemctl mask systemd-timesyncd.service" "2.3 Mask systemd-timesyncd"

    # Set timezone
    run_command "timedatectl set-timezone Asia/Tehran" "2.3 Set timezone to Asia/Tehran"

    # Configure chrony
    CHRONY_CONF="/etc/chrony/chrony.conf"
    CHRONY_POOL="pool asia.pool.ntp.org iburst"
    if ! grep -qE '^server|^pool' "$CHRONY_CONF"; then
      run_command "echo '${CHRONY_POOL}' >> ${CHRONY_CONF}" "2.3 Configure chrony with NTP pool"
    fi

    # Ensure chrony runs as _chrony
    CHRONY_SERVICE="/lib/systemd/system/chrony.service"
    if grep -q '^User=' "$CHRONY_SERVICE"; then
      run_command "sed -i 's/^User=.*/User=_chrony/' $CHRONY_SERVICE" "2.3 Ensure chrony runs as _chrony"
    else
      run_command "sed -i '/^

\[Service\]

/a User=_chrony' $CHRONY_SERVICE" "2.3 Add User=_chrony to chrony.service"
    fi

    run_command "systemctl daemon-reexec" "2.3 Reload systemd daemon"
    run_command "systemctl enable chrony" "2.3 Enable chrony"
    run_command "systemctl restart chrony" "2.3 Restart chrony"

  elif [[ "$TIME_SYNC_DAEMON" == "systemd-timesyncd" ]]; then
    # ---------------------[ systemd-timesyncd Setup ]---------------------
    run_command "apt purge -y chrony" "2.3 Remove chrony"
    run_command "apt autoremove -y chrony" "2.3 Autoremove chrony dependencies"

    # Set timezone
    run_command "timedatectl set-timezone Asia/Tehran" "2.3 Set timezone to Asia/Tehran"

    # Configure systemd-timesyncd
    TIMESYNC_CONF="/etc/systemd/timesyncd.conf"
    TIMESERVER="pool asia.pool.ntp.org"
    if ! grep -q "^NTP=" "$TIMESYNC_CONF"; then
      run_command "sed -i '/^

\[Time\]

/a NTP=${TIMESERVER}' $TIMESYNC_CONF" "2.3 Add NTP server to timesyncd.conf"
    else
      run_command "sed -i 's/^NTP=.*/NTP=${TIMESERVER}/' $TIMESYNC_CONF" "2.3 Update NTP server in timesyncd.conf"
    fi

    run_command "systemctl enable systemd-timesyncd" "2.3 Enable systemd-timesyncd"
    run_command "systemctl start systemd-timesyncd" "2.3 Start systemd-timesyncd"
  fi
fi


#####################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "2.4" ]]; then
  # =====================[ SECTION 2.4.1: Configure cron ]=====================
  start_section "2.4.1"

  # 2.4.1.1 Ensure cron daemon is enabled and active
  CRON_SERVICE="cron.service"
  if systemctl list-unit-files | grep -q "^${CRON_SERVICE}"; then
    run_command "systemctl unmask ${CRON_SERVICE}" "2.4.1.1 Unmask ${CRON_SERVICE}"
    run_command "systemctl --now enable ${CRON_SERVICE}" "2.4.1.1 Enable and start ${CRON_SERVICE}"
  else
    log_message "2.4.1.1 Cron service not found — skipping"
  fi

  # 2.4.1.2–2.4.1.7 Ensure permissions on cron directories and files
  CRON_PATHS=(
    /etc/crontab
    /etc/cron.hourly/
    /etc/cron.daily/
    /etc/cron.weekly/
    /etc/cron.monthly/
    /etc/cron.d/
  )

  for path in "${CRON_PATHS[@]}"; do
    run_command "chown root:root $path" "2.4.1 Set owner of $path"
    run_command "chmod og-rwx $path" "2.4.1 Set permissions of $path"
  done

  # 2.4.1.8 Restrict crontab to authorized users
  CRON_ALLOW="/etc/cron.allow"
  CRON_DENY="/etc/cron.deny"

  if [ ! -e "$CRON_ALLOW" ]; then
    run_command "touch $CRON_ALLOW" "2.4.1.8 Create cron.allow"
  fi
  run_command "chown root:root $CRON_ALLOW" "2.4.1.8 Set owner of cron.allow"
  run_command "chmod 640 $CRON_ALLOW" "2.4.1.8 Set permissions of cron.allow"

  if [ -e "$CRON_DENY" ]; then
    run_command "chown root:root $CRON_DENY" "2.4.1.8 Set owner of cron.deny"
    run_command "chmod 640 $CRON_DENY" "2.4.1.8 Set permissions of cron.deny"
  fi

  # =====================[ SECTION 2.4.2: Configure at ]=====================
  start_section "2.4.2"

  if dpkg -l | grep -qw at; then
    run_command "echo 'at is installed, proceeding with configuration'" "2.4.2.1 Confirm at presence"

    AT_ALLOW="/etc/at.allow"
    AT_DENY="/etc/at.deny"
    GROUP=$(getent group daemon &>/dev/null && echo "daemon" || echo "root")

    if [ ! -e "$AT_ALLOW" ]; then
      run_command "touch $AT_ALLOW" "2.4.2.1 Create at.allow"
    fi
    run_command "chown root:$GROUP $AT_ALLOW" "2.4.2.1 Set owner of at.allow"
    run_command "chmod 640 $AT_ALLOW" "2.4.2.1 Set permissions of at.allow"

    if [ -e "$AT_DENY" ]; then
      run_command "chown root:$GROUP $AT_DENY" "2.4.2.1 Set owner of at.deny"
      run_command "chmod 640 $AT_DENY" "2.4.2.1 Set permissions of at.deny"
    fi

    run_command "stat -Lc 'Access: (%a/%A) Owner: (%U) Group: (%G)' $AT_ALLOW" "2.4.2.1 Verify at.allow permissions"
    run_command "[ -e \"$AT_DENY\" ] && stat -Lc 'Access: (%a/%A) Owner: (%U) Group: (%G)' $AT_DENY || echo 'at.deny does not exist'" "2.4.2.1 Verify at.deny status"
  else
    log_message "2.4.2.1 'at' is not installed — skipping"
  fi
fi

######################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "3.1" ]]; then
  # =====================[ SECTION 3.1.1: Disable IPv6 (Manual) ]=====================
  start_section "3.1.1"

  # Create sysctl config to disable IPv6
  run_command "cat <<EOF > /etc/sysctl.d/99-disable-ipv6.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF" "3.1.1 Create sysctl config to disable IPv6"

  # Apply sysctl settings
  run_command "sysctl --system" "3.1.1 Apply sysctl changes"

  # Prevent IPv6 kernel module from loading
  run_command "echo 'install ipv6 /bin/true' > /etc/modprobe.d/disable-ipv6.conf" "3.1.1 Block IPv6 module loading"

  # Optional: Verify IPv6 is disabled
  run_command "ip a | grep inet6 || echo 'IPv6 is disabled'" "3.1.1 Confirm IPv6 status"

  # Reminder: Reboot required for full effect
  echo "🔁 Reboot is recommended to fully disable IPv6 across all interfaces."

  # =====================[ SECTION 3.1.2: Disable Wireless Interfaces (Automated) ]=====================
  start_section "3.1.2"

  # Function to disable a wireless module
  disable_module() {
    local module="$1"

    # Prevent module from loading
    run_command "echo 'install $module /bin/false' >> /etc/modprobe.d/${module}.conf" "3.1.2 Prevent loading of module: $module"

    # Unload module if active
    if lsmod | grep -q "^$module"; then
      run_command "modprobe -r $module" "3.1.2 Unload active module: $module"
    fi

    # Blacklist module
    if ! grep -q "blacklist $module" /etc/modprobe.d/*.conf 2>/dev/null; then
      run_command "echo 'blacklist $module' >> /etc/modprobe.d/${module}.conf" "3.1.2 Blacklist module: $module"
    fi
  }

  # Detect wireless interfaces and associated drivers
  WIRELESS_DRIVERS=$(find /sys/class/net/*/ -type d -name wireless 2>/dev/null | while read -r dir; do
    readlink -f "$(dirname "$dir")/device/driver/module" | xargs basename
  done | sort -u)

  # Disable each detected wireless driver
  for driver in $WIRELESS_DRIVERS; do
    disable_module "$driver"
  done

  # =====================[ SECTION 3.1.3: Disable Bluetooth Services (Automated) ]=====================
  start_section "3.1.3"

  # Check if bluez is installed
  if dpkg -l | grep -qw bluez; then
    # Attempt to stop bluetooth service
    run_command "systemctl stop bluetooth.service" "3.1.3 Stop bluetooth service"

    # Try to purge bluez package
    if apt purge -y bluez &>/dev/null; then
      run_command "apt purge -y bluez" "3.1.3 Remove bluez package"
    else
      # If bluez is required, mask the service instead
      run_command "systemctl mask bluetooth.service" "3.1.3 Mask bluetooth service"
    fi
  else
    log_message "3.1.3 bluez package is not installed — no action needed"
  fi

  # Reminder: Reboot may be required
  echo "🔁 Reboot is recommended to fully disable Bluetooth services and unload related modules."
fi

#############################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "3.2" ]]; then
  # =====================[ SECTION 3.2: Disable Network Kernel Modules ]=====================
  start_section "3.2"

  # List of network modules to disable
  NETWORK_MODULES=(
    dccp
    tipc
    rds
    sctp
  )

  for module in "${NETWORK_MODULES[@]}"; do
    # Check if module exists in kernel directories
    if find /lib/modules/$(uname -r)/kernel -type d -name "$module" | grep -q .; then
      # Unload if currently loaded
      if lsmod | grep -q "^$module"; then
        run_command "modprobe -r $module 2>/dev/null; rmmod $module 2>/dev/null" "3.2 Remove active module: $module"
      else
        run_command "echo '$module not currently loaded'" "3.2 Confirm $module not loaded"
      fi

      # Block loading of the module
      if ! grep -q "install $module /bin/false" /etc/modprobe.d/${module}.conf 2>/dev/null; then
        run_command "echo 'install $module /bin/false' >> /etc/modprobe.d/${module}.conf" "3.2 Block loading of module: $module"
      else
        log_message "3.2 Module $module already blocked from loading"
      fi

      # Blacklist the module
      if ! grep -q "blacklist $module" /etc/modprobe.d/${module}.conf 2>/dev/null; then
        run_command "echo 'blacklist $module' >> /etc/modprobe.d/${module}.conf" "3.2 Blacklist module: $module"
      else
        log_message "3.2 Module $module already blacklisted"
      fi
    else
      run_command "echo '$module module not found in kernel directories'" "3.2 Confirm absence of module: $module"
    fi
  done
fi

######################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "3.3" ]]; then
  # =====================[ SECTION 3.3.1: Disable IP Forwarding ]=====================
  start_section "3.3.1"

  # Disable IPv4 forwarding persistently
  run_command "echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.1 Set net.ipv4.ip_forward = 0"
  
  # Apply IPv4 forwarding setting immediately
  run_command "sysctl -w net.ipv4.ip_forward=0" "3.3.1 Apply IPv4 forwarding setting"
  run_command "sysctl -w net.ipv4.route.flush=1" "3.3.1 Flush IPv4 routing table"

  # Check if IPv6 is enabled
  if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ] && [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -eq 0 ]; then
    # Disable IPv6 forwarding persistently
    run_command "echo 'net.ipv6.conf.all.forwarding = 0' >> /etc/sysctl.d/60-netipv6_sysctl.conf" "3.3.1 Set net.ipv6.conf.all.forwarding = 0"

    # Apply IPv6 forwarding setting immediately
    run_command "sysctl -w net.ipv6.conf.all.forwarding=0" "3.3.1 Apply IPv6 forwarding setting"
    run_command "sysctl -w net.ipv6.route.flush=1" "3.3.1 Flush IPv6 routing table"
  else
    log_message "3.3.1 IPv6 is disabled — skipping IPv6 forwarding configuration"
  fi

  # =====================[ SECTION 3.3.2: Disable Packet Redirect Sending ]=====================
  start_section "3.3.2"

  # Persistently disable packet redirects
  run_command "echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.2 Set net.ipv4.conf.all.send_redirects = 0"
  run_command "echo 'net.ipv4.conf.default.send_redirects = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.2 Set net.ipv4.conf.default.send_redirects = 0"

  # Apply settings immediately
  run_command "sysctl -w net.ipv4.conf.all.send_redirects=0" "3.3.2 Apply net.ipv4.conf.all.send_redirects"
  run_command "sysctl -w net.ipv4.conf.default.send_redirects=0" "3.3.2 Apply net.ipv4.conf.default.send_redirects"
  run_command "sysctl -w net.ipv4.route.flush=1" "3.3.2 Flush IPv4 routing table"

  # =====================[ SECTION 3.3.3: Ignore Bogus ICMP Responses ]=====================
  start_section "3.3.3"

  # Persistently ignore bogus ICMP error responses
  run_command "echo 'net.ipv4.icmp_ignore_bogus_error_responses = 1' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.3 Set net.ipv4.icmp_ignore_bogus_error_responses = 1"

  # Apply setting immediately
  run_command "sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1" "3.3.3 Apply bogus ICMP ignore setting"
  run_command "sysctl -w net.ipv4.route.flush=1" "3.3.3 Flush IPv4 routing table"

  # =====================[ SECTION 3.3.4: Ignore Broadcast ICMP Requests ]=====================
  start_section "3.3.4"

  # Persistently ignore broadcast ICMP echo requests
  run_command "echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.4 Set net.ipv4.icmp_echo_ignore_broadcasts = 1"

  # Apply setting immediately
  run_command "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1" "3.3.4 Apply broadcast ICMP ignore setting"
  run_command "sysctl -w net.ipv4.route.flush=1" "3.3.4 Flush IPv4 routing table"


  # =====================[ SECTION 3.3.5: Disable ICMP Redirect Acceptance ]=====================
  start_section "3.3.5"

  # Persistently disable IPv4 ICMP redirect acceptance
  run_command "echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.5 Set net.ipv4.conf.all.accept_redirects = 0"
  run_command "echo 'net.ipv4.conf.default.accept_redirects = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.5 Set net.ipv4.conf.default.accept_redirects = 0"

  # Apply IPv4 settings immediately
  run_command "sysctl -w net.ipv4.conf.all.accept_redirects=0" "3.3.5 Apply net.ipv4.conf.all.accept_redirects"
  run_command "sysctl -w net.ipv4.conf.default.accept_redirects=0" "3.3.5 Apply net.ipv4.conf.default.accept_redirects"
  run_command "sysctl -w net.ipv4.route.flush=1" "3.3.5 Flush IPv4 routing table"

  # Check if IPv6 is enabled
  if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ] && [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -eq 0 ]; then
    # Persistently disable IPv6 ICMP redirect acceptance
    run_command "echo 'net.ipv6.conf.all.accept_redirects = 0' >> /etc/sysctl.d/60-netipv6_sysctl.conf" "3.3.5 Set net.ipv6.conf.all.accept_redirects = 0"
    run_command "echo 'net.ipv6.conf.default.accept_redirects = 0' >> /etc/sysctl.d/60-netipv6_sysctl.conf" "3.3.5 Set net.ipv6.conf.default.accept_redirects = 0"

    # Apply IPv6 settings immediately
    run_command "sysctl -w net.ipv6.conf.all.accept_redirects=0" "3.3.5 Apply net.ipv6.conf.all.accept_redirects"
    run_command "sysctl -w net.ipv6.conf.default.accept_redirects=0" "3.3.5 Apply net.ipv6.conf.default.accept_redirects"
    run_command "sysctl -w net.ipv6.route.flush=1" "3.3.5 Flush IPv6 routing table"
  else
    log_message "3.3.5 IPv6 is disabled — skipping IPv6 redirect configuration"
  fi

  # =====================[ UFW Override Handling ]=====================
  if [ -f /etc/ufw/sysctl.conf ]; then
    run_command "echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/ufw/sysctl.conf" "3.3.5 Mirror IPv4 setting in UFW sysctl.conf"
    run_command "echo 'net.ipv4.conf.default.accept_redirects = 0' >> /etc/ufw/sysctl.conf" "3.3.5 Mirror IPv4 default setting in UFW sysctl.conf"

    if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ] && [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -eq 0 ]; then
      run_command "echo 'net.ipv6.conf.all.accept_redirects = 0' >> /etc/ufw/sysctl.conf" "3.3.5 Mirror IPv6 setting in UFW sysctl.conf"
      run_command "echo 'net.ipv6.conf.default.accept_redirects = 0' >> /etc/ufw/sysctl.conf" "3.3.5 Mirror IPv6 default setting in UFW sysctl.conf"
    fi

    # Optional: prevent UFW from overriding system-wide sysctl
    run_command "sed -i 's/^IPT_SYSCTL=.*/IPT_SYSCTL=0/' /etc/default/ufw" "3.3.5 Set IPT_SYSCTL=0 to respect system-wide sysctl"
  fi

  # =====================[ SECTION 3.3.6: Disable Secure ICMP Redirects ]=====================
  start_section "3.3.6"

  # Persistently disable secure ICMP redirects for IPv4
  run_command "echo 'net.ipv4.conf.all.secure_redirects = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.6 Set net.ipv4.conf.all.secure_redirects = 0"
  run_command "echo 'net.ipv4.conf.default.secure_redirects = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.6 Set net.ipv4.conf.default.secure_redirects = 0"

  # Apply settings immediately
  run_command "sysctl -w net.ipv4.conf.all.secure_redirects=0" "3.3.6 Apply net.ipv4.conf.all.secure_redirects"
  run_command "sysctl -w net.ipv4.conf.default.secure_redirects=0" "3.3.6 Apply net.ipv4.conf.default.secure_redirects"
  run_command "sysctl -w net.ipv4.route.flush=1" "3.3.6 Flush IPv4 routing table"

  # =====================[ UFW Override Handling ]=====================
  if [ -f /etc/ufw/sysctl.conf ]; then
    run_command "echo 'net.ipv4.conf.all.secure_redirects = 0' >> /etc/ufw/sysctl.conf" "3.3.6 Mirror net.ipv4.conf.all.secure_redirects in UFW sysctl.conf"
    run_command "echo 'net.ipv4.conf.default.secure_redirects = 0' >> /etc/ufw/sysctl.conf" "3.3.6 Mirror net.ipv4.conf.default.secure_redirects in UFW sysctl.conf"

    # Optional: prevent UFW from overriding system-wide sysctl
    run_command "sed -i 's/^IPT_SYSCTL=.*/IPT_SYSCTL=0/' /etc/default/ufw" "3.3.6 Set IPT_SYSCTL=0 to respect system-wide sysctl"
  fi

  # =====================[ SECTION 3.3.7: Enable Reverse Path Filtering ]=====================
  start_section "3.3.7"

  # Persistently enable reverse path filtering
  run_command "echo 'net.ipv4.conf.all.rp_filter = 1' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.7 Set net.ipv4.conf.all.rp_filter = 1"
  run_command "echo 'net.ipv4.conf.default.rp_filter = 1' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.7 Set net.ipv4.conf.default.rp_filter = 1"

  # Apply settings immediately
  run_command "sysctl -w net.ipv4.conf.all.rp_filter=1" "3.3.7 Apply net.ipv4.conf.all.rp_filter"
  run_command "sysctl -w net.ipv4.conf.default.rp_filter=1" "3.3.7 Apply net.ipv4.conf.default.rp_filter"
  run_command "sysctl -w net.ipv4.route.flush=1" "3.3.7 Flush IPv4 routing table"

  # =====================[ UFW Override Handling ]=====================
  if [ -f /etc/ufw/sysctl.conf ]; then
    run_command "echo 'net.ipv4.conf.all.rp_filter = 1' >> /etc/ufw/sysctl.conf" "3.3.7 Mirror net.ipv4.conf.all.rp_filter in UFW sysctl.conf"
    run_command "echo 'net.ipv4.conf.default.rp_filter = 1' >> /etc/ufw/sysctl.conf" "3.3.7 Mirror net.ipv4.conf.default.rp_filter in UFW sysctl.conf"

    # Optional: prevent UFW from overriding system-wide sysctl
    run_command "sed -i 's/^IPT_SYSCTL=.*/IPT_SYSCTL=0/' /etc/default/ufw" "3.3.7 Set IPT_SYSCTL=0 to respect system-wide sysctl"
  fi

  # =====================[ SECTION 3.3.8: Disable Source Routed Packet Acceptance ]=====================
  start_section "3.3.8"

  # Persistently disable source routed packets for IPv4
  run_command "echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.8 Set net.ipv4.conf.all.accept_source_route = 0"
  run_command "echo 'net.ipv4.conf.default.accept_source_route = 0' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.8 Set net.ipv4.conf.default.accept_source_route = 0"

  # Apply IPv4 settings immediately
  run_command "sysctl -w net.ipv4.conf.all.accept_source_route=0" "3.3.8 Apply net.ipv4.conf.all.accept_source_route"
  run_command "sysctl -w net.ipv4.conf.default.accept_source_route=0" "3.3.8 Apply net.ipv4.conf.default.accept_source_route"
  run_command "sysctl -w net.ipv4.route.flush=1" "3.3.8 Flush IPv4 routing table"

  # Check if IPv6 is enabled
  if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ] && [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -eq 0 ]; then
    # Persistently disable source routed packets for IPv6
    run_command "echo 'net.ipv6.conf.all.accept_source_route = 0' >> /etc/sysctl.d/60-netipv6_sysctl.conf" "3.3.8 Set net.ipv6.conf.all.accept_source_route = 0"
    run_command "echo 'net.ipv6.conf.default.accept_source_route = 0' >> /etc/sysctl.d/60-netipv6_sysctl.conf" "3.3.8 Set net.ipv6.conf.default.accept_source_route = 0"

    # Apply IPv6 settings immediately
    run_command "sysctl -w net.ipv6.conf.all.accept_source_route=0" "3.3.8 Apply net.ipv6.conf.all.accept_source_route"
    run_command "sysctl -w net.ipv6.conf.default.accept_source_route=0" "3.3.8 Apply net.ipv6.conf.default.accept_source_route"
    run_command "sysctl -w net.ipv6.route.flush=1" "3.3.8 Flush IPv6 routing table"
  else
    log_message "3.3.8 IPv6 is disabled — skipping IPv6 source route configuration"
  fi

  # =====================[ UFW Override Handling ]=====================
  if [ -f /etc/ufw/sysctl.conf ]; then
    run_command "echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/ufw/sysctl.conf" "3.3.8 Mirror net.ipv4.conf.all.accept_source_route in UFW sysctl.conf"
    run_command "echo 'net.ipv4.conf.default.accept_source_route = 0' >> /etc/ufw/sysctl.conf" "3.3.8 Mirror net.ipv4.conf.default.accept_source_route in UFW sysctl.conf"

    if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ] && [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -eq 0 ]; then
      run_command "echo 'net.ipv6.conf.all.accept_source_route = 0' >> /etc/ufw/sysctl.conf" "3.3.8 Mirror net.ipv6.conf.all.accept_source_route in UFW sysctl.conf"
      run_command "echo 'net.ipv6.conf.default.accept_source_route = 0' >> /etc/ufw/sysctl.conf" "3.3.8 Mirror net.ipv6.conf.default.accept_source_route in UFW sysctl.conf"
    fi

    # Optional: prevent UFW from overriding system-wide sysctl
    run_command "sed -i 's/^IPT_SYSCTL=.*/IPT_SYSCTL=0/' /etc/default/ufw" "3.3.8 Set IPT_SYSCTL=0 to respect system-wide sysctl"
  fi

  # =====================[ SECTION 3.3.9: Enable Logging of Suspicious Packets ]=====================
  start_section "3.3.9"

  # Persistently enable logging of martian packets for IPv4
  run_command "echo 'net.ipv4.conf.all.log_martians = 1' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.9 Set net.ipv4.conf.all.log_martians = 1"
  run_command "echo 'net.ipv4.conf.default.log_martians = 1' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.9 Set net.ipv4.conf.default.log_martians = 1"

  # Apply settings immediately
  run_command "sysctl -w net.ipv4.conf.all.log_martians=1" "3.3.9 Apply net.ipv4.conf.all.log_martians"
  run_command "sysctl -w net.ipv4.conf.default.log_martians=1" "3.3.9 Apply net.ipv4.conf.default.log_martians"
  run_command "sysctl -w net.ipv4.route.flush=1" "3.3.9 Flush IPv4 routing table"

  # =====================[ UFW Override Handling ]=====================
  if [ -f /etc/ufw/sysctl.conf ]; then
    run_command "echo 'net.ipv4.conf.all.log_martians = 1' >> /etc/ufw/sysctl.conf" "3.3.9 Mirror net.ipv4.conf.all.log_martians in UFW sysctl.conf"
    run_command "echo 'net.ipv4.conf.default.log_martians = 1' >> /etc/ufw/sysctl.conf" "3.3.9 Mirror net.ipv4.conf.default.log_martians in UFW sysctl.conf"

    # Optional: prevent UFW from overriding system-wide sysctl
    run_command "sed -i 's/^IPT_SYSCTL=.*/IPT_SYSCTL=0/' /etc/default/ufw" "3.3.9 Set IPT_SYSCTL=0 to respect system-wide sysctl"
  fi

  # =====================[ SECTION 3.3.10: Enable TCP SYN Cookies ]=====================
  start_section "3.3.10"

  # Persistently enable TCP SYN cookies
  run_command "echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.d/60-netipv4_sysctl.conf" "3.3.10 Set net.ipv4.tcp_syncookies = 1"

  # Apply setting immediately
  run_command "sysctl -w net.ipv4.tcp_syncookies=1" "3.3.10 Apply net.ipv4.tcp_syncookies"
  run_command "sysctl -w net.ipv4.route.flush=1" "3.3.10 Flush IPv4 routing table"

  # =====================[ UFW Override Handling ]=====================
  if [ -f /etc/ufw/sysctl.conf ]; then
    run_command "echo 'net.ipv4.tcp_syncookies = 1' >> /etc/ufw/sysctl.conf" "3.3.10 Mirror net.ipv4.tcp_syncookies in UFW sysctl.conf"

    # Optional: prevent UFW from overriding system-wide sysctl
    run_command "sed -i 's/^IPT_SYSCTL=.*/IPT_SYSCTL=0/' /etc/default/ufw" "3.3.10 Set IPT_SYSCTL=0 to respect system-wide sysctl"
  fi

  # =====================[ SECTION 3.3.11: Disable IPv6 Router Advertisements ]=====================
  start_section "3.3.11"

  # Check if IPv6 is enabled
  if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ] && [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -eq 0 ]; then
    # Persistently disable IPv6 router advertisements
    run_command "echo 'net.ipv6.conf.all.accept_ra = 0' >> /etc/sysctl.d/60-netipv6_sysctl.conf" "3.3.11 Set net.ipv6.conf.all.accept_ra = 0"
    run_command "echo 'net.ipv6.conf.default.accept_ra = 0' >> /etc/sysctl.d/60-netipv6_sysctl.conf" "3.3.11 Set net.ipv6.conf.default.accept_ra = 0"

    # Apply settings immediately
    run_command "sysctl -w net.ipv6.conf.all.accept_ra=0" "3.3.11 Apply net.ipv6.conf.all.accept_ra"
    run_command "sysctl -w net.ipv6.conf.default.accept_ra=0" "3.3.11 Apply net.ipv6.conf.default.accept_ra"
    run_command "sysctl -w net.ipv6.route.flush=1" "3.3.11 Flush IPv6 routing table"

    # =====================[ UFW Override Handling ]=====================
    if [ -f /etc/ufw/sysctl.conf ]; then
      run_command "echo 'net.ipv6.conf.all.accept_ra = 0' >> /etc/ufw/sysctl.conf" "3.3.11 Mirror net.ipv6.conf.all.accept_ra in UFW sysctl.conf"
      run_command "echo 'net.ipv6.conf.default.accept_ra = 0' >> /etc/ufw/sysctl.conf" "3.3.11 Mirror net.ipv6.conf.default.accept_ra in UFW sysctl.conf"

      # Optional: prevent UFW from overriding system-wide sysctl
      run_command "sed -i 's/^IPT_SYSCTL=.*/IPT_SYSCTL=0/' /etc/default/ufw" "3.3.11 Set IPT_SYSCTL=0 to respect system-wide sysctl"
    fi
  else
    log_message "3.3.11 IPv6 is disabled — skipping router advertisement configuration"
  fi
fi

##############################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "4.1" || "$TARGET_SECTION" == "4.2" || "$TARGET_SECTION" == "4.3" || "$TARGET_SECTION" == "4.4" ]]; then
  # =====================[ SECTION 4.1.1: Choose and Configure Single Firewall Utility ]=====================
  start_section "4.1.1"

  # Set your preferred firewall utility here: ufw, firewalld, nftables, iptables
  PREFERRED_FIREWALL="ufw"

  # Disable all other firewall services
  if [[ "$PREFERRED_FIREWALL" == "ufw" ]]; then
    run_command "systemctl disable --now firewalld 2>/dev/null || true" "4.1.1 Disable firewalld"
    run_command "systemctl disable --now nftables 2>/dev/null || true" "4.1.1 Disable nftables"

    # =====================[ SECTION 4.2: Configure UFW ]=====================
    start_section "4.2.1"
    run_command "apt-get install -y ufw" "4.2.1 Install UFW"

    start_section "4.2.2"
    run_command "apt-get purge -y iptables-persistent" "4.2.2 Remove iptables-persistent"

    start_section "4.2.3"
    run_command "systemctl unmask ufw.service" "4.2.3 Unmask UFW service"
    run_command "systemctl --now enable ufw.service" "4.2.3 Enable and start UFW service"
    run_command "ufw enable" "4.2.3 Enable UFW firewall"

    start_section "4.2.4"
    run_command "ufw allow in on lo" "4.2.4 Allow inbound traffic on loopback"
    run_command "ufw allow out on lo" "4.2.4 Allow outbound traffic on loopback"
    run_command "ufw deny in from 127.0.0.0/8" "4.2.4 Deny inbound traffic to loopback from 127.0.0.0/8"
    run_command "ufw deny in from ::1" "4.2.4 Deny inbound traffic to loopback from ::1"

    start_section "4.2.7"
    run_command "ufw default deny incoming" "4.2.7 Set default deny for incoming traffic"
    run_command "ufw default deny outgoing" "4.2.7 Set default deny for outgoing traffic"
    run_command "ufw default deny routed" "4.2.7 Set default deny for routed traffic"

  elif [[ "$PREFERRED_FIREWALL" == "nftables" ]]; then
    run_command "systemctl disable --now ufw 2>/dev/null || true" "4.1.1 Disable UFW"
    run_command "systemctl disable --now firewalld 2>/dev/null || true" "4.1.1 Disable firewalld"

    # =====================[ SECTION 4.3: Configure nftables ]=====================
    start_section "4.3.1"
    run_command "apt-get install -y nftables" "4.3.1 Install nftables"

    start_section "4.3.2"
    run_command "systemctl disable --now ufw 2>/dev/null || true" "4.3.2 Disable UFW with nftables"

    start_section "4.3.3"
    run_command "iptables -F && iptables -X" "4.3.3 Flush IPv4 iptables rules"
    run_command "ip6tables -F && ip6tables -X" "4.3.3 Flush IPv6 iptables rules"

    start_section "4.3.4"
    run_command "nft add table inet filter" "4.3.4 Create nftables table"

    start_section "4.3.5"
    run_command "nft add chain inet filter input { type filter hook input priority 0; policy drop; }" "4.3.5 Create input chain"
    run_command "nft add chain inet filter forward { type filter hook forward priority 0; policy drop; }" "4.3.5 Create forward chain"
    run_command "nft add chain inet filter output { type filter hook output priority 0; policy accept; }" "4.3.5 Create output chain"

    start_section "4.3.6"
    run_command "nft add rule inet filter input iif lo accept" "4.3.6 Accept loopback traffic"
    run_command "nft add rule inet filter input ip saddr 127.0.0.0/8 counter drop" "4.3.6 Drop spoofed loopback traffic"
    run_command "nft add rule inet filter input ip6 saddr ::1 counter drop" "4.3.6 Drop spoofed IPv6 loopback traffic"

    start_section "4.3.8"
    run_command "nft add rule inet filter input ct state established,related accept" "4.3.8 Accept established/related connections"
    run_command "nft add rule inet filter input counter drop" "4.3.8 Default deny all other input"

    start_section "4.3.9"
    run_command "systemctl enable --now nftables" "4.3.9 Enable nftables service"

    start_section "4.3.10"
    run_command "nft list ruleset > /etc/nftables.conf" "4.3.10 Save nftables ruleset to config"

  elif [[ "$PREFERRED_FIREWALL" == "iptables" ]]; then
    run_command "systemctl disable --now ufw 2>/dev/null || true" "4.1.1 Disable UFW"
    run_command "systemctl disable --now firewalld 2>/dev/null || true" "4.1.1 Disable firewalld"
    run_command "systemctl disable --now nftables 2>/dev/null || true" "4.1.1 Disable nftables"

    # =====================[ SECTION 4.4: Configure iptables ]=====================
    start_section "4.4.1.1"
    run_command "apt-get install -y iptables iptables-persistent" "4.4.1.1 Install iptables packages"

    start_section "4.4.1.2"
    run_command "systemctl disable --now nftables 2>/dev/null || true" "4.4.1.2 Disable nftables with iptables"

    start_section "4.4.1.3"
    run_command "systemctl disable --now ufw 2>/dev/null || true" "4.4.1.3 Disable UFW with iptables"

    start_section "4.4.2.1"
    run_command "iptables -P INPUT DROP" "4.4.2.1 Set default deny for INPUT"
    run_command "iptables -P FORWARD DROP" "4.4.2.1 Set default deny for FORWARD"
    run_command "iptables -P OUTPUT ACCEPT" "4.4.2.1 Set default policy for OUTPUT"

    start_section "4.4.2.2"
    run_command "iptables -A INPUT -i lo -j ACCEPT" "4.4.2.2 Accept loopback traffic"
    run_command "iptables -A OUTPUT -o lo -j ACCEPT" "4.4.2.2 Accept loopback outbound"
    run_command "iptables -A INPUT -s 127.0.0.0/8 -j DROP" "4.4.2.2 Drop spoofed loopback traffic"

    start_section "4.4.3.1"
    run_command "ip6tables -P INPUT DROP" "4.4.3.1 Set default deny for IPv6 INPUT"
    run_command "ip6tables -P FORWARD DROP" "4.4.3.1 Set default deny for IPv6 FORWARD"
    run_command "ip6tables -P OUTPUT ACCEPT" "4.4.3.1 Set default policy for IPv6 OUTPUT"

    start_section "4.4.3.2"
    run_command "ip6tables -A INPUT -i lo -j ACCEPT" "4.4.3.2 Accept IPv6 loopback traffic"
    run_command "ip6tables -A OUTPUT -o lo -j ACCEPT" "4.4.3.2 Accept IPv6 loopback outbound"
    run_command "ip6tables -A INPUT -s ::1 -j DROP" "4.4.3.2 Drop spoofed IPv6 loopback traffic"
  fi

  # Final check: confirm only one firewall is active
  ACTIVE_FIREWALLS=$(systemctl list-units --type=service | grep -E 'ufw|firewalld|nftables' | grep active | wc -l)
  if [[ "$ACTIVE_FIREWALLS" -eq 1 ]]; then
    log_message "4.1.1 $PREFERRED_FIREWALL is the only active firewall — compliant"
  else
    log_message "4.1.1 Warning: Multiple firewall services may still be active"
  fi
fi

############################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "5.1.1" ]]; then
  # =====================[ SECTION 5.1.1: Secure SSH Configuration Files ]=====================
  start_section "5.1.1"

  # Secure main sshd_config file
  run_command "chmod u-x,og-rwx /etc/ssh/sshd_config" "5.1.1 Set permissions on /etc/ssh/sshd_config"
  run_command "chown root:root /etc/ssh/sshd_config" "5.1.1 Set ownership on /etc/ssh/sshd_config"

  # Secure all *.conf files in /etc/ssh/sshd_config.d
  while IFS= read -r -d $'\0' l_file; do
    run_command "chmod u-x,og-rwx \"$l_file\"" "5.1.1 Set permissions on $l_file"
    run_command "chown root:root \"$l_file\"" "5.1.1 Set ownership on $l_file"
  done < <(find /etc/ssh/sshd_config.d -type f -name '*.conf' -print0 2>/dev/null)

  # =====================[ Handle Include Directives ]=====================
  INCLUDE_PATHS=$(grep -E '^\s*Include\s+' /etc/ssh/sshd_config | awk '{print $2}')
  for path in $INCLUDE_PATHS; do
    # Expand wildcards and secure matching *.conf files
    for file in $(find $(dirname "$path") -type f -name "$(basename "$path")" 2>/dev/null); do
      run_command "chmod u-x,og-rwx \"$file\"" "5.1.1 Set permissions on included file $file"
      run_command "chown root:root \"$file\"" "5.1.1 Set ownership on included file $file"
    done
  done

  # =====================[ SECTION 5.1.2: Secure SSH Private Host Key Files ]=====================
  start_section "5.1.2"

  # Determine SSH group name (if any)
  SSH_GROUP=$(awk -F: '($1 ~ /^(ssh_keys|_?ssh)$/) {print $1}' /etc/group)

  # Find and process private SSH host key files
  while IFS= read -r -d $'\0' file; do
    if ssh-keygen -lf "$file" &>/dev/null && file "$file" | grep -Piq '\bopenssh\b.*\bprivate key\b'; then
      # Get file mode, owner, and group
      read -r mode owner group <<< "$(stat -Lc '%a %U %G' "$file")"

      # Determine expected permissions
      if [[ "$group" == "$SSH_GROUP" ]]; then
        expected_mode="0640"
        run_command "chmod u-x,g-wx,o-rwx \"$file\"" "5.1.2 Restrict permissions on $file (group: $group)"
      else
        expected_mode="0600"
        run_command "chmod u-x,go-rwx \"$file\"" "5.1.2 Restrict permissions on $file (group: $group)"
      fi

      # Fix ownership if needed
      if [[ "$owner" != "root" ]]; then
        run_command "chown root \"$file\"" "5.1.2 Set owner to root for $file"
      fi

      # Fix group if needed
      if [[ "$group" != "$SSH_GROUP" && "$group" != "root" ]]; then
        new_group="${SSH_GROUP:-root}"
        run_command "chgrp \"$new_group\" \"$file\"" "5.1.2 Set group to $new_group for $file"
      fi
    fi
  done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null)

  # =====================[ SECTION 5.1.3: Secure SSH Public Host Key Files ]=====================
  start_section "5.1.3"

  # Define permission mask and expected mode
  PERM_MASK=0133
  EXPECTED_MODE=$(printf '%o' $((0777 & ~$PERM_MASK)))

  # Find and process public SSH host key files
  while IFS= read -r -d $'\0' file; do
    if ssh-keygen -lf "$file" &>/dev/null && file "$file" | grep -Piq '\bopenssh\b.*\bpublic key\b'; then
      read -r mode owner group <<< "$(stat -Lc '%a %U %G' "$file")"

      # Fix permissions if needed
      if (( mode & PERM_MASK )); then
        run_command "chmod u-x,go-wx \"$file\"" "5.1.3 Restrict permissions on $file"
      fi

      # Fix ownership if needed
      if [[ "$owner" != "root" ]]; then
        run_command "chown root \"$file\"" "5.1.3 Set owner to root for $file"
      fi

      # Fix group if needed
      if [[ "$group" != "root" ]]; then
        run_command "chgrp root \"$file\"" "5.1.3 Set group to root for $file"
      fi
    fi
  done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null)
fi



# =====================[ END OF CIS Ubuntu 24.04 HARDENING SCRIPT ]=====================

echo ""
echo "✅ CIS Oracle Linux 9 hardening complete."
echo "📌 Please review any warnings or manual steps noted during execution."
echo "🔁 A reboot may be required for certain changes to take effect."
echo "🗂️ Logs saved to: $LOG_DIR"
echo ""

# 📊 Summary of results
echo "📊 Summary of results:"
ALL_ERRORS="$LOG_DIR/all_errors.log"
> "$ALL_ERRORS"  # Clear or create the global error log

for section in "$LOG_DIR/section_logs"/*; do
  sec_name=$(basename "$section")
  success_log="$section/success.log"
  error_log="$section/error.log"

  success_count=0
  error_count=0

  # Count successes
  [ -f "$success_log" ] && success_count=$(wc -l < "$success_log")

  # Count errors and append to global error log
  if [ -f "$error_log" ]; then
    error_count=$(wc -l < "$error_log")
    while IFS= read -r line; do
      echo "[$sec_name] $line" >> "$ALL_ERRORS"
    done < "$error_log"
  fi

  echo "  - $sec_name: ✅ $success_count success(es), ❌ $error_count error(s)"
done

# 📄 Global error log summary
if [ -s "$ALL_ERRORS" ]; then
  echo ""
  echo "❗ Errors were recorded during execution."
  echo "📄 Review them in: $ALL_ERRORS"
else
  echo ""
  echo "✅ No errors recorded in global log."
fi

echo ""
echo "🛡️ Stay secure. Stay compliant."
