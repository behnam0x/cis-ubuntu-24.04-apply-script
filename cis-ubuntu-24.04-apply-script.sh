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
 
 # Reusable function to disable a kernel module if it exists
 disable_module() {
   local mod="$1"
   local conf="/etc/modprobe.d/${mod}.conf"
   local bin_false
   bin_false="$(readlink -f /bin/false)"
 
   # Check if module exists in kernel
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
 
 # List of filesystem modules to disable (CIS 1.1.1.1 – 1.1.1.9)
 for mod in cramfs freevxfs hfs hfsplus jffs2 squashfs udf usb-storage overlayfs; do
   disable_module "$mod"
 done
 
 # Remove related user-space tools (CIS 1.1.1.9)
 for pkg in cramfs-utils squashfs-tools; do
   if dpkg -l | grep -qw "$pkg"; then
     run_command "apt purge -y $pkg" "1.1.1.9 Remove $pkg package"
   else
     log_message "1.1.1.9 Package $pkg not installed — skipping purge"
   fi
 done


 # =====================[ SECTION 1.1.2: Configure Filesystem Partitions ]=====================
 start_section "1.1.2"
 
 # Helper function to enforce mount options in /etc/fstab
 enforce_mount_option() {
   local mount_point="$1"
   local option="$2"
   local checklist="$3"
   run_command "sed -i \"/[[:space:]]${mount_point}[[:space:]]/ s/defaults/defaults,${option}/\" /etc/fstab" "${checklist} Set ${option} on ${mount_point}"
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

# =====================[ SECTION 1.7.1: Ensure GDM is removed ]=====================
start_section "1.7.1"

# Remove gdm3 and unused dependencies
if dpkg -l | grep -qw gdm3; then
  run_command "apt purge -y gdm3" "1.7.1 Remove gdm3 package"
  run_command "apt autoremove -y gdm3" "1.7.1 Autoremove gdm3 dependencies"
else
  log_message "1.7.1 gdm3 is not installed — no action needed"
fi

# =====================[ SECTION 1.7.2: Ensure GDM login banner is configured ]=====================
start_section "1.7.2"

BANNER_TEXT="Authorized uses only. All activity may be monitored and reported"
GDM_PROFILE="gdm"
GDM_PROFILE_FILE="/etc/dconf/profile/${GDM_PROFILE}"
GDM_DB_DIR="/etc/dconf/db/${GDM_PROFILE}.d"
GDM_KEYFILE="${GDM_DB_DIR}/01-banner-message"

# Check if running in graphical session
if [ "$XDG_SESSION_TYPE" = "x11" ] || [ "$XDG_SESSION_TYPE" = "wayland" ]; then
  run_command "gsettings set org.gnome.login-screen banner-message-text '${BANNER_TEXT}'" "1.7.2 Set GDM banner text via gsettings"
  run_command "gsettings set org.gnome.login-screen banner-message-enable true" "1.7.2 Enable GDM banner via gsettings"
else
  log_message "1.7.2 Not in graphical session — applying system-wide dconf configuration"

  # Create GDM profile if missing
  run_command "mkdir -p /etc/dconf/profile" "1.7.2 Ensure /etc/dconf/profile exists"
  run_command "echo -e 'user-db:user\nsystem-db:${GDM_PROFILE}\nfile-db:/usr/share/${GDM_PROFILE}/greeter-dconf-defaults' > ${GDM_PROFILE_FILE}" "1.7.2 Create GDM profile file"

  # Create GDM database directory and keyfile
  run_command "mkdir -p ${GDM_DB_DIR}" "1.7.2 Ensure GDM dconf database directory exists"
  run_command "echo -e '[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='\"${BANNER_TEXT}\" > ${GDM_KEYFILE}" "1.7.2 Write GDM banner settings to keyfile"

  # Apply dconf changes
  run_command "dconf update" "1.7.2 Apply dconf changes"
fi

# =====================[ SECTION 1.7.3: Ensure GDM disable-user-list option is enabled ]=====================
start_section "1.7.3"

GDM_PROFILE="gdm"
GDM_PROFILE_FILE="/etc/dconf/profile/${GDM_PROFILE}"
GDM_DB_DIR="/etc/dconf/db/${GDM_PROFILE}.d"
GDM_KEYFILE="${GDM_DB_DIR}/00-login-screen"

# Check if running in graphical session
if [ "$XDG_SESSION_TYPE" = "x11" ] || [ "$XDG_SESSION_TYPE" = "wayland" ]; then
  run_command "gsettings set org.gnome.login-screen disable-user-list true" "1.7.3 Set disable-user-list via gsettings"
else
  log_message "1.7.3 Not in graphical session — applying system-wide dconf configuration"

  # Create GDM profile if missing
  run_command "mkdir -p /etc/dconf/profile" "1.7.3 Ensure /etc/dconf/profile exists"
  run_command "echo -e 'user-db:user\nsystem-db:${GDM_PROFILE}\nfile-db:/usr/share/${GDM_PROFILE}/greeter-dconf-defaults' > ${GDM_PROFILE_FILE}" "1.7.3 Create GDM profile file"

  # Create GDM database directory and keyfile
  run_command "mkdir -p ${GDM_DB_DIR}" "1.7.3 Ensure GDM dconf database directory exists"
  run_command "echo -e '[org/gnome/login-screen]\n# Do not show the user list\ndisable-user-list=true' > ${GDM_KEYFILE}" "1.7.3 Write disable-user-list setting to keyfile"

  # Apply dconf changes
  run_command "dconf update" "1.7.3 Apply dconf changes"
fi

# =====================[ SECTION 1.7.4: Ensure GDM screen locks when the user is idle ]=====================
start_section "1.7.4"

# Idle and lock delay values (in seconds)
IDLE_DELAY="900"
LOCK_DELAY="5"

DCONF_DB="local"
DCONF_PROFILE="/etc/dconf/profile/user"
DCONF_DB_DIR="/etc/dconf/db/${DCONF_DB}.d"
DCONF_KEYFILE="${DCONF_DB_DIR}/00-screensaver"

# Check if running in graphical session
if [ "$XDG_SESSION_TYPE" = "x11" ] || [ "$XDG_SESSION_TYPE" = "wayland" ]; then
  run_command "gsettings set org.gnome.desktop.screensaver lock-delay ${LOCK_DELAY}" "1.7.4 Set lock-delay via gsettings"
  run_command "gsettings set org.gnome.desktop.session idle-delay ${IDLE_DELAY}" "1.7.4 Set idle-delay via gsettings"
else
  log_message "1.7.4 Not in graphical session — applying system-wide dconf configuration"

  # Ensure dconf profile includes the local database
  run_command "mkdir -p /etc/dconf/profile" "1.7.4 Ensure /etc/dconf/profile exists"
  if ! grep -q "system-db:${DCONF_DB}" "${DCONF_PROFILE}" 2>/dev/null; then
    run_command "echo -e 'user-db:user\nsystem-db:${DCONF_DB}' >> ${DCONF_PROFILE}" "1.7.4 Add ${DCONF_DB} to dconf profile"
  fi

  # Create dconf database directory and keyfile
  run_command "mkdir -p ${DCONF_DB_DIR}" "1.7.4 Ensure dconf database directory exists"
  run_command "cat << EOF > ${DCONF_KEYFILE}
[org/gnome/desktop/session]
idle-delay=uint32 ${IDLE_DELAY}
[org/gnome/desktop/screensaver]
lock-delay=uint32 ${LOCK_DELAY}
EOF" "1.7.4 Write screensaver lock settings"

  # Apply dconf changes
  run_command "dconf update" "1.7.4 Apply dconf changes"
fi

# =====================[ SECTION 1.7.5: Ensure GDM screen locks cannot be overridden ]=====================
start_section "1.7.5"

DCONF_DB="local"
LOCK_DIR="/etc/dconf/db/${DCONF_DB}.d/locks"
LOCK_FILE="${LOCK_DIR}/00-screensaver"

# Ensure lock directory exists
run_command "mkdir -p ${LOCK_DIR}" "1.7.5 Ensure dconf lock directory exists"

# Write lock entries
run_command "echo '/org/gnome/desktop/session/idle-delay' > ${LOCK_FILE}" "1.7.5 Lock idle-delay setting"
run_command "echo '/org/gnome/desktop/screensaver/lock-delay' >> ${LOCK_FILE}" "1.7.5 Lock lock-delay setting"

# Apply dconf changes
run_command "dconf update" "1.7.5 Apply dconf changes"

# =====================[ SECTION 1.7.6: Disable GDM automatic mounting of removable media ]=====================
start_section "1.7.6"

DCONF_DB="local"
DCONF_PROFILE="/etc/dconf/profile/user"
DCONF_DB_DIR="/etc/dconf/db/${DCONF_DB}.d"
DCONF_KEYFILE="${DCONF_DB_DIR}/00-media-automount"

# Check if running in graphical session
if [ "$XDG_SESSION_TYPE" = "x11" ] || [ "$XDG_SESSION_TYPE" = "wayland" ]; then
  run_command "gsettings set org.gnome.desktop.media-handling automount false" "1.7.6 Disable automount via gsettings"
  run_command "gsettings set org.gnome.desktop.media-handling automount-open false" "1.7.6 Disable automount-open via gsettings"
else
  log_message "1.7.6 Not in graphical session — applying system-wide dconf configuration"

  # Ensure dconf profile includes the local database
  run_command "mkdir -p /etc/dconf/profile" "1.7.6 Ensure /etc/dconf/profile exists"
  if ! grep -q "system-db:${DCONF_DB}" "${DCONF_PROFILE}" 2>/dev/null; then
    run_command "echo -e '\nuser-db:user\nsystem-db:${DCONF_DB}' >> ${DCONF_PROFILE}" "1.7.6 Add ${DCONF_DB} to dconf profile"
  fi

  # Create dconf database directory and keyfile
  run_command "mkdir -p ${DCONF_DB_DIR}" "1.7.6 Ensure dconf database directory exists"
  run_command "echo -e '[org/gnome/desktop/media-handling]\nautomount=false\nautomount-open=false' > ${DCONF_KEYFILE}" "1.7.6 Write automount settings"

  # Apply dconf changes
  run_command "dconf update" "1.7.6 Apply dconf changes"
fi

# =====================[ SECTION 1.7.7: Lock GDM automount settings ]=====================
start_section "1.7.7"

DCONF_DB="local"
LOCK_DIR="/etc/dconf/db/${DCONF_DB}.d/locks"
LOCK_FILE="${LOCK_DIR}/00-media-automount"

# Ensure lock directory exists
run_command "mkdir -p ${LOCK_DIR}" "1.7.7 Ensure dconf lock directory exists"

# Write lock entries
run_command "echo '/org/gnome/desktop/media-handling/automount' > ${LOCK_FILE}" "1.7.7 Lock automount setting"
run_command "echo '/org/gnome/desktop/media-handling/automount-open' >> ${LOCK_FILE}" "1.7.7 Lock automount-open setting"

# Apply dconf changes
run_command "dconf update" "1.7.7 Apply dconf changes"

# =====================[ SECTION 1.7.8: Ensure GDM autorun-never is enabled ]=====================
start_section "1.7.8"

DCONF_DB="local"
DCONF_PROFILE="/etc/dconf/profile/user"
DCONF_DB_DIR="/etc/dconf/db/${DCONF_DB}.d"
DCONF_KEYFILE="${DCONF_DB_DIR}/00-media-autorun"

# Check if running in graphical session
if [ "$XDG_SESSION_TYPE" = "x11" ] || [ "$XDG_SESSION_TYPE" = "wayland" ]; then
  run_command "gsettings set org.gnome.desktop.media-handling autorun-never true" "1.7.8 Set autorun-never via gsettings"
else
  log_message "1.7.8 Not in graphical session — applying system-wide dconf configuration"

  # Ensure dconf profile includes the local database
  run_command "mkdir -p /etc/dconf/profile" "1.7.8 Ensure /etc/dconf/profile exists"
  if ! grep -q "system-db:${DCONF_DB}" "${DCONF_PROFILE}" 2>/dev/null; then
    run_command "echo -e '\nuser-db:user\nsystem-db:${DCONF_DB}' >> ${DCONF_PROFILE}" "1.7.8 Add ${DCONF_DB} to dconf profile"
  fi

  # Create dconf database directory and keyfile
  run_command "mkdir -p ${DCONF_DB_DIR}" "1.7.8 Ensure dconf database directory exists"
  run_command "echo -e '[org/gnome/desktop/media-handling]\nautorun-never=true' > ${DCONF_KEYFILE}" "1.7.8 Write autorun-never setting"

  # Apply dconf changes
  run_command "dconf update" "1.7.8 Apply dconf changes"
fi

# =====================[ SECTION 1.7.9: Lock GDM autorun-never setting ]=====================
start_section "1.7.9"

DCONF_DB="local"
LOCK_DIR="/etc/dconf/db/${DCONF_DB}.d/locks"
LOCK_FILE="${LOCK_DIR}/00-media-autorun"

# Ensure lock directory exists
run_command "mkdir -p ${LOCK_DIR}" "1.7.9 Ensure dconf lock directory exists"

# Write lock entry
run_command "echo '/org/gnome/desktop/media-handling/autorun-never' > ${LOCK_FILE}" "1.7.9 Lock autorun-never setting"

# Apply dconf changes
run_command "dconf update" "1.7.9 Apply dconf changes"

# =====================[ SECTION 1.7.10: Ensure XDMCP is not enabled ]=====================
start_section "1.7.10"

GDM_CONF="/etc/gdm/custom.conf"

# Check if file exists and contains active XDMCP enablement
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
