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

    if grep -qE "[[:space:]]${mount_point}[[:space:]]" /etc/fstab; then
      run_command "awk -v mp=\"$mount_point\" -v opt=\"$option\" '
      \$2 == mp {
        split(\$4, opts, \",\");
        found = 0;
        for (i in opts) if (opts[i] == opt) found = 1;
        if (!found) \$4 = \$4 \",\" opt;
      }
      { print }' /etc/fstab > /etc/fstab.tmp && mv /etc/fstab.tmp /etc/fstab" \
      "${checklist} Set ${option} on ${mount_point}"
    else
      log_message "${checklist} ${mount_point} not found in /etc/fstab — FAIL"
    fi
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

if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "1.2" ]]; then

  # =====================[ SECTION 1.2.1.1: Ensure GPG keys are configured ]=====================
  start_section "1.2.1.1"

  # Check for configured GPG keys in apt-key keyring
  if apt-key list 2>/dev/null | grep -q "pub"; then
    log_message "1.2.1.1 GPG keys are present in apt-key keyring"
  else
    log_message "1.2.1.1 No GPG keys found in apt-key keyring — manual review required"
  fi

  # Check for GPG key files in trusted.gpg.d
  if find /etc/apt/trusted.gpg.d/ -type f -name '*.gpg' | grep -q .; then
    log_message "1.2.1.1 GPG key files found in /etc/apt/trusted.gpg.d/"
  else
    log_message "1.2.1.1 No GPG key files found in /etc/apt/trusted.gpg.d/ — manual review required"
  fi

  log_message "1.2.1.1 Manual remediation: Ensure GPG keys are configured according to site policy"

  # =====================[ SECTION 1.2.1.2: Ensure package manager repositories are configured ]=====================
  start_section "1.2.1.2"

  # List configured APT repositories
  run_command "grep -h ^deb /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null" "1.2.1.2 List configured APT repositories"

  log_message "1.2.1.2 Manual remediation: Review and configure repositories according to site policy"

  # =====================[ SECTION 1.2.2.1: Ensure updates and security patches are installed ]=====================
  start_section "1.2.2.1"

  run_apt_command() {
    local CMD="$1"
    local LABEL="$2"
    local LOG="/tmp/apt_output.log"

    timeout 60 bash -c "$CMD" > "$LOG" 2>&1
    local EXIT_CODE=$?

    if [[ $EXIT_CODE -eq 124 ]]; then
      log_message "$LABEL Timeout: apt command exceeded 60s and was skipped"
    elif grep -qiE "Could not resolve|Temporary failure|Failed to fetch|Connection timed out|No address associated" "$LOG"; then
      log_message "$LABEL Network error: Unable to reach repositories"
    elif grep -qiE "unmet dependencies|dpkg was interrupted|fix-broken install" "$LOG"; then
      log_message "$LABEL Apt error: Dependency or package issue detected"
    elif [[ $EXIT_CODE -ne 0 ]]; then
      log_message "$LABEL Apt failed with exit code $EXIT_CODE"
    else
      log_message "$LABEL Success"
    fi
  }

  run_apt_command "apt update" "1.2.2.1 Refresh package index"
  run_apt_command "apt upgrade -y" "1.2.2.1 Apply standard package upgrades"
  run_apt_command "apt dist-upgrade -y" "1.2.2.1 Apply full distribution upgrade (site policy dependent)"

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

  # Ensure SSH displays the banner before login
  run_command "sed -i '/^Banner /d' /etc/ssh/sshd_config && echo 'Banner /etc/issue.net' >> /etc/ssh/sshd_config" "1.6.x Configure SSH banner directive"

  # =====================[ 1.6.1: Create Custom MOTD Script ]=====================
  run_command "mkdir -p /etc/update-motd.d" "1.6.1 Ensure MOTD directory exists"
  run_command "find /etc/update-motd.d/ -type f ! -name '00-custom' -exec chmod -x {} \;" "1.6.1 Disable default MOTD scripts"

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

  # =====================[ 1.6.4–1.6.6: File Permissions and Ownership ]=====================
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
    run_command "ufw --force enable" "4.2.3 Enable UFW firewall (forced)"


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
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "5.1" ]]; then
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

  # =====================[ SECTION 5.1.4: Configure SSHD Access Control ]=====================
  start_section "5.1.4"

  # Define your access control method: either AllowUsers or AllowGroups
  SSHD_ACCESS_TYPE="AllowUsers"  # or "AllowGroups"
  SSHD_ACCESS_VALUE="adminuser behnam admin"  # comma-separated list of users or groups

  # Backup original config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.4 Backup sshd_config"

  # Insert directive before first Include or Match statement
  if grep -qE '^\s*(Include|Match)\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    run_command "sed -i '${LINE_NUM}i\\${SSHD_ACCESS_TYPE} ${SSHD_ACCESS_VALUE}' /etc/ssh/sshd_config" "5.1.4 Insert ${SSHD_ACCESS_TYPE} before Include/Match"
  else
    run_command "echo '${SSHD_ACCESS_TYPE} ${SSHD_ACCESS_VALUE}' >> /etc/ssh/sshd_config" "5.1.4 Append ${SSHD_ACCESS_TYPE} to sshd_config"
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.5: Configure SSHD Banner ]=====================
  start_section "5.1.5"

  # Define banner path and message
  BANNER_PATH="/etc/issue.net"
  BANNER_MESSAGE="Authorized users only. All activity may be monitored and reported."

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.5 Backup sshd_config"

  # Insert Banner directive before first Include or Match
  if grep -qE '^\s*(Include|Match)\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    run_command "sed -i '${LINE_NUM}i\\Banner ${BANNER_PATH}' /etc/ssh/sshd_config" "5.1.5 Insert Banner directive before Include/Match"
  else
    run_command "echo 'Banner ${BANNER_PATH}' >> /etc/ssh/sshd_config" "5.1.5 Append Banner directive to sshd_config"
  fi

  # Create banner file with sanitized message
  run_command "printf '%s\\n' \"${BANNER_MESSAGE}\" > ${BANNER_PATH}" "5.1.5 Create banner file"
  run_command "sed -i 's/\\\

\[mrsv]//g' ${BANNER_PATH}" "5.1.5 Remove platform escape sequences from banner"

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.6: Configure SSHD Ciphers ]=====================
  start_section "5.1.6"

  # Define the list of weak ciphers to exclude
  CIPHER_LINE="Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,chacha20-poly1305@openssh.com"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.6 Backup sshd_config"

  # Insert or update Ciphers directive before first Include or Match
  if grep -qE '^\s*Ciphers\s+' /etc/ssh/sshd_config; then
    run_command "sed -i 's|^\s*Ciphers\s\+.*|${CIPHER_LINE}|' /etc/ssh/sshd_config" "5.1.6 Update existing Ciphers directive"
  elif grep -qE '^\s*(Include|Match)\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    run_command "sed -i '${LINE_NUM}i\\${CIPHER_LINE}' /etc/ssh/sshd_config" "5.1.6 Insert Ciphers directive before Include/Match"
  else
    run_command "echo '${CIPHER_LINE}' >> /etc/ssh/sshd_config" "5.1.6 Append Ciphers directive to sshd_config"
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.7: Configure SSHD ClientAlive Settings ]=====================
  start_section "5.1.7"

  # Define desired values
  CLIENT_ALIVE_INTERVAL="ClientAliveInterval 15"
  CLIENT_ALIVE_COUNT="ClientAliveCountMax 3"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.7 Backup sshd_config"

  # Update existing directives if found
  run_command "sed -i 's|^\s*ClientAliveInterval\s\+.*|${CLIENT_ALIVE_INTERVAL}|' /etc/ssh/sshd_config" "5.1.7 Set ClientAliveInterval"
  run_command "sed -i 's|^\s*ClientAliveCountMax\s\+.*|${CLIENT_ALIVE_COUNT}|' /etc/ssh/sshd_config" "5.1.7 Set ClientAliveCountMax"

  # Insert directives before first Include or Match if not present
  if ! grep -qE '^\s*ClientAliveInterval\b' /etc/ssh/sshd_config || ! grep -qE '^\s*ClientAliveCountMax\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${CLIENT_ALIVE_INTERVAL}\\n${CLIENT_ALIVE_COUNT}' /etc/ssh/sshd_config" "5.1.7 Insert ClientAlive settings before Include/Match"
    else
      run_command "echo -e '${CLIENT_ALIVE_INTERVAL}\\n${CLIENT_ALIVE_COUNT}' >> /etc/ssh/sshd_config" "5.1.7 Append ClientAlive settings to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.8: Configure SSHD DisableForwarding ]=====================
  start_section "5.1.8"

  # Define directive
  DISABLE_FORWARDING_LINE="DisableForwarding yes"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.8 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*DisableForwarding\s\+.*|${DISABLE_FORWARDING_LINE}|' /etc/ssh/sshd_config" "5.1.8 Update existing DisableForwarding directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*DisableForwarding\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${DISABLE_FORWARDING_LINE}' /etc/ssh/sshd_config" "5.1.8 Insert DisableForwarding before Include/Match"
    else
      run_command "echo '${DISABLE_FORWARDING_LINE}' >> /etc/ssh/sshd_config" "5.1.8 Append DisableForwarding to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.9: Disable GSSAPIAuthentication ]=====================
  start_section "5.1.9"

  # Define directive
  GSSAPI_LINE="GSSAPIAuthentication no"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.9 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*GSSAPIAuthentication\s\+.*|${GSSAPI_LINE}|' /etc/ssh/sshd_config" "5.1.9 Update existing GSSAPIAuthentication directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*GSSAPIAuthentication\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${GSSAPI_LINE}' /etc/ssh/sshd_config" "5.1.9 Insert GSSAPIAuthentication before Include/Match"
    else
      run_command "echo '${GSSAPI_LINE}' >> /etc/ssh/sshd_config" "5.1.9 Append GSSAPIAuthentication to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.10: Disable HostbasedAuthentication ]=====================
  start_section "5.1.10"

  # Define directive
  HOSTBASED_LINE="HostbasedAuthentication no"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.10 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*HostbasedAuthentication\s\+.*|${HOSTBASED_LINE}|' /etc/ssh/sshd_config" "5.1.10 Update existing HostbasedAuthentication directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*HostbasedAuthentication\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${HOSTBASED_LINE}' /etc/ssh/sshd_config" "5.1.10 Insert HostbasedAuthentication before Include/Match"
    else
      run_command "echo '${HOSTBASED_LINE}' >> /etc/ssh/sshd_config" "5.1.10 Append HostbasedAuthentication to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.11: Enable IgnoreRhosts ]=====================
  start_section "5.1.11"

  # Define directive
  IGNORE_RHOSTS_LINE="IgnoreRhosts yes"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.11 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*IgnoreRhosts\s\+.*|${IGNORE_RHOSTS_LINE}|' /etc/ssh/sshd_config" "5.1.11 Update existing IgnoreRhosts directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*IgnoreRhosts\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${IGNORE_RHOSTS_LINE}' /etc/ssh/sshd_config" "5.1.11 Insert IgnoreRhosts before Include/Match"
    else
      run_command "echo '${IGNORE_RHOSTS_LINE}' >> /etc/ssh/sshd_config" "5.1.11 Append IgnoreRhosts to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes


  # =====================[ SECTION 5.1.12: Configure SSHD KexAlgorithms ]=====================
  start_section "5.1.12"

  # Define the list of weak KexAlgorithms to exclude
  KEX_LINE="KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.12 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*KexAlgorithms\s\+.*|${KEX_LINE}|' /etc/ssh/sshd_config" "5.1.12 Update existing KexAlgorithms directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*KexAlgorithms\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${KEX_LINE}' /etc/ssh/sshd_config" "5.1.12 Insert KexAlgorithms before Include/Match"
    else
      run_command "echo '${KEX_LINE}' >> /etc/ssh/sshd_config" "5.1.12 Append KexAlgorithms to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.13: Configure LoginGraceTime ]=====================
  start_section "5.1.13"

  # Define directive
  LOGIN_GRACE_LINE="LoginGraceTime 60"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.13 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*LoginGraceTime\s\+.*|${LOGIN_GRACE_LINE}|' /etc/ssh/sshd_config" "5.1.13 Update existing LoginGraceTime directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*LoginGraceTime\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${LOGIN_GRACE_LINE}' /etc/ssh/sshd_config" "5.1.13 Insert LoginGraceTime before Include/Match"
    else
      run_command "echo '${LOGIN_GRACE_LINE}' >> /etc/ssh/sshd_config" "5.1.13 Append LoginGraceTime to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.14: Configure SSHD LogLevel ]=====================
  start_section "5.1.14"

  # Define directive (choose VERBOSE or INFO based on site policy)
  LOGLEVEL_LINE="LogLevel VERBOSE"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.14 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*LogLevel\s\+.*|${LOGLEVEL_LINE}|' /etc/ssh/sshd_config" "5.1.14 Update existing LogLevel directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*LogLevel\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${LOGLEVEL_LINE}' /etc/ssh/sshd_config" "5.1.14 Insert LogLevel before Include/Match"
    else
      run_command "echo '${LOGLEVEL_LINE}' >> /etc/ssh/sshd_config" "5.1.14 Append LogLevel to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.15: Configure SSHD MACs ]=====================
  start_section "5.1.15"

  # Define the list of weak MACs to exclude
  MAC_LINE="MACs -hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.15 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*MACs\s\+.*|${MAC_LINE}|' /etc/ssh/sshd_config" "5.1.15 Update existing MACs directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*MACs\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${MAC_LINE}' /etc/ssh/sshd_config" "5.1.15 Insert MACs directive before Include/Match"
    else
      run_command "echo '${MAC_LINE}' >> /etc/ssh/sshd_config" "5.1.15 Append MACs directive to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.16: Configure MaxAuthTries ]=====================
  start_section "5.1.16"

  # Define directive
  MAX_AUTH_TRIES_LINE="MaxAuthTries 4"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.16 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*MaxAuthTries\s\+.*|${MAX_AUTH_TRIES_LINE}|' /etc/ssh/sshd_config" "5.1.16 Update existing MaxAuthTries directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*MaxAuthTries\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${MAX_AUTH_TRIES_LINE}' /etc/ssh/sshd_config" "5.1.16 Insert MaxAuthTries before Include/Match"
    else
      run_command "echo '${MAX_AUTH_TRIES_LINE}' >> /etc/ssh/sshd_config" "5.1.16 Append MaxAuthTries to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.17: Configure MaxSessions ]=====================
  start_section "5.1.17"

  # Define directive
  MAX_SESSIONS_LINE="MaxSessions 10"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.17 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*MaxSessions\s\+.*|${MAX_SESSIONS_LINE}|' /etc/ssh/sshd_config" "5.1.17 Update existing MaxSessions directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*MaxSessions\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${MAX_SESSIONS_LINE}' /etc/ssh/sshd_config" "5.1.17 Insert MaxSessions before Include/Match"
    else
      run_command "echo '${MAX_SESSIONS_LINE}' >> /etc/ssh/sshd_config" "5.1.17 Append MaxSessions to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.18: Configure MaxStartups ]=====================
  start_section "5.1.18"

  # Define directive
  MAX_STARTUPS_LINE="MaxStartups 10:30:60"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.18 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*MaxStartups\s\+.*|${MAX_STARTUPS_LINE}|' /etc/ssh/sshd_config" "5.1.18 Update existing MaxStartups directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*MaxStartups\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${MAX_STARTUPS_LINE}' /etc/ssh/sshd_config" "5.1.18 Insert MaxStartups before Include/Match"
    else
      run_command "echo '${MAX_STARTUPS_LINE}' >> /etc/ssh/sshd_config" "5.1.18 Append MaxStartups to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.19: Disable PermitEmptyPasswords ]=====================
  start_section "5.1.19"

  # Define directive
  EMPTY_PASSWORDS_LINE="PermitEmptyPasswords no"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.19 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*PermitEmptyPasswords\s\+.*|${EMPTY_PASSWORDS_LINE}|' /etc/ssh/sshd_config" "5.1.19 Update existing PermitEmptyPasswords directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*PermitEmptyPasswords\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${EMPTY_PASSWORDS_LINE}' /etc/ssh/sshd_config" "5.1.19 Insert PermitEmptyPasswords before Include/Match"
    else
      run_command "echo '${EMPTY_PASSWORDS_LINE}' >> /etc/ssh/sshd_config" "5.1.19 Append PermitEmptyPasswords to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.20: Disable PermitRootLogin ]=====================
  start_section "5.1.20"

  # Define directive
  PERMIT_ROOT_LINE="PermitRootLogin no"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.20 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*PermitRootLogin\s\+.*|${PERMIT_ROOT_LINE}|' /etc/ssh/sshd_config" "5.1.20 Update existing PermitRootLogin directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*PermitRootLogin\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${PERMIT_ROOT_LINE}' /etc/ssh/sshd_config" "5.1.20 Insert PermitRootLogin before Include/Match"
    else
      run_command "echo '${PERMIT_ROOT_LINE}' >> /etc/ssh/sshd_config" "5.1.20 Append PermitRootLogin to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.21: Disable PermitUserEnvironment ]=====================
  start_section "5.1.21"

  # Define directive
  USER_ENV_LINE="PermitUserEnvironment no"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.21 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*PermitUserEnvironment\s\+.*|${USER_ENV_LINE}|' /etc/ssh/sshd_config" "5.1.21 Update existing PermitUserEnvironment directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*PermitUserEnvironment\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${USER_ENV_LINE}' /etc/ssh/sshd_config" "5.1.21 Insert PermitUserEnvironment before Include/Match"
    else
      run_command "echo '${USER_ENV_LINE}' >> /etc/ssh/sshd_config" "5.1.21 Append PermitUserEnvironment to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes

  # =====================[ SECTION 5.1.22: Enable UsePAM ]=====================
  start_section "5.1.22"

  # Define directive
  USE_PAM_LINE="UsePAM yes"

  # Backup sshd_config
  run_command "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak" "5.1.22 Backup sshd_config"

  # Update existing directive if found
  run_command "sed -i 's|^\s*UsePAM\s\+.*|${USE_PAM_LINE}|' /etc/ssh/sshd_config" "5.1.22 Update existing UsePAM directive"

  # Insert directive before first Include or Match if not present
  if ! grep -qE '^\s*UsePAM\b' /etc/ssh/sshd_config; then
    LINE_NUM=$(grep -nE '^\s*(Include|Match)\b' /etc/ssh/sshd_config | head -n1 | cut -d: -f1)
    if [[ -n "$LINE_NUM" ]]; then
      run_command "sed -i '${LINE_NUM}i\\${USE_PAM_LINE}' /etc/ssh/sshd_config" "5.1.22 Insert UsePAM before Include/Match"
    else
      run_command "echo '${USE_PAM_LINE}' >> /etc/ssh/sshd_config" "5.1.22 Append UsePAM to sshd_config"
    fi
  fi

  # Restart SSH service to apply changes
  run_command "systemctl restart sshd || echo 'WARNING: SSH restart failed — check config manually'" "5.1 Final: Restart SSH service"
fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "5.2" ]]; then
  # =====================[ SECTION 5.2.1: Ensure sudo is installed ]=====================
  start_section "5.2.1"

  # Check for LDAP requirement (customize this logic based on your environment)
  if grep -qi 'ldap' /etc/nsswitch.conf || getent passwd | grep -qi 'ldap'; then
    run_command "apt-get install -y sudo-ldap" "5.2.1 Install sudo-ldap (LDAP detected)"
  else
    run_command "apt-get install -y sudo" "5.2.1 Install sudo"
  fi

  # Verify installation
  if command -v sudo >/dev/null 2>&1; then
    log_message "5.2.1 Success: sudo is installed"
  else
    log_message "5.2.1 Error: sudo installation failed — manual remediation required"
  fi

  # =====================[ SECTION 5.2.2: Ensure sudo commands use PTY ]=====================
  start_section "5.2.2"

  # Create a safe sudoers config fragment
  echo "Defaults use_pty" > /etc/sudoers.d/00-use-pty
  run_command "visudo -cf /etc/sudoers.d/00-use-pty" "5.2.2 Validate sudoers fragment syntax"
  run_command "chmod 440 /etc/sudoers.d/00-use-pty" "5.2.2 Set correct permissions on sudoers fragment"

  # Remove any '!use_pty' entries from /etc/sudoers and valid sudoers.d files
  run_command "sed -i '/Defaults[[:space:]]*!use_pty/d' /etc/sudoers" "5.2.2 Remove '!use_pty' from /etc/sudoers"

  for file in /etc/sudoers.d/*; do
    if [[ -f \"$file\" && \"$file\" != *~ && \"$file\" != *.* ]]; then
      run_command \"sed -i '/Defaults[[:space:]]*!use_pty/d' \"$file\"\" \"5.2.2 Remove '!use_pty' from $file\"
    fi
  done

  log_message "5.2.2 Success: sudo is configured to use PTY for all commands"

  # =====================[ SECTION 5.2.3: Ensure sudo log file exists ]=====================
  start_section "5.2.3"

  # Create sudoers fragment to enable logging
  echo 'Defaults logfile="/var/log/sudo.log"' > /etc/sudoers.d/00-sudo-log
  run_command "visudo -cf /etc/sudoers.d/00-sudo-log" "5.2.3 Validate sudoers logging fragment"
  run_command "chmod 440 /etc/sudoers.d/00-sudo-log" "5.2.3 Set correct permissions on sudoers logging fragment"
  run_command "chown root:root /etc/sudoers.d/00-sudo-log" "5.2.3 Set ownership on sudoers logging fragment"

  # Ensure log file exists and is writable
  run_command "touch /var/log/sudo.log" "5.2.3 Create sudo log file if missing"
  run_command "chmod 600 /var/log/sudo.log" "5.2.3 Set sudo log file permissions"
  run_command "chown root:root /var/log/sudo.log" "5.2.3 Set sudo log file ownership"

  log_message "5.2.3 Success: sudo logging is configured to /var/log/sudo.log"

  # =====================[ SECTION 5.2.4: Ensure sudo requires password ]=====================
  start_section "5.2.4"

  # Remove NOPASSWD entries from /etc/sudoers
  run_command "sed -i '/NOPASSWD/d' /etc/sudoers" "5.2.4 Remove NOPASSWD from /etc/sudoers"

  # Remove NOPASSWD entries from valid sudoers.d files
  for file in /etc/sudoers.d/*; do
    if [[ -f \"$file\" && \"$file\" != *~ && \"$file\" != *.* ]]; then
      run_command \"sed -i '/NOPASSWD/d' \"$file\"\" \"5.2.4 Remove NOPASSWD from $file\"
      run_command \"visudo -cf \"$file\"\" \"5.2.4 Validate syntax of $file\"
    fi
  done

  log_message "5.2.4 Success: All NOPASSWD entries removed — sudo now requires password for escalation"

  # =====================[ SECTION 5.2.5: Ensure sudo re-authentication is not disabled ]=====================
  start_section "5.2.5"

  # Remove !authenticate from /etc/sudoers
  run_command "sed -i '/Defaults[[:space:]]*!authenticate/d' /etc/sudoers" "5.2.5 Remove '!authenticate' from /etc/sudoers"

  # Remove !authenticate from valid sudoers.d files
  for file in /etc/sudoers.d/*; do
    if [[ -f \"$file\" && \"$file\" != *~ && \"$file\" != *.* ]]; then
      run_command \"sed -i '/Defaults[[:space:]]*!authenticate/d' \"$file\"\" \"5.2.5 Remove '!authenticate' from $file\"
      run_command \"visudo -cf \"$file\"\" \"5.2.5 Validate syntax of $file\"
    fi
  done

  log_message "5.2.5 Success: All '!authenticate' entries removed — sudo now requires re-authentication"

  # =====================[ SECTION 5.2.6: Ensure sudo authentication timeout is configured correctly ]=====================
  start_section "5.2.6"

  # Create or update sudoers fragment with correct timeout
  echo 'Defaults timestamp_timeout=15' > /etc/sudoers.d/00-timeout
  run_command "visudo -cf /etc/sudoers.d/00-timeout" "5.2.6 Validate sudoers timeout fragment"
  run_command "chmod 440 /etc/sudoers.d/00-timeout" "5.2.6 Set correct permissions on timeout fragment"
  run_command "chown root:root /etc/sudoers.d/00-timeout" "5.2.6 Set ownership on timeout fragment"

  # Remove or correct any existing timeout values >15 in /etc/sudoers
  run_command "sed -i -E '/timestamp_timeout=[0-9]+/s/timestamp_timeout=[0-9]+/timestamp_timeout=15/' /etc/sudoers" "5.2.6 Enforce timeout in /etc/sudoers"

  # Scan and fix valid sudoers.d files
  for file in /etc/sudoers.d/*; do
    if [[ -f \"$file\" && \"$file\" != *~ && \"$file\" != *.* ]]; then
      run_command \"sed -i -E '/timestamp_timeout=[0-9]+/s/timestamp_timeout=[0-9]+/timestamp_timeout=15/' \"$file\"\" \"5.2.6 Enforce timeout in $file\"
      run_command \"visudo -cf \"$file\"\" \"5.2.6 Validate syntax of $file\"
    fi
  done

  log_message "5.2.6 Success: sudo timeout configured to 15 minutes or less"

  # =====================[ SECTION 5.2.7: Restrict access to the su command ]=====================
  start_section "5.2.7"

  # Create the sugroup if it doesn't exist
  if ! getent group sugroup >/dev/null; then
    run_command "groupadd sugroup" "5.2.7 Create 'sugroup' for su access restriction"
  else
    log_message "5.2.7 Group 'sugroup' already exists"
  fi

  # Add PAM restriction to /etc/pam.d/su if not already present
  PAM_LINE="auth required pam_wheel.so use_uid group=sugroup"
  if ! grep -Fxq "$PAM_LINE" /etc/pam.d/su; then
    echo "$PAM_LINE" >> /etc/pam.d/su
    log_message "5.2.7 PAM configuration updated to restrict su access to 'sugroup'"
  else
    log_message "5.2.7 PAM configuration already restricts su access to 'sugroup'"
  fi

  # Reminder to add authorized users to sugroup
  log_message "5.2.7 Manual step: Add authorized users to 'sugroup' to allow su access"
fi

###############################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "5.3" ]]; then
  # =====================[ SECTION 5.3.1.1: Ensure latest version of PAM is installed ]=====================
  start_section "5.3.1.1"

  # Install or reinstall essential PAM packages using apt
  apt update
  apt install --reinstall -y \
    libpam0g \
    libpam-modules \
    libpam-modules-bin \
    libpam-runtime \
    libpam-pwquality \
    libpam-tmpdir \
    libpam-fprintd

  # Reconfigure PAM profiles to apply changes
  pam-auth-update --force

  # =====================[ PAM Functionality Test: Validate passwd works ]=====================
  useradd -m testuser_5311
  echo "testuser_5311:TempPass123!" | chpasswd

  echo -e "TempPass123!\nNewPass123!\nNewPass123!" | passwd testuser_5311 > /tmp/passwd_test.log 2>&1
  EXIT_CODE=$?

  if [[ $EXIT_CODE -eq 0 ]]; then
    log_message "5.3.1.1 [✓] Password change test passed for testuser_5311"
  else
    log_message "5.3.1.1 [✗] Password change test failed — check /tmp/passwd_test.log and PAM configuration"
    ls -l /etc/shadow >> /tmp/passwd_test.log
    stat /etc/shadow >> /tmp/passwd_test.log
  fi



  # =====================[ SECTION 5.3.1.2: Ensure libpam-modules is installed ]=====================
  start_section "5.3.1.2"
  
  # Check if libpam-modules is installed
  if dpkg -s libpam-modules >/dev/null 2>&1; then
    # Try to upgrade libpam-modules safely
    timeout 60 apt-get install --only-upgrade -y libpam-modules > /tmp/pam_modules_upgrade.log 2>&1
    EXIT_CODE=$?
  
    if [[ $EXIT_CODE -eq 124 ]]; then
      log_message "5.3.1.2 [✗] Timeout: libpam-modules upgrade took too long"
    elif grep -qiE "could not resolve|failed to fetch|temporary failure|connection timed out" /tmp/pam_modules_upgrade.log; then
      log_message "5.3.1.2 [✗] Network error: Unable to reach repositories — upgrade failed"
    elif [[ $EXIT_CODE -ne 0 ]]; then
      log_message "5.3.1.2 [✗] Error: libpam-modules upgrade failed with exit code $EXIT_CODE"
    else
      log_message "5.3.1.2 [✓] Success: libpam-modules upgraded"
    fi
    log_message "5.3.1.2 Log saved to /tmp/pam_modules_upgrade.log"
  else
    log_message "5.3.1.2 [ℹ] libpam-modules is not installed — skipping upgrade"
  fi

  # =====================[ SECTION 5.3.1.3: Ensure libpam-pwquality is installed ]=====================
  start_section "5.3.1.3"
  
  # Check if libpam-pwquality is installed
  if dpkg -s libpam-pwquality >/dev/null 2>&1; then
    log_message "5.3.1.3 [✓] libpam-pwquality is already installed"
  else
    # Attempt installation
    timeout 60 apt-get install -y libpam-pwquality > /tmp/pwquality_install.log 2>&1
    EXIT_CODE=$?
  
    if [[ $EXIT_CODE -eq 124 ]]; then
      log_message "5.3.1.3 [✗] Timeout: libpam-pwquality installation took too long"
    elif grep -qiE "could not resolve|failed to fetch|temporary failure|connection timed out" /tmp/pwquality_install.log; then
      log_message "5.3.1.3 [✗] Network error: Unable to reach repositories — installation failed"
    elif [[ $EXIT_CODE -ne 0 ]]; then
      log_message "5.3.1.3 [✗] Error: libpam-pwquality installation failed with exit code $EXIT_CODE"
    else
      log_message "5.3.1.3 [✓] Success: libpam-pwquality installed"
    fi
    log_message "5.3.1.3 Log saved to /tmp/pwquality_install.log"
  fi


  # =====================[ SECTION 5.3.2.1: Ensure pam_unix module is enabled ]=====================
  start_section "5.3.2.1"
  
  # Enable pam_unix module using pam-auth-update
  timeout 30 pam-auth-update --enable unix > /tmp/pam_unix_enable.log 2>&1
  EXIT_CODE=$?
  
  if [[ $EXIT_CODE -eq 124 ]]; then
    log_message "5.3.2.1 [✗] Timeout: pam-auth-update took too long"
  elif grep -qiE "error|failed|not found" /tmp/pam_unix_enable.log; then
    log_message "5.3.2.1 [✗] Error: Failed to enable pam_unix — check for custom PAM profiles or missing package"
  elif [[ $EXIT_CODE -ne 0 ]]; then
    log_message "5.3.2.1 [✗] Error: pam-auth-update exited with code $EXIT_CODE"
  else
    log_message "5.3.2.1 [✓] Success: pam_unix module enabled"
  fi
  log_message "5.3.2.1 Log saved to /tmp/pam_unix_enable.log"
  
  # Optional: notify if pam_faillock is used instead
  if grep -q "pam_faillock.so" /etc/pam.d/common-auth 2>/dev/null; then
    log_message "5.3.2.1 [ℹ] Note: pam_faillock module is present — ensure it aligns with site policy"
  fi

  # =====================[ SECTION 5.3.2.2: Ensure pam_faillock module is enabled ]=====================
  start_section "5.3.2.2"

  # Create faillock profile
  cat <<EOF > /usr/share/pam-configs/faillock
Name: Enable pam_faillock to deny access
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
 [default=die] pam_faillock.so authfail
EOF

  # Create faillock_notify profile
  cat <<EOF > /usr/share/pam-configs/faillock_notify
Name: Notify of failed login attempts and reset count upon success
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
 requisite pam_faillock.so preauth
Account-Type: Primary
Account:
 required pam_faillock.so
EOF

  # Enable both profiles
  timeout 30 pam-auth-update --enable faillock --enable faillock_notify > /tmp/faillock_enable.log 2>&1
  EXIT_CODE=$?

  if [[ $EXIT_CODE -eq 124 ]]; then
    log_message "5.3.2.2 [✗] Timeout: pam-auth-update took too long"
  elif grep -qiE "error|failed|not found" /tmp/faillock_enable.log; then
    log_message "5.3.2.2 [✗] Error: Failed to enable pam_faillock profiles — check for syntax or package issues"
  elif [[ $EXIT_CODE -ne 0 ]]; then
    log_message "5.3.2.2 [✗] Error: pam-auth-update exited with code $EXIT_CODE"
  else
    log_message "5.3.2.2 [✓] Success: pam_faillock module and notification profile enabled"
  fi
  log_message "5.3.2.2 Log saved to /tmp/faillock_enable.log"


  # =====================[ SECTION 5.3.2.3: Ensure pam_pwquality module is enabled ]=====================
  start_section "5.3.2.3"

  # Check if pam_pwquality profile exists
  if grep -P --quiet '\bpam_pwquality\.so\b' /usr/share/pam-configs/*; then
    log_message "5.3.2.3 [ℹ] pam_pwquality profile already exists — enabling it"
  else
    # Create pam_pwquality profile
    cat <<EOF > /usr/share/pam-configs/pwquality
Name: Pwquality password strength checking
Default: yes
Priority: 1024
Conflicts: cracklib
Password-Type: Primary
Password:
 requisite pam_pwquality.so retry=3
EOF
    log_message "5.3.2.3 [✓] Created pam_pwquality profile"
  fi

  # Enable the profile
  timeout 30 pam-auth-update --enable pwquality > /tmp/pwquality_enable.log 2>&1
  EXIT_CODE=$?

  if [[ $EXIT_CODE -eq 124 ]]; then
    log_message "5.3.2.3 [✗] Timeout: pam-auth-update took too long"
  elif grep -qiE "error|failed|not found" /tmp/pwquality_enable.log; then
    log_message "5.3.2.3 [✗] Error: Failed to enable pam_pwquality — check for syntax or package issues"
  elif [[ $EXIT_CODE -ne 0 ]]; then
    log_message "5.3.2.3 [✗] Error: pam-auth-update exited with code $EXIT_CODE"
  else
    log_message "5.3.2.3 [✓] Success: pam_pwquality module enabled"
  fi
  log_message "5.3.2.3 Log saved to /tmp/pwquality_enable.log"


  # =====================[ SECTION 5.3.2.4: Ensure pam_pwhistory module is enabled ]=====================
  start_section "5.3.2.4"

  # Check if pam_pwhistory profile exists
  if grep -P --quiet '\bpam_pwhistory\.so\b' /usr/share/pam-configs/*; then
    log_message "5.3.2.4 [ℹ] pam_pwhistory profile already exists — enabling it"
  else
    # Create pam_pwhistory profile
    cat <<EOF > /usr/share/pam-configs/pwhistory
Name: pwhistory password history checking
Default: yes
Priority: 1024
Password-Type: Primary
Password:
 requisite pam_pwhistory.so remember=24 enforce_for_root try_first_pass use_authtok
EOF
    log_message "5.3.2.4 [✓] Created pam_pwhistory profile"
  fi

  # Enable the profile
  timeout 30 pam-auth-update --enable pwhistory > /tmp/pwhistory_enable.log 2>&1
  EXIT_CODE=$?

  if [[ $EXIT_CODE -eq 124 ]]; then
    log_message "5.3.2.4 [✗] Timeout: pam-auth-update took too long"
  elif grep -qiE "error|failed|not found" /tmp/pwhistory_enable.log; then
    log_message "5.3.2.4 [✗] Error: Failed to enable pam_pwhistory — check for syntax or package issues"
  elif [[ $EXIT_CODE -ne 0 ]]; then
    log_message "5.3.2.4 [✗] Error: pam-auth-update exited with code $EXIT_CODE"
  else
    log_message "5.3.2.4 [✓] Success: pam_pwhistory module enabled"
  fi
  log_message "5.3.2.4 Log saved to /tmp/pwhistory_enable.log"


  # =====================[ SECTION 5.3.3.1.1: Ensure password failed attempts lockout is configured ]=====================
  start_section "5.3.3.1.1"
  
  # Ensure faillock.conf exists and sets deny=5
  if [[ -f /etc/security/faillock.conf ]]; then
    if grep -q '^deny[[:space:]]*=' /etc/security/faillock.conf; then
      run_command "sed -i 's/^deny[[:space:]]*=.*/deny = 5/' /etc/security/faillock.conf" "5.3.3.1.1 [✓] Update deny value in faillock.conf"
    else
      echo "deny = 5" >> /etc/security/faillock.conf
      log_message "5.3.3.1.1 [✓] Added deny = 5 to faillock.conf"
    fi
  else
    echo "deny = 5" > /etc/security/faillock.conf
    log_message "5.3.3.1.1 [✓] Created faillock.conf with deny = 5"
  fi
  
  # Remove embedded deny= from pam_faillock.so lines in PAM profiles
  grep -Pl -- '\bpam_faillock\.so\h+([^#\n\r]+\h+)?deny\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    run_command "sed -i -E 's/(pam_faillock\.so[^#\n\r]*)\s+deny=[0-9]+/\1/' \"$file\"" "5.3.3.1.1 [✓] Remove deny= from $file"
  done
  
  log_message "5.3.3.1.1 [✓] Success: Password lockout configured via faillock.conf with deny = 5"


  # =====================[ SECTION 5.3.3.1.2: Ensure password unlock time is configured ]=====================
  start_section "5.3.3.1.2"
  
  # Ensure unlock_time = 900 is set in /etc/security/faillock.conf
  if [[ -f /etc/security/faillock.conf ]]; then
    if grep -q '^\s*unlock_time\s*=' /etc/security/faillock.conf; then
      run_command "sed -i 's/^\s*unlock_time\s*=.*/unlock_time = 900/' /etc/security/faillock.conf" "5.3.3.1.2 [✓] Updated unlock_time value in faillock.conf"
    else
      echo "unlock_time = 900" >> /etc/security/faillock.conf
      log_message "5.3.3.1.2 [✓] Appended unlock_time = 900 to faillock.conf"
    fi
  else
    echo "unlock_time = 900" > /etc/security/faillock.conf
    log_message "5.3.3.1.2 [✓] Created faillock.conf with unlock_time = 900"
  fi
  
  # Remove unlock_time=<N> from pam_faillock.so lines in PAM profiles
  grep -Pl -- '\bpam_faillock\.so\h+([^#\n\r]+\h+)?unlock_time\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    run_command "sed -i -E 's/(pam_faillock\.so[^#\n\r]*)\s+unlock_time=[0-9]+/\1/' \"$file\"" "5.3.3.1.2 [✓] Removed unlock_time= from $file"
  done
  
  log_message "5.3.3.1.2 [✓] Success: Unlock time set to 900 seconds and PAM profiles cleaned"
  

  # =====================[ SECTION 5.3.3.1.3: Ensure lockout includes root account ]=====================
  start_section "5.3.3.1.3"
  
  # Ensure even_deny_root is set in faillock.conf
  if [[ -f /etc/security/faillock.conf ]]; then
    if ! grep -q '^\s*even_deny_root\b' /etc/security/faillock.conf; then
      echo "even_deny_root" >> /etc/security/faillock.conf
      log_message "5.3.3.1.3 [✓] Added even_deny_root to faillock.conf"
    else
      log_message "5.3.3.1.3 [ℹ] even_deny_root already present in faillock.conf"
    fi
  
    # Ensure root_unlock_time is 60 or more
    if grep -q '^\s*root_unlock_time\s*=' /etc/security/faillock.conf; then
      run_command "sed -i 's/^\s*root_unlock_time\s*=.*/root_unlock_time = 60/' /etc/security/faillock.conf" "5.3.3.1.3 [✓] Updated root_unlock_time to 60"
    else
      echo "root_unlock_time = 60" >> /etc/security/faillock.conf
      log_message "5.3.3.1.3 [✓] Appended root_unlock_time = 60 to faillock.conf"
    fi
  else
    echo -e "even_deny_root\nroot_unlock_time = 60" > /etc/security/faillock.conf
    log_message "5.3.3.1.3 [✓] Created faillock.conf with even_deny_root and root_unlock_time = 60"
  fi
  
  # Remove even_deny_root and root_unlock_time from PAM profile lines
  grep -Pl -- '\bpam_faillock\.so\h+([^#\n\r]+\h+)?(even_deny_root|root_unlock_time)' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    run_command "sed -i -E 's/(pam_faillock\.so[^#\n\r]*)\s+(even_deny_root|root_unlock_time=[0-9]+)//g' \"$file\"" "5.3.3.1.3 [✓] Cleaned $file of root-specific faillock options"
  done
  
  log_message "5.3.3.1.3 [✓] Success: Root account now included in lockout policy"


  # =====================[ SECTION 5.3.3.2.1: Ensure password number of changed characters is configured ]=====================
  start_section "5.3.3.2.1"
  
  # Comment out existing difok line in pwquality.conf
  if [[ -f /etc/security/pwquality.conf ]]; then
    run_command "sed -ri 's/^\\s*difok\\s*=.*/# &/' /etc/security/pwquality.conf" "5.3.3.2.1 [✓] Commented out difok in pwquality.conf"
  fi
  
  # Create pwquality.conf.d directory if missing
  if [[ ! -d /etc/security/pwquality.conf.d/ ]]; then
    run_command "mkdir -p /etc/security/pwquality.conf.d/" "5.3.3.2.1 [✓] Created pwquality.conf.d directory"
  fi
  
  # Create or overwrite difok setting in custom conf file
  echo "difok = 2" > /etc/security/pwquality.conf.d/50-pwdifok.conf
  log_message "5.3.3.2.1 [✓] Set difok = 2 in 50-pwdifok.conf"
  
  # Remove difok= from pam_pwquality.so lines in PAM profiles
  grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?difok\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    run_command "sed -i -E 's/(pam_pwquality\.so[^#\n\r]*)\\s+difok=[0-9]+/\\1/' \"$file\"" "5.3.3.2.1 [✓] Removed difok= from $file"
  done
  
  log_message "5.3.3.2.1 [✓] Success: Password change character requirement (difok) configured to 2"

  # =====================[ SECTION 5.3.3.2.2: Ensure minimum password length is configured ]=====================
  start_section "5.3.3.2.2"
  
  # Comment out existing minlen line in pwquality.conf
  if [[ -f /etc/security/pwquality.conf ]]; then
    run_command "sed -ri 's/^\\s*minlen\\s*=.*/# &/' /etc/security/pwquality.conf" "5.3.3.2.2 [✓] Commented out minlen in pwquality.conf"
  fi
  
  # Create pwquality.conf.d directory if missing
  if [[ ! -d /etc/security/pwquality.conf.d/ ]]; then
    run_command "mkdir -p /etc/security/pwquality.conf.d/" "5.3.3.2.2 [✓] Created pwquality.conf.d directory"
  fi
  
  # Create or overwrite minlen setting in custom conf file
  echo "minlen = 14" > /etc/security/pwquality.conf.d/50-pwlength.conf
  log_message "5.3.3.2.2 [✓] Set minlen = 14 in 50-pwlength.conf"
  
  # Remove minlen= from pam_pwquality.so lines in PAM profiles
  grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?minlen\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    run_command "sed -i -E 's/(pam_pwquality\.so[^#\n\r]*)\\s+minlen=[0-9]+/\\1/' \"$file\"" "5.3.3.2.2 [✓] Removed minlen= from $file"
  done
  
  log_message "5.3.3.2.2 [✓] Success: Minimum password length configured to 14 characters"
  

  # =====================[ SECTION 5.3.3.2.3: Ensure password complexity is configured ]=====================
  start_section "5.3.3.2.3"

  # Comment out complexity settings in pwquality.conf
  if [[ -f /etc/security/pwquality.conf ]]; then
    run_command "sed -ri 's/^\\s*minclass\\s*=.*/# &/' /etc/security/pwquality.conf" "5.3.3.2.3 [✓] Commented out minclass in pwquality.conf"
    run_command "sed -ri 's/^\\s*[dulo]credit\\s*=.*/# &/' /etc/security/pwquality.conf" "5.3.3.2.3 [✓] Commented out credit settings in pwquality.conf"
  fi

  # Create pwquality.conf.d directory if missing
  if [[ ! -d /etc/security/pwquality.conf.d/ ]]; then
    run_command "mkdir -p /etc/security/pwquality.conf.d/" "5.3.3.2.3 [✓] Created pwquality.conf.d directory"
  fi

  # Create or overwrite complexity settings in custom conf file
  cat <<EOF > /etc/security/pwquality.conf.d/50-pwcomplexity.conf
minclass = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
  log_message "5.3.3.2.3 [✓] Set password complexity in 50-pwcomplexity.conf"

  # Remove complexity arguments from pam_pwquality.so lines in PAM profiles
  grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?(minclass|[dulo]credit|ocredit)\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    run_command "sed -i -E 's/(pam_pwquality\.so[^#\n\r]*)\\s+(minclass=[0-9]+|[dulo]credit=-?[0-9]+|ocredit=-?[0-9]+)//g' \"$file\"" "5.3.3.2.3 [✓] Removed complexity arguments from $file"
  done

  log_message "5.3.3.2.3 [✓] Success: Password complexity configured according to site policy"


  # =====================[ SECTION 5.3.3.2.4: Ensure password same consecutive characters is configured ]=====================
  start_section "5.3.3.2.4"
  
  # Comment out existing maxrepeat line in pwquality.conf
  if [[ -f /etc/security/pwquality.conf ]]; then
    run_command "sed -ri 's/^\\s*maxrepeat\\s*=.*/# &/' /etc/security/pwquality.conf" "5.3.3.2.4 [✓] Commented out maxrepeat in pwquality.conf"
  fi
  
  # Create pwquality.conf.d directory if missing
  if [[ ! -d /etc/security/pwquality.conf.d/ ]]; then
    run_command "mkdir -p /etc/security/pwquality.conf.d/" "5.3.3.2.4 [✓] Created pwquality.conf.d directory"
  fi
  
  # Create or overwrite maxrepeat setting in custom conf file
  echo "maxrepeat = 3" > /etc/security/pwquality.conf.d/50-pwrepeat.conf
  log_message "5.3.3.2.4 [✓] Set maxrepeat = 3 in 50-pwrepeat.conf"
  
  # Remove maxrepeat= from pam_pwquality.so lines in PAM profiles
  grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?maxrepeat\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    run_command "sed -i -E 's/(pam_pwquality\.so[^#\n\r]*)\\s+maxrepeat=[0-9]+/\\1/' \"$file\"" "5.3.3.2.4 [✓] Removed maxrepeat= from $file"
  done
  
  log_message "5.3.3.2.4 [✓] Success: Password consecutive character limit (maxrepeat) configured to 3"


  # =====================[ SECTION 5.3.3.2.5: Ensure password maximum sequential characters is configured ]=====================
  start_section "5.3.3.2.5"

  # Comment out existing maxsequence line in pwquality.conf
  if [[ -f /etc/security/pwquality.conf ]]; then
    run_command "sed -ri 's/^\\s*maxsequence\\s*=.*/# &/' /etc/security/pwquality.conf" "5.3.3.2.5 Comment out maxsequence in pwquality.conf"
  fi

  # Create pwquality.conf.d directory if missing
  if [[ ! -d /etc/security/pwquality.conf.d/ ]]; then
    run_command "mkdir -p /etc/security/pwquality.conf.d/" "5.3.3.2.5 Create pwquality.conf.d directory"
  fi

  # Create or overwrite maxsequence setting in custom conf file
  echo "maxsequence = 3" > /etc/security/pwquality.conf.d/50-pwmaxsequence.conf
  log_message "5.3.3.2.5 Set maxsequence = 3 in 50-pwmaxsequence.conf"

  # Remove maxsequence= from pam_pwquality.so lines in PAM profiles
  grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?maxsequence\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    run_command "sed -i -E 's/(pam_pwquality\.so[^#\n\r]*)\\s+maxsequence=[0-9]+/\\1/' \"$file\"" "5.3.3.2.5 Remove maxsequence= from $file"
  done

  log_message "5.3.3.2.5 Success: Password sequential character limit (maxsequence) configured to 3"

  # =====================[ SECTION 5.3.3.2.6: Ensure password dictionary check is enabled ]=====================
  start_section "5.3.3.2.6"
  
  # Comment out dictcheck = 0 in pwquality.conf
  if [[ -f /etc/security/pwquality.conf ]]; then
    run_command "sed -ri 's/^\\s*dictcheck\\s*=\\s*0/# &/' /etc/security/pwquality.conf" "5.3.3.2.6 [✓] Commented out dictcheck = 0 in pwquality.conf"
  fi
  
  # Comment out dictcheck = 0 in all pwquality.conf.d/*.conf files
  find /etc/security/pwquality.conf.d/ -type f -name '*.conf' 2>/dev/null | while read -r conf_file; do
    run_command "sed -ri 's/^\\s*dictcheck\\s*=\\s*0/# &/' \"$conf_file\"" "5.3.3.2.6 [✓] Commented out dictcheck = 0 in $conf_file"
  done
  
  # Remove dictcheck= from pam_pwquality.so lines in PAM profiles
  grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?dictcheck\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    run_command "sed -i -E 's/(pam_pwquality\.so[^#\n\r]*)\\s+dictcheck=[0-9]+/\\1/' \"$file\"" "5.3.3.2.6 [✓] Removed dictcheck= from $file"
  done
  
  log_message "5.3.3.2.6 [✓] Success: Dictionary check enabled for password quality"


  # =====================[ SECTION 5.3.3.2.7: Ensure password quality checking is enforced ]=====================
  start_section "5.3.3.2.7"
  
  # Comment out enforcing = 0 in pwquality.conf
  if [[ -f /etc/security/pwquality.conf ]]; then
    run_command "sed -ri 's/^\\s*enforcing\\s*=\\s*0/# &/' /etc/security/pwquality.conf" "5.3.3.2.7 [✓] Commented out enforcing = 0 in pwquality.conf"
  fi
  
  # Comment out enforcing = 0 in all pwquality.conf.d/*.conf files
  find /etc/security/pwquality.conf.d/ -type f -name '*.conf' 2>/dev/null | while read -r conf_file; do
    run_command "sed -ri 's/^\\s*enforcing\\s*=\\s*0/# &/' \"$conf_file\"" "5.3.3.2.7 [✓] Commented out enforcing = 0 in $conf_file"
  done
  
  # Remove enforcing=0 from pam_pwquality.so lines in PAM profiles
  grep -Pl -- '\bpam_pwquality\.so\h+([^#\n\r]+\h+)?enforcing=0\b' /usr/share/pam-configs/* 2>/dev/null | while read -r file; do
    run_command "sed -i -E 's/(pam_pwquality\.so[^#\n\r]*)\\s+enforcing=0/\\1/' \"$file\"" "5.3.3.2.7 [✓] Removed enforcing=0 from $file"
  done
  
  log_message "5.3.3.2.7 [✓] Success: Password quality enforcement enabled"


  # =====================[ SECTION 5.3.3.2.8: Ensure password quality is enforced for root user ]=====================
  start_section "5.3.3.2.8"
  
  # Create pwquality.conf.d directory if missing
  if [[ ! -d /etc/security/pwquality.conf.d/ ]]; then
    run_command "mkdir -p /etc/security/pwquality.conf.d/" "5.3.3.2.8 [✓] Created pwquality.conf.d directory"
  fi
  
  # Create or overwrite enforce_for_root setting in custom conf file
  echo "enforce_for_root" > /etc/security/pwquality.conf.d/50-pwroot.conf
  log_message "5.3.3.2.8 [✓] Set enforce_for_root in 50-pwroot.conf"
  
  log_message "5.3.3.2.8 [✓] Success: Password quality enforcement enabled for root user"



  # =====================[ SECTION 5.3.3.3.1: Ensure password history is configured ]=====================
  start_section "5.3.3.3.1"
  
  # Identify PAM profiles using pam_pwhistory.so in Password section
  awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_pwhistory\.so/) print FILENAME}' /usr/share/pam-configs/* 2>/dev/null | sort -u | while read -r file; do
    # Ensure remember=24 is present
    if grep -q 'pam_pwhistory\.so' "$file"; then
      if grep -q 'pam_pwhistory\.so.*remember=' "$file"; then
        run_command "sed -i -E 's/(pam_pwhistory\.so[^#\n\r]*)remember=[0-9]+/\1remember=24/' \"$file\"" "5.3.3.3.1 [✓] Updated remember=24 in $file"
      else
        run_command "sed -i -E 's/(pam_pwhistory\.so[^#\n\r]*)/\1 remember=24/' \"$file\"" "5.3.3.3.1 [✓] Added remember=24 to $file"
      fi
  
      # Extract profile name from file name
      PROFILE_NAME=$(basename "$file")
      run_command "pam-auth-update --enable \"$PROFILE_NAME\"" "5.3.3.3.1 [✓] Re-enabled PAM profile $PROFILE_NAME"
    fi
  done
  
  log_message "5.3.3.3.1 [✓] Success: Password history configured with remember=24"

  # =====================[ SECTION 5.3.3.3.2: Ensure password history is enforced for root user ]=====================
  start_section "5.3.3.3.2"
  
  # Identify PAM profiles using pam_pwhistory.so in Password section
  awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_pwhistory\.so/) print FILENAME}' /usr/share/pam-configs/* 2>/dev/null | sort -u | while read -r file; do
    # Ensure enforce_for_root is present
    if grep -q 'pam_pwhistory\.so' "$file"; then
      if grep -q 'pam_pwhistory\.so.*enforce_for_root' "$file"; then
        log_message "5.3.3.3.2 [ℹ] enforce_for_root already present in $file"
      else
        run_command "sed -i -E 's/(pam_pwhistory\.so[^#\n\r]*)/\1 enforce_for_root/' \"$file\"" "5.3.3.3.2 [✓] Added enforce_for_root to $file"
      fi
  
      # Extract profile name from file name
      PROFILE_NAME=$(basename "$file")
      run_command "pam-auth-update --enable \"$PROFILE_NAME\"" "5.3.3.3.2 [✓] Re-enabled PAM profile $PROFILE_NAME"
    fi
  done
  
  log_message "5.3.3.3.2 [✓] Success: Password history enforcement enabled for root user"


  # =====================[ SECTION 5.3.3.3.3: Ensure pam_pwhistory includes use_authtok ]=====================
  start_section "5.3.3.3.3"
  
  # Identify PAM profiles using pam_pwhistory.so in Password section
  awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_pwhistory\.so/) print FILENAME}' /usr/share/pam-configs/* 2>/dev/null | sort -u | while read -r file; do
    # Ensure use_authtok is present
    if grep -q 'pam_pwhistory\.so' "$file"; then
      if grep -q 'pam_pwhistory\.so.*use_authtok' "$file"; then
        log_message "5.3.3.3.3 [ℹ] use_authtok already present in $file"
      else
        run_command "sed -i -E 's/(pam_pwhistory\.so[^#\n\r]*)/\1 use_authtok/' \"$file\"" "5.3.3.3.3 [✓] Added use_authtok to $file"
      fi
  
      # Extract profile name from file name
      PROFILE_NAME=$(basename "$file")
      run_command "pam-auth-update --enable \"$PROFILE_NAME\"" "5.3.3.3.3 [✓] Re-enabled PAM profile $PROFILE_NAME"
    fi
  done
  
  log_message "5.3.3.3.3 [✓] Success: pam_pwhistory includes use_authtok"


  # =====================[ SECTION 5.3.3.4.1: Ensure pam_unix does not include nullok ]=====================
  start_section "5.3.3.4.1"
  
  # Find PAM profiles with pam_unix.so containing nullok
  grep -PH -- '^\h*([^#\n\r]+\h+)?pam_unix\.so\h+([^#\n\r]+\h+)?nullok\b' /usr/share/pam-configs/* 2>/dev/null | cut -d: -f1 | sort -u | while read -r file; do
    # Remove nullok from pam_unix.so lines
    run_command "sed -i -E 's/(pam_unix\.so[^#\n\r]*)\\s+nullok/\\1/' \"$file\"" "5.3.3.4.1 [✓] Removed nullok from $file"
  
    # Extract profile name from file name
    PROFILE_NAME=$(basename "$file")
    run_command "pam-auth-update --enable \"$PROFILE_NAME\"" "5.3.3.4.1 [✓] Re-enabled PAM profile $PROFILE_NAME"
  done
  
  log_message "5.3.3.4.1 [✓] Success: nullok removed from pam_unix.so lines"
  

  # =====================[ SECTION 5.3.3.4.2: Ensure pam_unix does not include remember ]=====================
  start_section "5.3.3.4.2"
  
  # Find PAM profiles with pam_unix.so containing remember=
  grep -PH -- '^\h*([^#\n\r]+\h+)?pam_unix\.so\h+([^#\n\r]+\h+)?remember\b' /usr/share/pam-configs/* 2>/dev/null | cut -d: -f1 | sort -u | while read -r file; do
    # Remove remember=<N> from pam_unix.so lines
    run_command "sed -i -E 's/(pam_unix\.so[^#\n\r]*)\\s+remember=[0-9]+/\\1/' \"$file\"" "5.3.3.4.2 [✓] Removed remember= from $file"
  
    # Extract profile name from file name
    PROFILE_NAME=$(basename "$file")
    run_command "pam-auth-update --enable \"$PROFILE_NAME\"" "5.3.3.4.2 [✓] Re-enabled PAM profile $PROFILE_NAME"
  done
  
  log_message "5.3.3.4.2 [✓] Success: remember= removed from pam_unix.so lines"


  # =====================[ SECTION 5.3.3.4.3: Ensure pam_unix includes a strong password hashing algorithm ]=====================
  start_section "5.3.3.4.3"
  
  # Identify PAM profiles using pam_unix.so in Password section
  awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_unix\.so/) print FILENAME}' /usr/share/pam-configs/* 2>/dev/null | sort -u | while read -r file; do
    # Ensure hashing algorithm is present (yescrypt or sha512)
    if grep -q 'pam_unix\.so' "$file"; then
      if grep -Eq 'pam_unix\.so.*(yescrypt|sha512)' "$file"; then
        log_message "5.3.3.4.3 [ℹ] Strong hashing algorithm already present in $file"
      else
        run_command "sed -i -E 's/(pam_unix\.so[^#\n\r]*)/\1 yescrypt/' \"$file\"" "5.3.3.4.3 [✓] Added yescrypt to $file"
      fi
  
      # Extract profile name from file name
      PROFILE_NAME=$(basename "$file")
      run_command "pam-auth-update --enable \"$PROFILE_NAME\"" "5.3.3.4.3 [✓] Re-enabled PAM profile $PROFILE_NAME"
    fi
  done
  
  log_message "5.3.3.4.3 [✓] Success: pam_unix configured with strong password hashing algorithm"
  

  # =====================[ SECTION 5.3.3.4.4: Ensure pam_unix includes use_authtok in Password section only ]=====================
  start_section "5.3.3.4.4"
  
  # Identify PAM profiles using pam_unix.so in Password section
  awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_unix\.so/) print FILENAME}' /usr/share/pam-configs/* 2>/dev/null | sort -u | while read -r file; do
    # Process Password section only
    awk '
      BEGIN { in_password = 0 }
      /^Password-Type:/ { in_password = 1; next }
      /^Password-Initial:/ { in_password = 0 }
      /^-Type:/ { in_password = 0 }
      {
        if (in_password && /pam_unix\.so/ && !/use_authtok/) {
          sub(/pam_unix\.so/, "pam_unix.so use_authtok")
        }
        print
      }
    ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    log_message "5.3.3.4.4 [✓] Updated $file to include use_authtok in Password section"
  
    # Extract profile name from file name
    PROFILE_NAME=$(basename "$file")
    run_command "pam-auth-update --enable \"$PROFILE_NAME\"" "5.3.3.4.4 [✓] Re-enabled PAM profile $PROFILE_NAME"
  done
  
  log_message "5.3.3.4.4 [✓] Success: pam_unix includes use_authtok in Password section only"


  # Install all required PAM modules
  apt update
  apt install --reinstall -y \
    libpam0g \
    libpam-modules \
    libpam-modules-bin \
    libpam-runtime \
    libpam-pwquality \
    libpam-tmpdir \
    libpam-fprintd
  
  # Reconfigure PAM profiles
  pam-auth-update --force
  
  # Confirm pam_unix.so is present
  grep pam_unix.so /etc/pam.d/common-password || echo "Missing pam_unix.so — passwd will fail"
  
  # Now run the password test
  useradd -m testuser_5311
  echo "testuser_5311:TempPass123!" | chpasswd
  echo -e "TempPass123!\nNewPass123!\nNewPass123!" | passwd testuser_5311 > /tmp/passwd_test.log 2>&1

fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "5.4" ]]; then
  # =====================[ SECTION 5.4.1.1: Ensure password expiration is configured ]=====================
  start_section "5.4.1.1"
  
  # Set PASS_MAX_DAYS in /etc/login.defs
  run_command "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs" "5.4.1.1 Set PASS_MAX_DAYS to 365 in login.defs"
  run_command "grep -q '^PASS_MAX_DAYS' /etc/login.defs || echo 'PASS_MAX_DAYS 365' >> /etc/login.defs" "5.4.1.1 Ensure PASS_MAX_DAYS is present in login.defs"
  
  # Update max password age for all users with valid password hashes
  run_command "awk -F: '(\$2~/^\\$.+\\$/) {if(\$5 > 365 || \$5 < 1) system(\"chage --maxdays 365 \" \$1)}' /etc/shadow" "5.4.1.1 Set max password age to 365 for users"
  
  # Set last password change date for users missing it (e.g., root after kickstart)
  run_command 'for user in $(awk -F: '\''($2~/^\$.+\$/) && ($3 == 0 || $1 == "root") {print $1}'\'' /etc/shadow); do chage -d "$(date +%Y-%m-%d)" "$user"; done' "5.4.1.1 Set last password change date for root and UID 0 users"
  
  # =====================[ SECTION 5.4.1.2: Ensure minimum password days is configured ]=====================
  start_section "5.4.1.2"
  
  # Set PASS_MIN_DAYS in /etc/login.defs
  run_command "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs" "5.4.1.2 Set PASS_MIN_DAYS to 1 in login.defs"
  run_command "grep -q '^PASS_MIN_DAYS' /etc/login.defs || echo 'PASS_MIN_DAYS 1' >> /etc/login.defs" "5.4.1.2 Ensure PASS_MIN_DAYS is present in login.defs"
  
  # Modify user parameters for all users with password hashes and mindays < 1
  run_command "awk -F: '(\$2~/^\\$.+\\$/) {if(\$4 < 1) system(\"chage --mindays 1 \" \$1)}' /etc/shadow" "5.4.1.2 Set minimum password age to 1 for all users"
  
  # =====================[ SECTION 5.4.1.3: Ensure password expiration warning days is configured ]=====================
  start_section "5.4.1.3"
  
  # Set PASS_WARN_AGE in /etc/login.defs
  run_command "sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs" "5.4.1.3 Set PASS_WARN_AGE to 7 in login.defs"
  run_command "grep -q '^PASS_WARN_AGE' /etc/login.defs || echo 'PASS_WARN_AGE 7' >> /etc/login.defs" "5.4.1.3 Ensure PASS_WARN_AGE is present in login.defs"
  
  # Modify user parameters for all users with password hashes and warndays < 7
  run_command "awk -F: '(\$2~/^\\$.+\\$/) {if(\$6 < 7) system(\"chage --warndays 7 \" \$1)}' /etc/shadow" "5.4.1.3 Set password expiration warning to 7 days for all users"
  
  # =====================[ SECTION 5.4.1.4: Ensure strong password hashing algorithm is configured ]=====================
  start_section "5.4.1.4"
  
  # Set ENCRYPT_METHOD to YESCRYPT in /etc/login.defs
  run_command "sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs" "5.4.1.4 Set ENCRYPT_METHOD to YESCRYPT in login.defs"
  run_command "grep -q '^ENCRYPT_METHOD' /etc/login.defs || echo 'ENCRYPT_METHOD YESCRYPT' >> /etc/login.defs" "5.4.1.4 Ensure ENCRYPT_METHOD is present in login.defs"
  
  # =====================[ SECTION 5.4.1.5: Ensure inactive password lock is configured ]=====================
  start_section "5.4.1.5"
  
  # Set default inactivity period to 45 days for new users
  run_command "useradd -D -f 45" "5.4.1.5 Set default inactivity period to 45 days"
  
  # Modify user parameters for all users with password hashes and inactive age > 45 or < 0
  run_command "awk -F: '(\$2~/^\\$.+\\$/) {if(\$7 > 45 || \$7 < 0) system(\"chage --inactive 45 \" \$1)}' /etc/shadow" "5.4.1.5 Enforce 45-day inactivity lock for all users"
  
  # =====================[ SECTION 5.4.1.6: Ensure all users last password change date is in the past ]=====================
  start_section "5.4.1.6"
  
  # Identify users with a password change date in the future and reset it to today
  run_command "awk -F: -v today=\$(date +%s) '(\$2~/^\\$.+\\$/) && (\$3 > 0) {cmd=\"date -d \\\"1970-01-01 +\" \$3 \" days\\\" +%s\"; cmd | getline pwd_date; close(cmd); if(pwd_date > today) system(\"chage -d \\\"\\\$(date +%Y-%m-%d)\\\" \" \$1)}' /etc/shadow" "5.4.1.6 Reset future password change dates to today"
  
  # =====================[ SECTION 5.4.2.1: Ensure root is the only UID 0 account ]=====================
  start_section "5.4.2.1"
  
  # Ensure root has UID 0
  run_command "usermod -u 0 root" "5.4.2.1 Set UID 0 for root account"
  
  # Identify and modify any other accounts with UID 0
  run_command "awk -F: '(\$3 == 0 && \$1 != \"root\") {print \$1}' /etc/passwd | while read user; do new_uid=\$(shuf -i 1001-1999 -n 1); usermod -u \$new_uid \$user; done" "5.4.2.1 Reassign UID for non-root UID 0 accounts"

  # =====================[ SECTION 5.4.2.2: Ensure root is the only GID 0 account ]=====================
  start_section "5.4.2.2"
  
  # Ensure root user's GID is 0
  run_command "usermod -g 0 root" "5.4.2.2 Set root user's GID to 0"
  
  # Ensure root group's GID is 0
  run_command "groupmod -g 0 root" "5.4.2.2 Set root group's GID to 0"
  
  # Identify and modify any other users with GID 0
  run_command "awk -F: '(\$4 == 0 && \$1 != \"root\") {print \$1}' /etc/passwd | while read user; do new_gid=\$(shuf -i 1001-1999 -n 1); usermod -g \$new_gid \$user; done" "5.4.2.2 Reassign GID for non-root GID 0 accounts"

  # =====================[ SECTION 5.4.2.3: Ensure group root is the only GID 0 group ]=====================
  start_section "5.4.2.3"
  
  # Ensure root group has GID 0
  run_command "groupmod -g 0 root" "5.4.2.3 Set root group's GID to 0"
  
  # Identify and modify any other groups with GID 0
  run_command "awk -F: '(\$3 == 0 && \$1 != \"root\") {print \$1}' /etc/group | while read grp; do new_gid=\$(shuf -i 1001-1999 -n 1); groupmod -g \$new_gid \$grp; done" "5.4.2.3 Reassign GID for non-root GID 0 groups"
  
  # =====================[ SECTION 5.4.2.4: Ensure root account access is controlled ]=====================
  start_section "5.4.2.4"
  
  # Option 1: Set a password for the root user (recommended if root login is permitted)
  # run_command "passwd root" "5.4.2.4 Set password for root account"
  
  # Option 2: Lock the root user account (recommended if root login is disabled)
   run_command "usermod -L root" "5.4.2.4 Lock root account"
   
  # =====================[ SECTION 5.4.2.5: Ensure root path integrity ]=====================
  start_section "5.4.2.5"
  
  # Check and sanitize entries in root's PATH
  run_command 'for dir in $(echo $PATH | tr ":" "\n"); do \
    if [[ -z "$dir" ]]; then \
      echo "Empty PATH entry (::) detected"; \
    elif [[ "$dir" == "." ]]; then \
      echo "Current directory (.) in PATH — remove for security"; \
    elif [[ ! -d "$dir" ]]; then \
      echo "Non-directory PATH entry: $dir"; \
    elif [[ $(stat -c %U "$dir") != "root" ]]; then \
      echo "Non-root owned directory in PATH: $dir"; \
    elif [[ $(stat -c %a "$dir") -gt 755 ]]; then \
      echo "Directory $dir has permissions more permissive than 0755"; \
    fi; \
  done' "5.4.2.5 Audit root PATH integrity"

  # =====================[ SECTION 5.4.2.6: Ensure root user umask is configured ]=====================
  start_section "5.4.2.6"
  
  # Update umask in /root/.bash_profile to 0027 or more restrictive
  run_command "sed -i '/^umask /s/umask .*/umask 0027/' /root/.bash_profile" "5.4.2.6 Set umask to 0027 in /root/.bash_profile"
  run_command "grep -q '^umask' /root/.bash_profile || echo 'umask 0027' >> /root/.bash_profile" "5.4.2.6 Ensure umask is present in /root/.bash_profile"
  
  # Update umask in /root/.bashrc to 0027 or more restrictive
  run_command "sed -i '/^umask /s/umask .*/umask 0027/' /root/.bashrc" "5.4.2.6 Set umask to 0027 in /root/.bashrc"
  run_command "grep -q '^umask' /root/.bashrc || echo 'umask 0027' >> /root/.bashrc" "5.4.2.6 Ensure umask is present in /root/.bashrc"
  
  # =====================[ SECTION 5.4.2.7: Ensure system accounts do not have a valid login shell ]=====================
  start_section "5.4.2.7"
  
  # Set shell to nologin for system accounts with valid login shells
  run_command 'UID_MIN=$(awk "/^\s*UID_MIN/{print \$2}" /etc/login.defs); \
  valid_shells="^($(awk -F/ '\''$NF != \"nologin\" {print}'\'' /etc/shells | sed -r "/^\//{s,/,\\\\/,g;p}" | paste -s -d "|" -))\$"; \
  awk -v pat="$valid_shells" -v uid_min="$UID_MIN" -F: '\''($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3 < uid_min || $3 == 65534) && $(NF) ~ pat) \
  {system("usermod -s $(command -v nologin) " $1)}'\'' /etc/passwd' "5.4.2.7 Set shell to nologin for system accounts"

  # =====================[ SECTION 5.4.2.8: Ensure accounts without a valid login shell are locked ]=====================
  start_section "5.4.2.8"
  
  # Lock non-root accounts that do not have a valid login shell
  run_command '
  valid_shells=$(grep -Ev "nologin|false" /etc/shells | tr "\n" " ")
  for user in $(awk -F: '\''$1 != "root" {print $1}'\'' /etc/passwd); do
    user_shell=$(getent passwd "$user" | cut -d: -f7)
    if ! echo "$valid_shells" | grep -qw "$user_shell"; then
      echo "Attempting to lock: $user with shell $user_shell"
      if passwd -S "$user" | awk '\''$2 !~ /^L/ {exit 0} $2 ~ /^L/ {exit 1}'\''; then
        usermod -L "$user"
      fi
    fi
  done
  ' "5.4.2.8 Lock non-root accounts without valid login shell"
  

  
  # =====================[ SECTION 5.4.3.1: Ensure nologin is not listed in /etc/shells ]=====================
  start_section "5.4.3.1"
  
  # Remove any lines containing 'nologin' from /etc/shells
  run_command "sed -i '/nologin/d' /etc/shells" "5.4.3.1 Remove nologin entries from /etc/shells"

  # =====================[ SECTION 5.4.3.2: Ensure default user shell timeout is configured ]=====================
  start_section "5.4.3.2"
  
  # Remove any existing TMOUT lines and append secure configuration to /etc/profile
  run_command "sed -i '/TMOUT=/d' /etc/profile && echo -e '\nTMOUT=900\nreadonly TMOUT\nexport TMOUT' >> /etc/profile" "5.4.3.2 Set TMOUT to 900 in /etc/profile"
  
  # Remove any existing TMOUT lines and append secure configuration to /etc/bashrc
  run_command "sed -i '/TMOUT=/d' /etc/bashrc && echo -e '\nTMOUT=900\nreadonly TMOUT\nexport TMOUT' >> /etc/bashrc" "5.4.3.2 Set TMOUT to 900 in /etc/bashrc"
  
  # Remove any existing TMOUT lines and append secure configuration to all *.sh files in /etc/profile.d
  run_command "find /etc/profile.d/ -type f -name '*.sh' -exec sed -i '/TMOUT=/d' {} + -exec bash -c 'echo -e \"\\nTMOUT=900\\nreadonly TMOUT\\nexport TMOUT\" >> {}' \\;" "5.4.3.2 Set TMOUT to 900 in /etc/profile.d/*.sh"
  
  # =====================[ SECTION 5.4.3.3: Ensure default user umask is configured ]=====================
  start_section "5.4.3.3"
  
  # Set default umask to 027 system-wide via profile.d
  run_command "printf '%s\\n' 'umask 027' > /etc/profile.d/50-systemwide_umask.sh" "5.4.3.3 Create system-wide umask config file"
  
  # Make umask readonly and exported
  run_command "echo 'readonly umask' >> /etc/profile.d/50-systemwide_umask.sh" "5.4.3.3 Make umask readonly"
  run_command "echo 'export umask' >> /etc/profile.d/50-systemwide_umask.sh" "5.4.3.3 Export umask setting"
  
  # Comment out weaker umask settings in system-wide config files
  run_command "sed -i '/^[[:space:]]*umask[[:space:]]\+[0-9]\{3\}/s/^/#/' /etc/profile /etc/bashrc /etc/bash.bashrc /etc/login.defs /etc/default/login" "5.4.3.3 Comment out weaker umask settings in system files"
  
  # Comment out weaker umask settings in profile.d scripts
  run_command "find /etc/profile.d/ -type f -name '*.sh' -exec sed -i '/^[[:space:]]*umask [0-9][0-9][0-9]/s/^/#/' {} +" "5.4.3.3 Comment out weaker umask settings in profile.d scripts"

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
