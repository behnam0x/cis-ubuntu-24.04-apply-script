#!/bin/bash
# CIS Hardening Script for Ubuntu 24.04
# Author: Behnam0x
# Date: $(date +%Y-%m-%d)

# =====================[ GLOBAL VARIABLES ]=====================
USE_TIMESTAMP=true  # Set to false to reuse the same log folder

RUN_TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
BASE_LOG_DIR="/home/${SUDO_USER:-$(whoami)}/setup_logs"

if [ "$USE_TIMESTAMP" = true ]; then
  LOG_DIR="$BASE_LOG_DIR/$RUN_TIMESTAMP"
  mkdir -p "$LOG_DIR"
  # 🧹 Keep only the 5 most recent timestamped log folders
  cd "$BASE_LOG_DIR"
  ls -dt */ | tail -n +6 | xargs -r rm -rf
else
  LOG_DIR="$BASE_LOG_DIR"
  rm -rf "$LOG_DIR"/*
  mkdir -p "$LOG_DIR"
fi

CURRENT_SECTION=""

# =====================[ SUMMARY TRACKING ]=====================
declare -A SUCCESS_COUNT
declare -A ERROR_COUNT

# =====================[ LOGGING FILES ]=====================
SUCCESS_LOG="$LOG_DIR/success.log"
ERROR_LOG="$LOG_DIR/error.log"
INFO_LOG="$LOG_DIR/info.log"
DETAILS_LOG="$LOG_DIR/details.log"

> "$SUCCESS_LOG"
> "$ERROR_LOG"
> "$INFO_LOG"
> "$DETAILS_LOG"

# =====================[ LOGGING FUNCTIONS ]=====================
start_section() {
  CURRENT_SECTION="$1"
  echo "[ℹ] 🔹 Starting section: $CURRENT_SECTION" | tee -a "$INFO_LOG"
}


log_success() {
  local MSG="  [✓] $1"
  echo -e "\e[32m$MSG\e[0m" | tee -a "$SUCCESS_LOG"
  ((SUCCESS_COUNT["$CURRENT_SECTION"]++))
}

log_error() {
  local MSG="  [✗] $1"
  echo -e "\e[31m$MSG\e[0m" | tee -a "$ERROR_LOG"
  ((ERROR_COUNT["$CURRENT_SECTION"]++))
}

log_message() {
  local MSG="  [ℹ] $1"
  echo -e "\e[36m$MSG\e[0m" | tee -a "$INFO_LOG"
}

run_command() {
  local CMD="$1"
  local DESC="$2"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] EXEC: $DESC" >> "$DETAILS_LOG"
  echo "COMMAND: $CMD" >> "$DETAILS_LOG"
  if eval "$CMD" >> "$DETAILS_LOG" 2>&1; then
    log_success "$DESC"
  else
    log_error "$DESC"
  fi
}

end_section() {
  local status=$1
  if [ "$status" -eq 0 ]; then
    echo -e "\e[32m[✓] Section completed successfully\e[0m"
  else
    echo -e "\e[31m[✗] Section failed\e[0m"
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

# =====================[ FINAL SUMMARY ]=====================
print_summary() {
  echo ""
  echo -e "\e[32m✅ CIS Ubuntu 24.04 hardening complete.\e[0m"
  echo -e "\e[34m📌 Please review any warnings or manual steps noted during execution.\e[0m"
  echo -e "\e[33m🔁 A reboot may be required for certain changes to take effect.\e[0m"
  echo -e "\e[36m🗂️ Logs saved to: $LOG_DIR\e[0m"
  echo ""

  echo -e "\e[36m📊 Summary of results:\e[0m"
  for section in $(printf "%s\n" "${!SUCCESS_COUNT[@]}" | sort -V); do
    success_count=${SUCCESS_COUNT[$section]:-0}
    error_count=${ERROR_COUNT[$section]:-0}
    echo -n "  - $section:"
    echo -ne " \e[32m✅ $success_count success(es)\e[0m"
    echo -ne ", \e[31m❌ $error_count error(s)\e[0m"
    echo ""
  done

  if [ -s "$ERROR_LOG" ]; then
    echo ""
    echo -e "\e[31m❗ Errors were recorded during execution.\e[0m"
    echo -e "\e[33m📄 Review them in: $ERROR_LOG\e[0m"
  else
    echo ""
    echo -e "\e[32m✅ No errors recorded in global log.\e[0m"
  fi

  echo ""
  echo -e "\e[36m📁 Log files for this run:\e[0m"
  echo "    ├── Success log: $SUCCESS_LOG"
  echo "    ├── Error log:   $ERROR_LOG"
  echo "    ├── Info log:    $INFO_LOG"
  echo "    └── Details log: $DETAILS_LOG"
  echo ""
  echo -e "\e[36m🛡️ Stay secure. Stay compliant.\e[0m"
}



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

###############################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "1.2" ]]; then

  # =====================[ SECTION 1.2.1.1: Ensure GPG keys are configured ]=====================
  start_section "1.2.1.1"

  # Check for GPG key files in trusted.gpg.d
  if find /etc/apt/trusted.gpg.d/ -type f -name '*.gpg' | grep -q .; then
    log_message "1.2.1.1 GPG key files found in /etc/apt/trusted.gpg.d/"
  else
    log_message "1.2.1.1 No GPG key files found in /etc/apt/trusted.gpg.d/ — manual review required"
  fi

  log_message "1.2.1.1 Manual remediation: Ensure GPG keys are configured according to site policy"

  # =====================[ SECTION 1.2.1.2: Ensure package manager repositories are configured ]=====================
  start_section "1.2.1.2"

  run_command "find /etc/apt/ -name '*.list' -exec grep -h ^deb {} \;" "1.2.1.2 List configured APT repositories"

  log_message "1.2.1.2 Manual remediation: Review and configure repositories according to site policy"


  # =====================[ SECTION 1.2.2.1: Ensure updates and security patches are installed ]=====================
  start_section "1.2.2.1"

  # Helper: Check if system is online
  is_online() {
    ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1
  }

  run_apt_command() {
    local CMD="$1"
    local LABEL="$2"
    local LOG="/tmp/apt_output.log"

    if ! is_online; then
      log_message "$LABEL Skipped: system appears to be offline"
      return
    fi

    if ! command -v timeout &>/dev/null; then
      log_message "$LABEL Skipped: 'timeout' command not available"
      return
    fi

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



#############################################################################
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
  GRUB_PASSWORD_HASH="grub.pbkdf2.sha512.600000.C6179215DBE8C9F03B3A91B42F33F6626CAD6F5E0FB40AFB4E55FA075D96B3B3DB8FC1C7DC78319"
  CUSTOM_GRUB_FILE="/etc/grub.d/01_password"

  run_command "
cat > $CUSTOM_GRUB_FILE <<EOF
#!/bin/sh
set -e
cat <<EOP
exec tail -n +2 \$0
set superusers=\"$GRUB_USER\"
password_pbkdf2 $GRUB_USER $GRUB_PASSWORD_HASH
EOP
EOF
" "1.4.1 Create GRUB password script"

  run_command "chmod 700 $CUSTOM_GRUB_FILE" "1.4.1 Set executable permissions on GRUB password script"
  run_command "update-grub" "1.4.1 Apply GRUB configuration changes"

  # =====================[ SECTION 1.4.2: Ensure access to bootloader config is configured ]=====================
  start_section "1.4.2"

  run_command "chown root:root /boot/grub/grub.cfg" "1.4.2 Set ownership of grub.cfg to root:root"
  run_command "chmod 600 /boot/grub/grub.cfg" "1.4.2 Set secure permissions on grub.cfg"

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

  # =====================[ 1.6.4–1.6.6: File Permissions and Ownership ]=====================
  run_command "chmod 744 /etc/issue /etc/issue.net /etc/update-motd.d/00-custom" "1.6.4–1.6.6 Set banner file permissions"
  run_command "chown root:root /etc/issue /etc/issue.net /etc/update-motd.d/00-custom" "1.6.4–1.6.6 Set banner file ownership"

  # =====================[ MOTD Interference and PAM Configuration ]=====================
  run_command "systemctl disable motd-news.service" "1.6.x Disable motd-news service"
  run_command "systemctl mask motd-news.service" "1.6.x Mask motd-news service"
  
  run_command "sed -i '/pam_motd.so/d' /etc/pam.d/sshd && echo 'session optional pam_motd.so motd=/run/motd.dynamic' >> /etc/pam.d/sshd" "1.6.x Configure PAM to show dynamic MOTD"
  run_command "sed -i '/pam_motd.so/d' /etc/pam.d/login && echo 'session optional pam_motd.so motd=/run/motd.dynamic' >> /etc/pam.d/login" "1.6.x Ensure PAM login MOTD is enabled"

fi

#################################################################################
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

  # Helper: Check if system is online
  is_online() {
    ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1
  }

  # === Choose your preferred time sync daemon ===
  TIME_SYNC_DAEMON="chrony"  # Options: chrony or systemd-timesyncd

  if [[ "$TIME_SYNC_DAEMON" == "chrony" ]]; then
    # ---------------------[ Chrony Setup ]---------------------
    if is_online; then
      run_command "apt update && apt install -y chrony" "2.3 Install chrony"
    else
      log_message "2.3 Skipped chrony install: system appears to be offline"
    fi

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
    if is_online; then
      run_command "apt purge -y chrony" "2.3 Remove chrony"
      run_command "apt autoremove -y chrony" "2.3 Autoremove chrony dependencies"
    else
      log_message "2.3 Skipped chrony removal: system appears to be offline"
    fi

    # Set timezone
    run_command "timedatectl set-timezone Asia/Tehran" "2.3 Set timezone to Asia/Tehran"

    # Configure systemd-timesyncd
    TIMESYNC_CONF="/etc/systemd/timesyncd.conf"
    TIMESERVER="pool asia.pool.ntp.org"
    if grep -q "^NTP=" "$TIMESYNC_CONF"; then
      run_command "sed -i 's/^NTP=.*/NTP=${TIMESERVER}/' $TIMESYNC_CONF" "2.3 Update NTP server in timesyncd.conf"
    else
      run_command "sed -i '/^

\[Time\]

/a NTP=${TIMESERVER}' $TIMESYNC_CONF" "2.3 Add NTP server to timesyncd.conf"
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

  # Helper: Check if system is online
  is_online() {
    ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1
  }

  # Install PAM libraries only if online
  if is_online; then
    apt update
    apt install --reinstall -y \
      libpam0g \
      libpam-modules \
      libpam-modules-bin \
      libpam-runtime \
      libpam-pwquality \
      libpam-tmpdir \
      libpam-fprintd
  else
    log_message "5.3.1.1 Skipped PAM package install: system appears to be offline"
  fi

  # Reconfigure PAM profiles if tool is available
  if command -v pam-auth-update &>/dev/null; then
    pam-auth-update --force
  else
    log_message "5.3.1.1 Skipped pam-auth-update: command not available"
  fi

  # =====================[ PAM Functionality Test: Validate passwd works ]=====================
  userdel -r testuser_5311 2>/dev/null
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

  # Helper: Check if system is online
  is_online() {
    ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1
  }

  # Check if libpam-pwquality is installed
  if dpkg -s libpam-pwquality >/dev/null 2>&1; then
    log_message "5.3.1.3 [✓] libpam-pwquality is already installed"
  else
    if ! is_online; then
      log_message "5.3.1.3 [✗] Skipped: system appears to be offline — libpam-pwquality not installed"
    elif ! command -v timeout &>/dev/null; then
      log_message "5.3.1.3 [✗] Skipped: 'timeout' command not available"
    else
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

  # Helper: Check if system is online
  is_online() {
    ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1
  }

  # Install all required PAM modules first
  if is_online; then
    apt update
    apt install --reinstall -y \
      libpam0g \
      libpam-modules \
      libpam-modules-bin \
      libpam-runtime \
      libpam-pwquality \
      libpam-tmpdir \
      libpam-fprintd
  else
    log_message "5.3.3.4.4 Skipped PAM package install: system appears to be offline"
  fi

  # Confirm pam_unix.so is present
  grep pam_unix.so /etc/pam.d/common-password || echo "Missing pam_unix.so — passwd will fail"

  # Reconfigure PAM profiles
  if command -v pam-auth-update &>/dev/null; then
    pam-auth-update --force
  else
    log_message "5.3.3.4.4 Skipped pam-auth-update: command not available"
  fi

  # Modify PAM profiles to include use_authtok in Password section only
  awk '/Password-Type:/{ f = 1;next } /-Type:/{ f = 0 } f {if (/pam_unix\.so/) print FILENAME}' /usr/share/pam-configs/* 2>/dev/null | sort -u | while read -r file; do
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

    PROFILE_NAME=$(basename "$file")
    run_command "pam-auth-update --enable \"$PROFILE_NAME\"" "5.3.3.4.4 [✓] Re-enabled PAM profile $PROFILE_NAME"
  done

  log_message "5.3.3.4.4 [✓] Success: pam_unix includes use_authtok in Password section only"

  # =====================[ PAM Functionality Test ]=====================
  userdel -r testuser_5311 2>/dev/null
  useradd -m testuser_5311
  echo "testuser_5311:TempPass123!" | chpasswd
  echo -e "TempPass123!\nNewPass123!\nNewPass123!" | passwd testuser_5311 > /tmp/passwd_test.log 2>&1
  EXIT_CODE=$?

  if [[ $EXIT_CODE -eq 0 ]]; then
    log_message "5.3.3.4.4 [✓] Password change test passed for testuser_5311"
  else
    log_message "5.3.3.4.4 [✗] Password change test failed — check /tmp/passwd_test.log and PAM configuration"
    ls -l /etc/shadow >> /tmp/passwd_test.log
    stat /etc/shadow >> /tmp/passwd_test.log
  fi
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
  
  # Secure TMOUT configuration block
  TMOUT_CONFIG=$'\n# Set TMOUT only if not already defined\nif [ -z "$TMOUT" ]; then\n  TMOUT=900\n  readonly TMOUT\n  export TMOUT\nfi\n'
  
  # Remove any existing TMOUT lines and append secure block to /etc/profile
  run_command "sed -i '/TMOUT=/d' /etc/profile && echo \"$TMOUT_CONFIG\" >> /etc/profile" "5.4.3.2 Set TMOUT block in /etc/profile"
  
  # Create or overwrite /etc/profile.d/timeout.sh with the secure block
  run_command "echo \"$TMOUT_CONFIG\" > /etc/profile.d/timeout.sh" "5.4.3.2 Create /etc/profile.d/timeout.sh with TMOUT block"
  
  # Ensure correct permissions
  run_command "chmod 644 /etc/profile.d/timeout.sh" "5.4.3.2 Set permissions on timeout.sh"
  run_command "chown root:root /etc/profile.d/timeout.sh" "5.4.3.2 Set ownership on timeout.sh"

  # =====================[ SECTION 5.4.3.3: Ensure default user umask is configured ]=====================
  start_section "5.4.3.3"
  
  # Set default umask to 027 system-wide via profile.d
  run_command "printf '%s\\n' 'umask 027' > /etc/profile.d/50-systemwide_umask.sh" \
    "5.4.3.3 Create system-wide umask config file"
  
  # Make umask readonly and exported
  run_command "echo 'readonly umask' >> /etc/profile.d/50-systemwide_umask.sh" \
    "5.4.3.3 Make umask readonly"
  run_command "echo 'export umask' >> /etc/profile.d/50-systemwide_umask.sh" \
    "5.4.3.3 Export umask setting"
  
  # Comment out weaker umask settings in system-wide config files (only if they exist)
  run_command "for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/login.defs /etc/default/login; do \
    [ -f \"\\\$f\" ] && sed -i '/^[[:space:]]*umask[[:space:]]\\+[0-9]\\{3\\}/s/^/#/' \"\\\$f\"; done" \
    "5.4.3.3 Comment out weaker umask settings in system files"

  
  # Comment out weaker umask settings in profile.d scripts
  run_command "find /etc/profile.d/ -type f -name '*.sh' -exec sed -i \
    '/^[[:space:]]*umask [0-9][0-9][0-9]/s/^/#/' {} +" \
    "5.4.3.3 Comment out weaker umask settings in profile.d scripts"
  
fi


########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "6.1.1" || "$TARGET_SECTION" == 6.1 ]]; then
  # =====================[ SECTION 6.1.1.1: Ensure journald service is enabled and active ]=====================
  start_section "6.1.1.1"
  
  # Unmask, start, and enable systemd-journald service
  run_command "systemctl unmask systemd-journald.service" "6.1.1.1 Unmask journald service"
  run_command "systemctl start systemd-journald.service" "6.1.1.1 Start journald service"
  run_command "systemctl enable systemd-journald.service" "6.1.1.1 Enable journald service"
  
  # =====================[ SECTION 6.1.1.2: Ensure journald log file access is configured ]=====================
  start_section "6.1.1.2"
  
  # Copy default journald tmpfiles config to override location
  run_command "cp /usr/lib/tmpfiles.d/systemd.conf /etc/tmpfiles.d/systemd.conf" "6.1.1.2 Copy journald tmpfiles config"
  
  # Update permissions for journald log files to 0640
  run_command "sed -i 's|^f /run/log/journal/%m/system.journal .*|f /run/log/journal/%m/system.journal 0640 root systemd-journal -|' /etc/tmpfiles.d/systemd.conf" "6.1.1.2 Set journald log file mode to 0640"
  
  # Apply the updated tmpfiles configuration
  run_command "systemd-tmpfiles --create /etc/tmpfiles.d/systemd.conf" "6.1.1.2 Apply journald tmpfiles config"
  
  # =====================[ SECTION 6.1.1.3: Ensure journald log file rotation is configured ]=====================
  start_section "6.1.1.3"
  
  # Define journald rotation settings
  run_command '
  a_settings=("SystemMaxUse=1G" "SystemKeepFree=500M" "RuntimeMaxUse=200M" "RuntimeKeepFree=50M" "MaxFileSec=1month")
  
  conf_file="/etc/systemd/journald.conf.d/60-journald.conf"
  
  # Ensure drop-in directory exists
  mkdir -p /etc/systemd/journald.conf.d/
  
  # Create or update the drop-in config file
  if grep -q "^\s*
  
  \[Journal\]
  
  " "$conf_file" 2>/dev/null; then
    # Append settings if [Journal] already exists
    for setting in "${a_settings[@]}"; do
      grep -q "^$setting" "$conf_file" || echo "$setting" >> "$conf_file"
    done
  else
    # Create new file with [Journal] section and settings
    {
      echo "[Journal]"
      for setting in "${a_settings[@]}"; do
        echo "$setting"
      done
    } > "$conf_file"
  fi
  ' "6.1.1.3 Create journald drop-in config for log rotation"
  
  # Reload journald to apply new settings
  run_command "systemctl reload-or-restart systemd-journald" "6.1.1.3 Reload journald with updated rotation settings"
  
  # =====================[ SECTION 6.1.1.4: Ensure only one logging system is in use (configured for ALL) ]=====================
  start_section "6.1.1.4"
  
  # Set logging system preference: journald, rsyslog, or all
  LOGGING_SYSTEM="all"
  
  if [ "$LOGGING_SYSTEM" = "journald" ]; then
    run_command "systemctl unmask systemd-journald.service" "6.1.1.4 Unmask journald"
    run_command "systemctl enable systemd-journald.service" "6.1.1.4 Enable journald"
    run_command "systemctl start systemd-journald.service" "6.1.1.4 Start journald"
    run_command "systemctl stop rsyslog.service" "6.1.1.4 Stop rsyslog"
    run_command "systemctl disable rsyslog.service" "6.1.1.4 Disable rsyslog"
    run_command "systemctl mask rsyslog.service" "6.1.1.4 Mask rsyslog"
  
  elif [ "$LOGGING_SYSTEM" = "rsyslog" ]; then
    run_command "systemctl enable rsyslog.service" "6.1.1.4 Enable rsyslog"
    run_command "systemctl start rsyslog.service" "6.1.1.4 Start rsyslog"
    run_command "systemctl stop systemd-journald.service" "6.1.1.4 Stop journald"
    run_command "systemctl disable systemd-journald.service" "6.1.1.4 Disable journald"
    run_command "systemctl mask systemd-journald.service" "6.1.1.4 Mask journald"
  
  elif [ "$LOGGING_SYSTEM" = "all" ]; then
    run_command "systemctl unmask systemd-journald.service" "6.1.1.4 Unmask journald"
    run_command "systemctl enable systemd-journald.service" "6.1.1.4 Enable journald"
    run_command "systemctl start systemd-journald.service" "6.1.1.4 Start journald"
    run_command "systemctl enable rsyslog.service" "6.1.1.4 Enable rsyslog"
    run_command "systemctl start rsyslog.service" "6.1.1.4 Start rsyslog"
  else
    echo "Invalid LOGGING_SYSTEM value: $LOGGING_SYSTEM"
    end_section 1
    exit 1
  fi
  
  end_section 0
fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "6.1.2" || "$TARGET_SECTION" == 6.1 ]]; then
  # =====================[ SECTION 6.1.2.1.1: Ensure systemd-journal-remote is installed ]=====================
  start_section "6.1.2.1.1"

  # Helper: Check if system is online
  is_online() {
    ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1
  }

  if is_online; then
    run_command "apt install -y systemd-journal-remote" "6.1.2.1.1 Install systemd-journal-remote"
  else
    log_message "6.1.2.1.1 Skipped: system appears to be offline — systemd-journal-remote not installed"
  fi

  # =====================[ SECTION 6.1.2.1.2: Ensure systemd-journal-upload authentication is configured ]=====================
  start_section "6.1.2.1.2"
  
  # Set the remote upload destination
  URL="192.168.50.42"
  
  # Configure systemd-journal-upload authentication
  run_command "
  a_settings=(\"URL=$URL\" \\
  \"ServerKeyFile=/etc/ssl/private/journal-upload.pem\" \\
  \"ServerCertificateFile=/etc/ssl/certs/journal-upload.pem\" \\
  \"TrustedCertificateFile=/etc/ssl/ca/trusted.pem\")
  
  conf_file=\"/etc/systemd/journal-upload.conf.d/60-journald_upload.conf\"
  
  mkdir -p /etc/systemd/journal-upload.conf.d/
  
  if grep -q \"^\\s*\
  
  \[Upload\\]
  
  \" \"\$conf_file\" 2>/dev/null; then
    for setting in \"\${a_settings[@]}\"; do
      grep -q \"^\$setting\" \"\$conf_file\" || echo \"\$setting\" >> \"\$conf_file\"
    done
  else
    {
      echo \"[Upload]\"
      for setting in \"\${a_settings[@]}\"; do
        echo \"\$setting\"
      done
    } > \"\$conf_file\"
  fi
  " "6.1.2.1.2 Configure systemd-journal-upload authentication"
  
  # Reload the journal-upload service to apply changes
  run_command "systemctl reload-or-restart systemd-journal-upload" "6.1.2.1.2 Reload systemd-journal-upload"
  
  # =====================[ SECTION 6.1.2.1.3: Ensure systemd-journal-upload is enabled and active ]=====================
  start_section "6.1.2.1.3"
  
  # Unmask, enable, and start systemd-journal-upload
  run_command "systemctl unmask systemd-journal-upload.service" "6.1.2.1.3 Unmask systemd-journal-upload"
  run_command "systemctl --now enable systemd-journal-upload.service" "6.1.2.1.3 Enable and start systemd-journal-upload"
  
  # =====================[ SECTION 6.1.2.1.4: Ensure systemd-journal-remote service is not in use ]=====================
  start_section "6.1.2.1.4"
  
  # Stop and mask systemd-journal-remote service and socket
  run_command "systemctl stop systemd-journal-remote.socket systemd-journal-remote.service" "6.1.2.1.4 Stop systemd-journal-remote"
  run_command "systemctl mask systemd-journal-remote.socket systemd-journal-remote.service" "6.1.2.1.4 Mask systemd-journal-remote"
  
  # =====================[ SECTION 6.1.2.2: Ensure journald ForwardToSyslog is disabled ]=====================
  start_section "6.1.2.2"
  
  # Configure journald to disable forwarding to syslog
  run_command '
  a_settings=("ForwardToSyslog=no")
  
  conf_file="/etc/systemd/journald.conf.d/60-journald.conf"
  
  # Ensure drop-in directory exists
  mkdir -p /etc/systemd/journald.conf.d/
  
  # Create or update the drop-in config file
  if grep -q "^\s*
  
  \[Journal\]
  
  " "$conf_file" 2>/dev/null; then
    for setting in "${a_settings[@]}"; do
      grep -q "^$setting" "$conf_file" || echo "$setting" >> "$conf_file"
    done
  else
    {
      echo "[Journal]"
      for setting in "${a_settings[@]}"; do
        echo "$setting"
      done
    } > "$conf_file"
  fi
  ' "6.1.2.2 Disable ForwardToSyslog in journald"
  
  # Reload journald to apply the new setting
  run_command "systemctl reload-or-restart systemd-journald" "6.1.2.2 Reload journald with updated ForwardToSyslog setting"
  
  # =====================[ SECTION 6.1.2.3: Ensure journald Compress is configured ]=====================
  start_section "6.1.2.3"
  
  # Choose your logging system: journald, rsyslog, or all
  LOGGING_SYSTEM="journald"
  
  if [ "$LOGGING_SYSTEM" = "journald" ] || [ "$LOGGING_SYSTEM" = "all" ]; then
    run_command '
    a_settings=("Compress=yes")
  
    conf_file="/etc/systemd/journald.conf.d/60-journald.conf"
  
    mkdir -p /etc/systemd/journald.conf.d/
  
    if grep -q "^\s*
  
  \[Journal\]
  
  " "$conf_file" 2>/dev/null; then
      for setting in "${a_settings[@]}"; do
        grep -q "^$setting" "$conf_file" || echo "$setting" >> "$conf_file"
      done
    else
      {
        echo "[Journal]"
        for setting in "${a_settings[@]}"; do
          echo "$setting"
        done
      } > "$conf_file"
    fi
    ' "6.1.2.3 Enable journald compression"
  
    run_command "systemctl reload-or-restart systemd-journald" "6.1.2.3 Reload journald with Compress=yes"
  else
    echo "6.1.2.3 skipped: journald is not the preferred logging system"
  fi

  # =====================[ SECTION 6.1.2.4: Ensure journald Storage is configured ]=====================
  start_section "6.1.2.4"
  
  # Set your logging system: journald, rsyslog, or all
  LOGGING_SYSTEM="journald"
  
  if [ "$LOGGING_SYSTEM" = "journald" ] || [ "$LOGGING_SYSTEM" = "all" ]; then
    run_command '
    a_settings=("Storage=persistent")
  
    conf_file="/etc/systemd/journald.conf.d/60-journald.conf"
  
    mkdir -p /etc/systemd/journald.conf.d/
  
    if grep -q "^\s*
  
  \[Journal\]
  
  " "$conf_file" 2>/dev/null; then
      for setting in "${a_settings[@]}"; do
        grep -q "^$setting" "$conf_file" || echo "$setting" >> "$conf_file"
      done
    else
      {
        echo "[Journal]"
        for setting in "${a_settings[@]}"; do
          echo "$setting"
        done
      } > "$conf_file"
    fi
    ' "6.1.2.4 Set journald Storage=persistent"
  
    run_command "systemctl reload-or-restart systemd-journald" "6.1.2.4 Reload journald with Storage=persistent"
  else
    echo "6.1.2.4 skipped: journald is not the preferred logging system"
  fi
fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "6.1.3" || "$TARGET_SECTION" == 6.1 ]]; then

  # =====================[ SECTION 6.1.3.1: Ensure rsyslog is installed ]=====================
  start_section "6.1.3.1"

  # Helper: Check if system is online
  is_online() {
    ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1
  }

  if is_online; then
    run_command "apt install -y rsyslog" "6.1.3.1 Install rsyslog"
  else
    log_message "6.1.3.1 Skipped: system appears to be offline — rsyslog not installed"
  fi


  # =====================[ SECTION 6.1.3.2: Ensure rsyslog service is enabled and active ]=====================
  start_section "6.1.3.2"
  LOGGING_SYSTEM="rsyslog"
  if [ "$LOGGING_SYSTEM" = "rsyslog" ] || [ "$LOGGING_SYSTEM" = "all" ]; then
    run_command "systemctl unmask rsyslog.service" "6.1.3.2 Unmask rsyslog"
    run_command "systemctl enable rsyslog.service" "6.1.3.2 Enable rsyslog"
    run_command "systemctl start rsyslog.service" "6.1.3.2 Start rsyslog"
  else
    echo "6.1.3.2 skipped: rsyslog is not the preferred logging system"
  fi

  # =====================[ SECTION 6.1.3.3: Ensure journald is configured to send logs to rsyslog ]=====================
  start_section "6.1.3.3"
  LOGGING_SYSTEM="rsyslog"
  if [ "$LOGGING_SYSTEM" = "rsyslog" ] || [ "$LOGGING_SYSTEM" = "all" ]; then
    run_command '
a_settings=("ForwardToSyslog=yes")
conf_file="/etc/systemd/journald.conf.d/60-journald.conf"

mkdir -p /etc/systemd/journald.conf.d/

if grep -q "^\s*

\[Journal\]

" "$conf_file" 2>/dev/null; then
  for setting in "${a_settings[@]}"; do
    grep -q "^$setting" "$conf_file" || echo "$setting" >> "$conf_file"
  done
else
  {
    echo "[Journal]"
    for setting in "${a_settings[@]}"; do
      echo "$setting"
    done
  } > "$conf_file"
fi
    ' "6.1.3.3 Set ForwardToSyslog=yes for rsyslog forwarding"
    run_command "systemctl reload-or-restart systemd-journald" "6.1.3.3 Reload journald to apply ForwardToSyslog"
  else
    echo "6.1.3.3 skipped: rsyslog is not the preferred logging system"
  fi

  # =====================[ SECTION 6.1.3.4: Ensure rsyslog log file creation mode is configured ]=====================
  start_section "6.1.3.4"
  LOGGING_SYSTEM="rsyslog"
  if [ "$LOGGING_SYSTEM" = "rsyslog" ] || [ "$LOGGING_SYSTEM" = "all" ]; then
    run_command '
mkdir -p /etc/rsyslog.d/
echo "" >> /etc/rsyslog.d/60-rsyslog.conf
echo "\$FileCreateMode 0640" >> /etc/rsyslog.d/60-rsyslog.conf
    ' "6.1.3.4 Set rsyslog file creation mode to 0640"
    run_command "systemctl reload-or-restart rsyslog" "6.1.3.4 Reload rsyslog to apply FileCreateMode"
  else
    echo "6.1.3.4 skipped: rsyslog is not the preferred logging system"
  fi

  # =====================[ SECTION 6.1.3.5: Ensure rsyslog logging is configured ]=====================
  start_section "6.1.3.5"
  LOGGING_SYSTEM="rsyslog"
  if [ "$LOGGING_SYSTEM" = "rsyslog" ] || [ "$LOGGING_SYSTEM" = "all" ]; then
    run_command '
mkdir -p /etc/rsyslog.d/

cat > /etc/rsyslog.d/60-rsyslog-logging.conf <<EOF
# Emergency messages to all users
*.emerg                         :omusrmsg:*

# Authentication and authorization logs
auth,authpriv.*                /var/log/secure

# Mail subsystem logs
mail.*                         -/var/log/mail
mail.info                      -/var/log/mail.info
mail.warning                   -/var/log/mail.warn
mail.err                       /var/log/mail.err

# Cron job activity
cron.*                         /var/log/cron

# Warnings and errors
*.=warning;*.=err              -/var/log/warn
*.crit                         /var/log/warn

# General system messages excluding mail and news
*.*;mail.none;news.none        -/var/log/messages

# Kernel messages
kern.*                         /var/log/kern.log

# System daemon logs
daemon.*                       /var/log/daemon.log

# User-level messages
user.*                         /var/log/user.log

# Boot logs (often used by local7)
local7.*                       /var/log/boot.log

# Rsyslog internal messages
syslog.*                       /var/log/syslog

# Custom application logs using local facilities
local0,local1.*                -/var/log/localmessages
local2,local3.*                -/var/log/localmessages
local4,local5.*                -/var/log/localmessages
local6.*                       -/var/log/localmessages
EOF
    ' "6.1.3.5 Apply best-practice rsyslog logging rules"
    run_command "systemctl reload-or-restart rsyslog" "6.1.3.5 Reload rsyslog to apply logging rules"
  else
    echo "6.1.3.5 skipped: rsyslog is not the preferred logging system"
  fi

  # =====================[ SECTION 6.1.3.6: Ensure rsyslog is configured to send logs to a remote log host ]=====================
  start_section "6.1.3.6"
  LOGGING_SYSTEM="rsyslog"
  REMOTE_LOG_HOST="loghost.example.com"  # Replace with your actual log host
  if [ "$LOGGING_SYSTEM" = "rsyslog" ] || [ "$LOGGING_SYSTEM" = "all" ]; then
    run_command "
mkdir -p /etc/rsyslog.d/

cat > /etc/rsyslog.d/60-rsyslog-remote.conf <<EOF
*.* action(
  type=\"omfwd\"
  target=\"${REMOTE_LOG_HOST}\"
  port=\"514\"
  protocol=\"tcp\"
  action.resumeRetryCount=\"100\"
  queue.type=\"LinkedList\"
  queue.size=\"1000\"
)
EOF
    " "6.1.3.6 Configure rsyslog to forward logs to remote host"
    run_command "systemctl reload-or-restart rsyslog" "6.1.3.6 Reload rsyslog to apply remote forwarding"
  else
    echo "6.1.3.6 skipped: rsyslog is not the preferred logging system"
  fi

  # =====================[ SECTION 6.1.3.7: Ensure rsyslog is not configured to receive logs from remote clients ]=====================
  start_section "6.1.3.7"

  LOGGING_SYSTEM="rsyslog"

  if [ "$LOGGING_SYSTEM" = "rsyslog" ] || [ "$LOGGING_SYSTEM" = "all" ]; then
    run_command '
# Directives to remove
patterns=(
  "module(load=\"imtcp\")"
  "input(type=\"imtcp\" port=\"514\")"
  "\$ModLoad imtcp"
  "\$InputTCPServerRun"
)

# Target config files
config_files=$(grep -rlE "${patterns[*]}" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null)

# Remove matching lines
for file in $config_files; do
  for pattern in "${patterns[@]}"; do
    sed -i "/$pattern/d" "$file"
  done
done
    ' "6.1.3.7 Remove rsyslog remote receive directives"

    run_command "systemctl reload-or-restart rsyslog" "6.1.3.7 Reload rsyslog after removing remote receive config"
  else
    echo "6.1.3.7 skipped: rsyslog is not the preferred logging system"
  fi

  # =====================[ SECTION 6.1.3.8: Ensure logrotate is configured ]=====================
  start_section "6.1.3.8"

  run_command '
mkdir -p /etc/logrotate.d/

cat > /etc/logrotate.d/rsyslog <<EOF
/var/log/syslog
/var/log/messages
/var/log/secure
/var/log/cron
/var/log/mail
/var/log/mail.*
/var/log/kern.log
/var/log/daemon.log
/var/log/user.log
/var/log/boot.log
/var/log/localmessages
{
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF
  ' "6.1.3.8 Configure logrotate for rsyslog logs"
fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "6.1.4" || "$TARGET_SECTION" == 6.1 ]]; then

  # =====================[ SECTION 6.1.4.1: Ensure access to all logfiles has been configured ]=====================
  start_section "6.1.4.1"

  run_command '
log_paths=("/var/log" "/var/lib" "/var/audit")
a_output2=()

f_file_test_fix() {
  a_out2=()
  maxperm="$(printf "%o" $((0777 & ~$perm_mask)))"

  if [ $((l_mode & perm_mask)) -gt 0 ]; then
    a_out2+=(" o Mode: \"$l_mode\" should be \"$maxperm\" or more restrictive" " x Removing excess permissions")
    chmod "$l_rperms" "$l_fname"
  fi

  if [[ ! "$l_user" =~ $l_auser ]]; then
    a_out2+=(" o Owned by: \"$l_user\" and should be owned by \"${l_auser//|/ or }\"" " x Changing ownership to: \"$l_fix_account\"")
    chown "$l_fix_account" "$l_fname"
  fi

  if [[ ! "$l_group" =~ $l_agroup ]]; then
    a_out2+=(" o Group owned by: \"$l_group\" and should be group owned by \"${l_agroup//|/ or }\"" " x Changing group ownership to: \"$l_fix_account\"")
    chgrp "$l_fix_account" "$l_fname"
  fi

  [ "${#a_out2[@]}" -gt 0 ] && a_output2+=(" - File: \"$l_fname\" is:" "${a_out2[@]}")
}

l_fix_account="root"

for path in "${log_paths[@]}"; do
  while IFS= read -r -d $'\0' l_file; do
    while IFS=: read -r l_fname l_mode l_user l_group; do
      case "$(basename "$l_fname")" in
        lastlog* | wtmp* | btmp* | README)
          perm_mask="0113" l_rperms="ug-x,o-wx" l_auser="root" l_agroup="(root|utmp)"
          f_file_test_fix ;;
        cloud-init.log* | localmessages* | waagent.log*)
          perm_mask="0133" l_rperms="u-x,go-wx" l_auser="(root|syslog)" l_agroup="(root|adm)"
          f_file_test_fix ;;
        secure | auth.log | syslog | messages)
          perm_mask="0137" l_rperms="u-x,g-wx,o-rwx" l_auser="(root|syslog)" l_agroup="(root|adm)"
          f_file_test_fix ;;
        SSSD | sssd)
          perm_mask="0117" l_rperms="ug-x,o-rwx" l_auser="(root|SSSD)" l_agroup="(root|SSSD)"
          f_file_test_fix ;;
        gdm | gdm3)
          perm_mask="0117" l_rperms="ug-x,o-rwx" l_auser="root" l_agroup="(root|gdm|gdm3)"
          f_file_test_fix ;;
        *.journal | *.journal~)
          perm_mask="0137" l_rperms="u-x,g-wx,o-rwx" l_auser="root" l_agroup="(root|systemd-journal)"
          f_file_test_fix ;;
        *)
          perm_mask="0137" l_rperms="u-x,g-wx,o-rwx" l_auser="(root|syslog)" l_agroup="(root|adm)"
          user_shell="$(awk -F: -v u=\"$l_user\" '\''$1==u {print $7}'\'' /etc/passwd)"
          if [ "$l_user" = "root" ] || ! grep -Pq -- "^\s*${user_shell}\b" /etc/shells; then
            ! grep -Pq -- "$l_auser" <<< "$l_user" && l_auser="(root|syslog|$l_user)"
            ! grep -Pq -- "$l_agroup" <<< "$l_group" && l_agroup="(root|adm|$l_group)"
          fi
          f_file_test_fix ;;
      esac
    done < <(stat -Lc "%n:%#a:%U:%G" "$l_file")
  done < <(find -L "$path" -type f \( -perm /0137 -o ! -user root -o ! -group root \) -print0)
done

if [ "${#a_output2[@]}" -le 0 ]; then
  printf "\n%s\n" "- All files in log paths have appropriate permissions and ownership" " o No changes required"
else
  printf "\n%s\n" "${a_output2[@]}"
fi
  ' "6.1.4.1 Audit and fix log file permissions"

fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "6.2.1" || "$TARGET_SECTION" == 6.2 ]]; then

  # =====================[ SECTION 6.2.1.1: Ensure auditd packages are installed ]=====================
  start_section "6.2.1.1"

  # Helper: Check if system is online
  is_online() {
    ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1
  }

  if is_online; then
    run_command "apt install -y auditd audispd-plugins" "6.2.1.1 Install auditd and audispd-plugins"
  else
    log_message "6.2.1.1 Skipped: system appears to be offline — auditd not installed"
  fi

  
  # =====================[ SECTION 6.2.1.2: Ensure auditd service is enabled and active ]=====================
  start_section "6.2.1.2"

  run_command "systemctl unmask auditd" "6.2.1.2 Unmask auditd service"
  run_command "systemctl enable auditd" "6.2.1.2 Enable auditd service"
  run_command "systemctl start auditd" "6.2.1.2 Start auditd service"


  # =====================[ SECTION 6.2.1.3: Ensure auditing for early processes is enabled ]=====================
  start_section "6.2.1.3"

  # Add audit=1 to GRUB_CMDLINE_LINUX if not already present
  run_command "
if ! grep -q 'audit=1' /etc/default/grub; then
  sed -i 's/^\(GRUB_CMDLINE_LINUX=\".*\)\"/\1 audit=1\"/' /etc/default/grub
fi
" "6.2.1.3 Add audit=1 to GRUB_CMDLINE_LINUX"

  # Update GRUB configuration
  run_command "update-grub" "6.2.1.3 Apply GRUB configuration changes"


  # =====================[ SECTION 6.2.1.4: Ensure audit_backlog_limit is sufficient ]=====================
  start_section "6.2.1.4"

  # Add audit_backlog_limit=8192 to GRUB_CMDLINE_LINUX if not already present
  run_command "
if ! grep -q 'audit_backlog_limit=' /etc/default/grub; then
  sed -i 's/^\(GRUB_CMDLINE_LINUX=\".*\)\"/\1 audit_backlog_limit=8192\"/' /etc/default/grub
elif ! grep -q 'audit_backlog_limit=8192' /etc/default/grub; then
  sed -i 's/audit_backlog_limit=[0-9]\\+/audit_backlog_limit=8192/' /etc/default/grub
fi
" "6.2.1.4 Ensure audit_backlog_limit=8192 is set in GRUB"

  # Update GRUB configuration
  run_command "update-grub" "6.2.1.4 Apply GRUB configuration changes"


fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "6.2.2" || "$TARGET_SECTION" == 6.2 ]]; then

  # =====================[ SECTION 6.2.2.1: Ensure audit log storage size is configured ]=====================
  start_section "6.2.2.1"

  # Set max_log_file to 8 MB or higher in /etc/audit/auditd.conf
  run_command '
if grep -q "^max_log_file" /etc/audit/auditd.conf; then
  sed -i "s/^max_log_file.*/max_log_file = 8/" /etc/audit/auditd.conf
else
  echo "max_log_file = 8" >> /etc/audit/auditd.conf
fi
' "6.2.2.1 Set max_log_file = 8 in auditd.conf"


  # =====================[ SECTION 6.2.2.2: Ensure audit logs are not automatically deleted ]=====================
  start_section "6.2.2.2"

  # Set max_log_file_action to keep_logs in /etc/audit/auditd.conf
  run_command '
if grep -q "^max_log_file_action" /etc/audit/auditd.conf; then
  sed -i "s/^max_log_file_action.*/max_log_file_action = keep_logs/" /etc/audit/auditd.conf
else
  echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf
fi
' "6.2.2.2 Set max_log_file_action = keep_logs in auditd.conf"


  # =====================[ SECTION 6.2.2.3: Ensure system is disabled when audit logs are full ]=====================
  start_section "6.2.2.3"

  # Set disk_full_action and disk_error_action in /etc/audit/auditd.conf
  run_command '
if grep -q "^disk_full_action" /etc/audit/auditd.conf; then
  sed -i "s/^disk_full_action.*/disk_full_action = halt/" /etc/audit/auditd.conf
else
  echo "disk_full_action = halt" >> /etc/audit/auditd.conf
fi

if grep -q "^disk_error_action" /etc/audit/auditd.conf; then
  sed -i "s/^disk_error_action.*/disk_error_action = halt/" /etc/audit/auditd.conf
else
  echo "disk_error_action = halt" >> /etc/audit/auditd.conf
fi
' "6.2.2.3 Set disk_full_action and disk_error_action to halt in auditd.conf"


  # =====================[ SECTION 6.2.2.4: Ensure system warns when audit logs are low on space ]=====================
  start_section "6.2.2.4"

  # Set space_left_action and admin_space_left_action in /etc/audit/auditd.conf
  run_command '
if grep -q "^space_left_action" /etc/audit/auditd.conf; then
  sed -i "s/^space_left_action.*/space_left_action = email/" /etc/audit/auditd.conf
else
  echo "space_left_action = email" >> /etc/audit/auditd.conf
fi

if grep -q "^admin_space_left_action" /etc/audit/auditd.conf; then
  sed -i "s/^admin_space_left_action.*/admin_space_left_action = single/" /etc/audit/auditd.conf
else
  echo "admin_space_left_action = single" >> /etc/audit/auditd.conf
fi
' "6.2.2.4 Set space_left_action=email and admin_space_left_action=single in auditd.conf"

fi
########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "6.2.3" || "$TARGET_SECTION" == 6.2 ]]; then

  # =====================[ SECTION 6.2.3.1: Ensure sudoers changes are audited ]=====================
  start_section "6.2.3.1"

  AUDIT_RULE_FILE="/etc/audit/rules.d/50-scope.rules"

  run_command '
# Ensure audit rules for sudoers are present and optimized
if [ ! -f "$AUDIT_RULE_FILE" ]; then
  touch "$AUDIT_RULE_FILE"
fi

if grep -qE "^-w /etc/sudoers" "$AUDIT_RULE_FILE"; then
  sed -i "s|^-w /etc/sudoers.*|-w /etc/sudoers -p wa -k scope|" "$AUDIT_RULE_FILE"
else
  echo "-w /etc/sudoers -p wa -k scope" >> "$AUDIT_RULE_FILE"
fi

if grep -qE "^-w /etc/sudoers.d" "$AUDIT_RULE_FILE"; then
  sed -i "s|^-w /etc/sudoers.d.*|-w /etc/sudoers.d -p wa -k scope|" "$AUDIT_RULE_FILE"
else
  echo "-w /etc/sudoers.d -p wa -k scope" >> "$AUDIT_RULE_FILE"
fi
' "6.2.3.1 Edit or create audit rules for sudoers scope changes"

  run_command "augenrules --load" "6.2.3.1 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.1 Check if audit system is locked and warn about reboot requirement"



  # =====================[ SECTION 6.2.3.2: Ensure actions as another user are always logged ]=====================
  start_section "6.2.3.2"

  AUDIT_RULE_FILE="/etc/audit/rules.d/50-user_emulation.rules"

  run_command '
# Ensure audit rules for user emulation are present and optimized
if [ ! -f "$AUDIT_RULE_FILE" ]; then
  touch "$AUDIT_RULE_FILE"
fi

if ! grep -q "user_emulation" "$AUDIT_RULE_FILE"; then
  cat >> "$AUDIT_RULE_FILE" <<EOF
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
EOF
fi
' "6.2.3.2 Edit or create audit rules for user emulation"

  run_command "augenrules --load" "6.2.3.2 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.2 Check if audit system is locked and warn about reboot requirement"



  # =====================[ SECTION 6.2.3.3: Ensure sudo log file modifications are audited ]=====================
  start_section "6.2.3.3"

  run_command '
SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* 2>/dev/null | sed -e "s/.*logfile=//;s/,.*//" -e "s/\"//g")

if [ -n "$SUDO_LOG_FILE" ]; then
  AUDIT_RULE_FILE="/etc/audit/rules.d/50-sudo.rules"
  if [ ! -f "$AUDIT_RULE_FILE" ]; then
    touch "$AUDIT_RULE_FILE"
  fi

  if grep -q "$SUDO_LOG_FILE" "$AUDIT_RULE_FILE"; then
    sed -i "s|.*$SUDO_LOG_FILE.*|-w $SUDO_LOG_FILE -p wa -k sudo_log_file|" "$AUDIT_RULE_FILE"
  else
    echo "-w $SUDO_LOG_FILE -p wa -k sudo_log_file" >> "$AUDIT_RULE_FILE"
  fi
else
  echo "ERROR: Variable 'SUDO_LOG_FILE' is unset. Please ensure sudo logging is configured."
fi
' "6.2.3.3 Edit or create audit rule for sudo log file"

  run_command "augenrules --load" "6.2.3.3 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.3 Check if audit system is locked and warn about reboot requirement"


  # =====================[ SECTION 6.2.3.4: Ensure date/time modification events are audited ]=====================
  start_section "6.2.3.4"

  AUDIT_RULE_FILE="/etc/audit/rules.d/50-time-change.rules"

  run_command '
# Ensure audit rules for time-change events are present and optimized
if [ ! -f "$AUDIT_RULE_FILE" ]; then
  touch "$AUDIT_RULE_FILE"
fi

if ! grep -q "time-change" "$AUDIT_RULE_FILE"; then
  cat >> "$AUDIT_RULE_FILE" <<EOF
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change
EOF
fi
' "6.2.3.4 Edit or create audit rules for time-change events"

  run_command "augenrules --load" "6.2.3.4 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.4 Check if audit system is locked and warn about reboot requirement"


  # =====================[ SECTION 6.2.3.5: Ensure network environment modification events are audited ]=====================
  start_section "6.2.3.5"

  AUDIT_RULE_FILE="/etc/audit/rules.d/50-system_locale.rules"

  run_command '
# Ensure audit rules for system locale and network environment changes are present and optimized
if [ ! -f "$AUDIT_RULE_FILE" ]; then
  touch "$AUDIT_RULE_FILE"
fi

if ! grep -q "system-locale" "$AUDIT_RULE_FILE"; then
  cat >> "$AUDIT_RULE_FILE" <<EOF
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/network/ -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale
EOF
fi
' "6.2.3.5 Edit or create audit rules for system locale and network changes"

  run_command "augenrules --load" "6.2.3.5 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.5 Check if audit system is locked and warn about reboot requirement"



  # =====================[ SECTION 6.2.3.6: Ensure privileged command usage is audited ]=====================
  start_section "6.2.3.6"

  run_command '
UID_MIN=$(awk "/^\s*UID_MIN/{print \$2}" /etc/login.defs)
AUDIT_RULE_FILE="/etc/audit/rules.d/50-privileged.rules"
NEW_DATA=()

for PARTITION in $(findmnt -n -l -k -it $(awk "/nodev/ { print \$2 }" /proc/filesystems | paste -sd,) | grep -Pv "noexec|nosuid" | awk "{print \$1}"); do
  readarray -t DATA < <(find "${PARTITION}" -xdev -perm /6000 -type f | awk -v UID_MIN=${UID_MIN} "{print \"-a always,exit -F path=\" \$1 \" -F perm=x -F auid>=\" UID_MIN \" -F auid!=unset -k privileged\"}")
  for ENTRY in "${DATA[@]}"; do
    NEW_DATA+=("${ENTRY}")
  done
done

readarray &> /dev/null -t OLD_DATA < "${AUDIT_RULE_FILE}"
COMBINED_DATA=( "${OLD_DATA[@]}" "${NEW_DATA[@]}" )
printf "%s\n" "${COMBINED_DATA[@]}" | sort -u > "${AUDIT_RULE_FILE}"
' "6.2.3.6 Discover and write audit rules for privileged commands"

  run_command "augenrules --load" "6.2.3.6 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.6 Check if audit system is locked and warn about reboot requirement"



  # =====================[ SECTION 6.2.3.7: Ensure unsuccessful file access attempts are audited ]=====================
  start_section "6.2.3.7"

  run_command '
UID_MIN=$(awk "/^\s*UID_MIN/{print \$2}" /etc/login.defs)

if [ -n "$UID_MIN" ]; then
  AUDIT_RULE_FILE="/etc/audit/rules.d/50-access.rules"
  if [ ! -f "$AUDIT_RULE_FILE" ]; then
    touch "$AUDIT_RULE_FILE"
  fi

  if ! grep -q "access" "$AUDIT_RULE_FILE"; then
    cat >> "$AUDIT_RULE_FILE" <<EOF
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=$UID_MIN -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=$UID_MIN -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=$UID_MIN -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=$UID_MIN -F auid!=unset -k access
EOF
  fi
else
  echo "ERROR: Variable 'UID_MIN' is unset. Check /etc/login.defs."
fi
' "6.2.3.7 Edit or create audit rules for unsuccessful file access attempts"

  run_command "augenrules --load" "6.2.3.7 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.7 Check if audit system is locked and warn about reboot requirement"



  # =====================[ SECTION 6.2.3.8: Ensure identity modification events are audited ]=====================
  start_section "6.2.3.8"

  AUDIT_RULE_FILE="/etc/audit/rules.d/50-identity.rules"

  run_command '
# Ensure audit rules for identity-related file changes are present
if [ ! -f "$AUDIT_RULE_FILE" ]; then
  touch "$AUDIT_RULE_FILE"
fi

if ! grep -q "identity" "$AUDIT_RULE_FILE"; then
  cat >> "$AUDIT_RULE_FILE" <<EOF
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity
EOF
fi
' "6.2.3.8 Edit or create audit rules for identity-related file changes"

  run_command "augenrules --load" "6.2.3.8 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.8 Check if audit system is locked and warn about reboot requirement"


  # =====================[ SECTION 6.2.3.9: Ensure permission modification events are audited ]=====================
  start_section "6.2.3.9"

  run_command '
UID_MIN=$(awk "/^\s*UID_MIN/{print \$2}" /etc/login.defs)

if [ -n "$UID_MIN" ]; then
  AUDIT_RULE_FILE="/etc/audit/rules.d/50-perm_mod.rules"
  if [ ! -f "$AUDIT_RULE_FILE" ]; then
    touch "$AUDIT_RULE_FILE"
  fi

  if ! grep -q "perm_mod" "$AUDIT_RULE_FILE"; then
    cat >> "$AUDIT_RULE_FILE" <<EOF
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=$UID_MIN -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=$UID_MIN -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=$UID_MIN -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=$UID_MIN -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=$UID_MIN -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=$UID_MIN -F auid!=unset -k perm_mod
EOF
  fi
else
  echo "ERROR: Variable 'UID_MIN' is unset. Check /etc/login.defs."
fi
' "6.2.3.9 Edit or create audit rules for permission modification events"

  run_command "augenrules --load" "6.2.3.9 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.9 Check if audit system is locked and warn about reboot requirement"


  # =====================[ SECTION 6.2.3.10: Ensure successful file system mounts are audited ]=====================
  start_section "6.2.3.10"

  run_command '
UID_MIN=$(awk "/^\s*UID_MIN/{print \$2}" /etc/login.defs)

if [ -n "$UID_MIN" ]; then
  AUDIT_RULE_FILE="/etc/audit/rules.d/50-mounts.rules"
  if [ ! -f "$AUDIT_RULE_FILE" ]; then
    touch "$AUDIT_RULE_FILE"
  fi

  if ! grep -q "mounts" "$AUDIT_RULE_FILE"; then
    cat >> "$AUDIT_RULE_FILE" <<EOF
-a always,exit -F arch=b32 -S mount -F auid>=$UID_MIN -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S mount -F auid>=$UID_MIN -F auid!=unset -k mounts
EOF
  fi
else
  echo "ERROR: Variable 'UID_MIN' is unset. Check /etc/login.defs."
fi
' "6.2.3.10 Edit or create audit rules for successful mount events"

  run_command "augenrules --load" "6.2.3.10 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.10 Check if audit system is locked and warn about reboot requirement"


  # =====================[ SECTION 6.2.3.11: Ensure session initiation events are audited ]=====================
  start_section "6.2.3.11"

  AUDIT_RULE_FILE="/etc/audit/rules.d/50-session.rules"

  run_command '
# Ensure audit rules for session initiation files are present
if [ ! -f "$AUDIT_RULE_FILE" ]; then
  touch "$AUDIT_RULE_FILE"
fi

if ! grep -q "session" "$AUDIT_RULE_FILE"; then
  cat >> "$AUDIT_RULE_FILE" <<EOF
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
EOF
fi
' "6.2.3.11 Edit or create audit rules for session initiation files"

  run_command "augenrules --load" "6.2.3.11 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.11 Check if audit system is locked and warn about reboot requirement"


  # =====================[ SECTION 6.2.3.12: Ensure login and logout events are audited ]=====================
  start_section "6.2.3.12"

  AUDIT_RULE_FILE="/etc/audit/rules.d/50-login.rules"

  run_command '
# Ensure audit rules for login/logout tracking files are present
if [ ! -f "$AUDIT_RULE_FILE" ]; then
  touch "$AUDIT_RULE_FILE"
fi

if ! grep -q "logins" "$AUDIT_RULE_FILE"; then
  cat >> "$AUDIT_RULE_FILE" <<EOF
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
EOF
fi
' "6.2.3.12 Edit or create audit rules for login/logout tracking files"

  run_command "augenrules --load" "6.2.3.12 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.12 Check if audit system is locked and warn about reboot requirement"


  # =====================[ SECTION 6.2.3.13: Ensure file deletion events are audited ]=====================
  start_section "6.2.3.13"

  run_command '
UID_MIN=$(awk "/^\s*UID_MIN/{print \$2}" /etc/login.defs)

if [ -n "$UID_MIN" ]; then
  AUDIT_RULE_FILE="/etc/audit/rules.d/50-delete.rules"
  if [ ! -f "$AUDIT_RULE_FILE" ]; then
    touch "$AUDIT_RULE_FILE"
  fi

  if ! grep -q "delete" "$AUDIT_RULE_FILE"; then
    cat >> "$AUDIT_RULE_FILE" <<EOF
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=$UID_MIN -F auid!=unset -k delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=$UID_MIN -F auid!=unset -k delete
EOF
  fi
else
  echo "ERROR: Variable 'UID_MIN' is unset. Check /etc/login.defs."
fi
' "6.2.3.13 Edit or create audit rules for file deletion events"

  run_command "augenrules --load" "6.2.3.13 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.13 Check if audit system is locked and warn about reboot requirement"



  # =====================[ SECTION 6.2.3.14: Ensure MAC policy modification events are audited ]=====================
  start_section "6.2.3.14"

  AUDIT_RULE_FILE="/etc/audit/rules.d/50-MAC-policy.rules"

  run_command '
# Ensure audit rules for MAC policy changes are present
if [ ! -f "$AUDIT_RULE_FILE" ]; then
  touch "$AUDIT_RULE_FILE"
fi

if ! grep -q "MAC-policy" "$AUDIT_RULE_FILE"; then
  cat >> "$AUDIT_RULE_FILE" <<EOF
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
EOF
fi
' "6.2.3.14 Edit or create audit rules for MAC policy changes"

  run_command "augenrules --load" "6.2.3.14 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.14 Check if audit system is locked and warn about reboot requirement"



  # =====================[ SECTION 6.2.3.15: Ensure chcon command usage is audited ]=====================
  start_section "6.2.3.15"

  run_command '
UID_MIN=$(awk "/^\s*UID_MIN/{print \$2}" /etc/login.defs)

if [ -n "$UID_MIN" ]; then
  AUDIT_RULE_FILE="/etc/audit/rules.d/50-perm_chng.rules"
  if [ ! -f "$AUDIT_RULE_FILE" ]; then
    touch "$AUDIT_RULE_FILE"
  fi

  if ! grep -q "/usr/bin/chcon" "$AUDIT_RULE_FILE"; then
    echo "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=$UID_MIN -F auid!=unset -k perm_chng" >> "$AUDIT_RULE_FILE"
  fi
else
  echo "ERROR: Variable 'UID_MIN' is unset. Check /etc/login.defs."
fi
' "6.2.3.15 Edit or create audit rule for chcon command usage"

  run_command "augenrules --load" "6.2.3.15 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.15 Check if audit system is locked and warn about reboot requirement"



  # =====================[ SECTION 6.2.3.16: Ensure setfacl command usage is audited ]=====================
  start_section "6.2.3.16"

  run_command '
UID_MIN=$(awk "/^\s*UID_MIN/{print \$2}" /etc/login.defs)

if [ -n "$UID_MIN" ]; then
  AUDIT_RULE_FILE="/etc/audit/rules.d/50-perm_chng.rules"
  if [ ! -f "$AUDIT_RULE_FILE" ]; then
    touch "$AUDIT_RULE_FILE"
  fi

  if ! grep -q "/usr/bin/setfacl" "$AUDIT_RULE_FILE"; then
    echo "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=$UID_MIN -F auid!=unset -k perm_chng" >> "$AUDIT_RULE_FILE"
  fi
else
  echo "ERROR: Variable 'UID_MIN' is unset. Check /etc/login.defs."
fi
' "6.2.3.16 Edit or create audit rule for setfacl command usage"

  run_command "augenrules --load" "6.2.3.16 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.16 Check if audit system is locked and warn about reboot requirement"


  # =====================[ SECTION 6.2.3.17: Ensure chacl command usage is audited ]=====================
  start_section "6.2.3.17"

  run_command '
UID_MIN=$(awk "/^\s*UID_MIN/{print \$2}" /etc/login.defs)

if [ -n "$UID_MIN" ]; then
  AUDIT_RULE_FILE="/etc/audit/rules.d/50-perm_chng.rules"
  if [ ! -f "$AUDIT_RULE_FILE" ]; then
    touch "$AUDIT_RULE_FILE"
  fi

  if ! grep -q "/usr/bin/chacl" "$AUDIT_RULE_FILE"; then
    echo "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=$UID_MIN -F auid!=unset -k perm_chng" >> "$AUDIT_RULE_FILE"
  fi
else
  echo "ERROR: Variable 'UID_MIN' is unset. Check /etc/login.defs."
fi
' "6.2.3.17 Edit or create audit rule for chacl command usage"

  run_command "augenrules --load" "6.2.3.17 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.17 Check if audit system is locked and warn about reboot requirement"


  # =====================[ SECTION 6.2.3.18: Ensure usermod command usage is audited ]=====================
  start_section "6.2.3.18"

  run_command '
UID_MIN=$(awk "/^\s*UID_MIN/{print \$2}" /etc/login.defs)

if [ -n "$UID_MIN" ]; then
  AUDIT_RULE_FILE="/etc/audit/rules.d/50-usermod.rules"
  if [ ! -f "$AUDIT_RULE_FILE" ]; then
    touch "$AUDIT_RULE_FILE"
  fi

  if ! grep -q "/usr/sbin/usermod" "$AUDIT_RULE_FILE"; then
    echo "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=$UID_MIN -F auid!=unset -k usermod" >> "$AUDIT_RULE_FILE"
  fi
else
  echo "ERROR: Variable 'UID_MIN' is unset. Check /etc/login.defs."
fi
' "6.2.3.18 Edit or create audit rule for usermod command usage"

  run_command "augenrules --load" "6.2.3.18 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.18 Check if audit system is locked and warn about reboot requirement"


  # =====================[ SECTION 6.2.3.19: Ensure kernel module modification events are audited ]=====================
  start_section "6.2.3.19"

  run_command '
UID_MIN=$(awk "/^\s*UID_MIN/{print \$2}" /etc/login.defs)

if [ -n "$UID_MIN" ]; then
  AUDIT_RULE_FILE="/etc/audit/rules.d/50-kernel_modules.rules"
  if [ ! -f "$AUDIT_RULE_FILE" ]; then
    touch "$AUDIT_RULE_FILE"
  fi

  if ! grep -q "kernel_modules" "$AUDIT_RULE_FILE"; then
    cat >> "$AUDIT_RULE_FILE" <<EOF
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=$UID_MIN -F auid!=unset -k kernel_modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=$UID_MIN -F auid!=unset -k kernel_modules
EOF
  fi
else
  echo "ERROR: Variable 'UID_MIN' is unset. Check /etc/login.defs."
fi
' "6.2.3.19 Edit or create audit rules for kernel module operations"

  run_command "augenrules --load" "6.2.3.19 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.19 Check if audit system is locked and warn about reboot requirement"


  # =====================[ SECTION 6.2.3.20: Ensure audit configuration is immutable ]=====================
  start_section "6.2.3.20"

  AUDIT_RULE_FILE="/etc/audit/rules.d/99-finalize.rules"

  run_command '
# Ensure audit configuration is set to immutable
if [ ! -f "$AUDIT_RULE_FILE" ]; then
  touch "$AUDIT_RULE_FILE"
fi

if ! grep -q "^-e 2" "$AUDIT_RULE_FILE"; then
  echo "-e 2" >> "$AUDIT_RULE_FILE"
fi
' "6.2.3.20 Edit or create audit rule to make configuration immutable"

  run_command "augenrules --load" "6.2.3.20 Load audit rules into active configuration"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.20 Check if audit system is locked and warn about reboot requirement"


  # =====================[ SECTION 6.2.3.21: Ensure audit configuration is synchronized ]=====================
  start_section "6.2.3.21"

  run_command "augenrules --load" "6.2.3.21 Merge and load audit rules from disk"

  run_command '
if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then
  echo "⚠️ Audit system is locked (enabled 2). Reboot required to apply new audit rules."
fi
' "6.2.3.21 Check if audit system is locked and warn about reboot requirement"


  # =====================[ SECTION 6.2.3.final: Cleanup duplicate audit rules and reload ]=====================
  start_section "6.2.3.final"

  run_command '
# Comment out duplicate rules in /etc/audit/audit.rules (e.g., repeated -w /usr/bin and execve)
for i in $(grep -nE "^-w /usr/bin/ -p x -k processes$" /etc/audit/audit.rules | cut -d: -f1 | tail -n +2); do
  sed -i "${i}s/^/#/" /etc/audit/audit.rules
done

for i in $(grep -nE "^-a always,exit -F arch=b64 -S execve -k processes$" /etc/audit/audit.rules | cut -d: -f1 | tail -n +2); do
  sed -i "${i}s/^/#/" /etc/audit/audit.rules
done
' "6.2.3.final Comment out duplicate audit rules"

  run_command "auditctl -R /etc/audit/audit.rules" "6.2.3.final Reload cleaned audit rules"

  run_command "auditctl -l" "6.2.3.final Show active audit rules"

fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "6.2.4" || "$TARGET_SECTION" == 6.2 ]]; then

  # =====================[ SECTION 6.2.4.1: Ensure audit log file permissions are restricted ]=====================
  start_section "6.2.4.1"

  run_command '
if [ -f /etc/audit/auditd.conf ]; then
  LOG_DIR=$(dirname $(awk -F "=" "/^\s*log_file/ {print \$2}" /etc/audit/auditd.conf | xargs))
  find "$LOG_DIR" -type f -perm /0137 -exec chmod u-x,g-wx,o-rwx {} +
fi
' "6.2.4.1 Restrict audit log file permissions to 0640 or less"


  # =====================[ SECTION 6.2.4.2: Ensure audit log files are owned by root ]=====================
  start_section "6.2.4.2"

  run_command '
if [ -f /etc/audit/auditd.conf ]; then
  LOG_DIR=$(dirname $(awk -F "=" "/^\s*log_file/ {print \$2}" /etc/audit/auditd.conf | xargs))
  find "$LOG_DIR" -type f ! -user root -exec chown root {} +
fi
' "6.2.4.2 Ensure audit log files are owned by root"


  # =====================[ SECTION 6.2.4.3: Ensure audit log files group owner is adm ]=====================
  start_section "6.2.4.3"

  run_command '
sed -ri "s/^\s*#?\s*log_group\s*=.*/log_group = adm/" /etc/audit/auditd.conf
' "6.2.4.3 Set log_group = adm in auditd.conf"

  run_command "systemctl restart auditd" "6.2.4.3 Restart audit daemon to apply group ownership changes"

  run_command '
if [ -f /etc/audit/auditd.conf ]; then
  LOG_DIR=$(dirname $(awk -F "=" "/^\s*log_file/ {print \$2}" /etc/audit/auditd.conf | xargs))
  find "$LOG_DIR" -type f -name "audit.log*" ! -group adm ! -group root -exec chgrp adm {} +
fi
' "6.2.4.3 Set audit log files group owner to adm (excluding non-audit logs)"



  # =====================[ SECTION 6.2.4.4: Ensure audit log directory permissions are restricted ]=====================
  start_section "6.2.4.4"

  run_command '
if [ -f /etc/audit/auditd.conf ]; then
  LOG_DIR=$(dirname $(awk -F "=" "/^\s*log_file/ {print \$2}" /etc/audit/auditd.conf | xargs))
  chmod g-w,o-rwx "$LOG_DIR"
fi
' "6.2.4.4 Restrict audit log directory permissions to 0750 or less"


  # =====================[ SECTION 6.2.4.5: Ensure audit config file permissions are restricted ]=====================
  start_section "6.2.4.5"

  run_command '
find /etc/audit/ -type f \( -name "*.conf" -o -name "*.rules" \) -exec chmod u-x,g-wx,o-rwx {} +
' "6.2.4.5 Restrict audit configuration file permissions to 0640 or less"


  # =====================[ SECTION 6.2.4.6: Ensure audit config files are owned by root ]=====================
  start_section "6.2.4.6"

  run_command '
find /etc/audit/ -type f \( -name "*.conf" -o -name "*.rules" \) ! -user root -exec chown root {} +
' "6.2.4.6 Ensure audit configuration files are owned by root"


  # =====================[ SECTION 6.2.4.7: Ensure audit config files group owner is root ]=====================
  start_section "6.2.4.7"

  run_command '
find /etc/audit/ -type f \( -name "*.conf" -o -name "*.rules" \) ! -group root -exec chgrp root {} +
' "6.2.4.7 Ensure audit configuration files are group-owned by root"


  # =====================[ SECTION 6.2.4.8: Ensure audit tool permissions are restricted ]=====================
  start_section "6.2.4.8"

  run_command '
chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
' "6.2.4.8 Restrict audit tool permissions to prevent group/other write access"


  # =====================[ SECTION 6.2.4.9: Ensure audit tool ownership is root ]=====================
  start_section "6.2.4.9"

  run_command '
chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
' "6.2.4.9 Ensure audit tools are owned by root"


  # =====================[ SECTION 6.2.4.10: Ensure audit tool group ownership is root ]=====================
  start_section "6.2.4.10"

  run_command '
chgrp root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
' "6.2.4.10 Ensure audit tools are group-owned by root"

fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "6.3" ]]; then

  # =====================[ SECTION 6.3.1: Ensure AIDE is installed and initialized ]=====================
  start_section "6.3.1"

  # Helper: Check if system is online
  is_online() {
    ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1
  }

  # Attempt to install AIDE if not already installed
  if ! dpkg -s aide >/dev/null 2>&1; then
    if is_online; then
      run_command "apt install -y aide aide-common" "6.3.1 Install AIDE and aide-common packages"
    else
      log_message "6.3.1 Skipped: system appears to be offline — AIDE not installed"
    fi
  else
    log_message "6.3.1 [✓] AIDE is already installed"
  fi

  # Re-check if AIDE is installed before continuing
  if ! dpkg -s aide >/dev/null 2>&1; then
    log_message "6.3.1 [✗] AIDE is not installed — skipping initialization and scheduling"
    return
  fi

  # Initialize AIDE database
  if command -v aideinit &>/dev/null; then
    run_command "aideinit" "6.3.1 Initialize AIDE database"

    if [[ -f /var/lib/aide/aide.db.new ]]; then
      run_command "mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db" "6.3.1 Move initialized AIDE database into place"
    else
      log_message "6.3.1 Warning: aide.db.new not found — initialization may have failed"
    fi
  else
    log_message "6.3.1 Skipped: aideinit command not found — initialization not performed"
  fi

  # =====================[ SECTION 6.3.2: Ensure AIDE integrity checks are scheduled ]=====================
  start_section "6.3.2"

  run_command '
systemctl unmask dailyaidecheck.timer dailyaidecheck.service
' "6.3.2 Unmask dailyaidecheck.timer and dailyaidecheck.service"

  run_command '
systemctl --now enable dailyaidecheck.timer
' "6.3.2 Enable and start dailyaidecheck.timer for daily integrity checks"

  run_command '
if grep -q "/usr/bin/aide" /etc/systemd/system/aidecheck.service; then
  sed -i "s|/usr/bin/aide|/usr/bin/aide.wrapper|g" /etc/systemd/system/aidecheck.service
  systemctl daemon-reexec
fi
' "6.3.2 Replace aide with aide.wrapper in aidecheck.service (Ubuntu best practice)"

  # =====================[ SECTION 6.3.3: Ensure cryptographic integrity of audit tools ]=====================
  start_section "6.3.3"

  run_command '
AUDIT_PATH=$(readlink -f /sbin)
printf "%s\n" "" "# Audit Tools" \
"$AUDIT_PATH/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" \
"$AUDIT_PATH/auditd p+i+n+u+g+s+b+acl+xattrs+sha512" \
"$AUDIT_PATH/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512" \
"$AUDIT_PATH/aureport p+i+n+u+g+s+b+acl+xattrs+sha512" \
"$AUDIT_PATH/autrace p+i+n+u+g+s+b+acl+xattrs+sha512" \
"$AUDIT_PATH/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
' "6.3.3 Add audit tool integrity rules to aide.conf using sha512"

fi


##############################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "7.1" ]]; then

  # =====================[ SECTION 7.1.1: Ensure permissions on /etc/passwd are configured ]=====================
  start_section "7.1.1"

  run_command '
chmod u-x,go-wx /etc/passwd
' "7.1.1 Remove excess permissions from /etc/passwd"

  run_command '
chown root:root /etc/passwd
' "7.1.1 Set owner and group of /etc/passwd to root"


  # =====================[ SECTION 7.1.2: Ensure permissions on /etc/passwd- are configured ]=====================
  start_section "7.1.2"

  run_command '
chmod u-x,go-wx /etc/passwd-
' "7.1.2 Remove excess permissions from /etc/passwd-"

  run_command '
chown root:root /etc/passwd-
' "7.1.2 Set owner and group of /etc/passwd- to root"


  # =====================[ SECTION 7.1.3: Ensure permissions on /etc/group are configured ]=====================
  start_section "7.1.3"

  run_command '
chmod u-x,go-wx /etc/group
' "7.1.3 Remove excess permissions from /etc/group"

  run_command '
chown root:root /etc/group
' "7.1.3 Set owner and group of /etc/group to root"


  # =====================[ SECTION 7.1.4: Ensure permissions on /etc/group- are configured ]=====================
  start_section "7.1.4"

  run_command '
chmod u-x,go-wx /etc/group-
' "7.1.4 Remove excess permissions from /etc/group-"

  run_command '
chown root:root /etc/group-
' "7.1.4 Set owner and group of /etc/group- to root"



  # =====================[ SECTION 7.1.5: Ensure permissions on /etc/shadow are configured ]=====================
  start_section "7.1.5"

  run_command '
chown root:root /etc/shadow
' "7.1.5 Set owner and group of /etc/shadow to root or shadow"

  run_command '
chmod u-x,g-wx,o-rwx /etc/shadow
' "7.1.5 Remove excess permissions from /etc/shadow"


  # =====================[ SECTION 7.1.6: Ensure permissions on /etc/shadow- are configured ]=====================
  start_section "7.1.6"

  run_command '
chown root:root /etc/shadow-
' "7.1.6 Set owner and group of /etc/shadow- to root or shadow"

  run_command '
chmod u-x,g-wx,o-rwx /etc/shadow-
' "7.1.6 Remove excess permissions from /etc/shadow-"


  # =====================[ SECTION 7.1.7: Ensure permissions on /etc/gshadow are configured ]=====================
  start_section "7.1.7"

  run_command '
chown root:shadow /etc/gshadow || chown root:root /etc/gshadow
' "7.1.7 Set owner and group of /etc/gshadow to root or shadow"

  run_command '
chmod u-x,g-wx,o-rwx /etc/gshadow
' "7.1.7 Remove excess permissions from /etc/gshadow"


  # =====================[ SECTION 7.1.8: Ensure permissions on /etc/gshadow- are configured ]=====================
  start_section "7.1.8"

  run_command '
chown root:shadow /etc/gshadow- || chown root:root /etc/gshadow-
' "7.1.8 Set owner and group of /etc/gshadow- to root or shadow"

  run_command '
chmod u-x,g-wx,o-rwx /etc/gshadow-
' "7.1.8 Remove excess permissions from /etc/gshadow-"


  # =====================[ SECTION 7.1.9: Ensure permissions on /etc/shells are configured ]=====================
  start_section "7.1.9"

  run_command '
chmod u-x,go-wx /etc/shells
' "7.1.9 Remove excess permissions from /etc/shells"

  run_command '
chown root:root /etc/shells
' "7.1.9 Set owner and group of /etc/shells to root"


  # =====================[ SECTION 7.1.10: Ensure permissions on /etc/security/opasswd are configured ]=====================
  start_section "7.1.10"

  run_command '
[ -e "/etc/security/opasswd" ] && chmod u-x,go-rwx /etc/security/opasswd
' "7.1.10 Remove excess permissions from /etc/security/opasswd"

  run_command '
[ -e "/etc/security/opasswd" ] && chown root:root /etc/security/opasswd
' "7.1.10 Set owner and group of /etc/security/opasswd to root"

  run_command '
[ -e "/etc/security/opasswd.old" ] && chmod u-x,go-rwx /etc/security/opasswd.old
' "7.1.10 Remove excess permissions from /etc/security/opasswd.old"

  run_command '
[ -e "/etc/security/opasswd.old" ] && chown root:root /etc/security/opasswd.old
' "7.1.10 Set owner and group of /etc/security/opasswd.old to root"


  # =====================[ SECTION 7.1.11: Secure world writable files and directories ]=====================
  start_section "7.1.11"

  run_command '
l_smask="01000"
a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/*" -a ! -path "/snap/*")

while IFS= read -r l_mount; do
  while IFS= read -r -d $'\''\0'\'' l_file; do
    if [ -e "$l_file" ]; then
      l_mode="$(stat -Lc '\''%#a'\'' "$l_file")"
      if [ -f "$l_file" ]; then
        chmod o-w "$l_file"
      fi
      if [ -d "$l_file" ]; then
        if [ ! $(( l_mode & l_smask )) -gt 0 ]; then
          chmod a+t "$l_file"
        fi
      fi
    fi
  done < <(find "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type d \) -perm -0002 -print0 2>/dev/null)
done < <(findmnt -Dkerno fstype,target | awk '\''($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^(\/run\/user\/|\/tmp|\/var\/tmp)/){print $2}'\'')
' "7.1.11 Remove world-write from files and add sticky bit to directories"


  # =====================[ SECTION 7.1.12: Ensure no unowned files or directories exist ]=====================
  start_section "7.1.12"

  run_command '
find / -xdev \( -nouser -o -nogroup \) -exec chown root:root {} +
' "7.1.12 Assign root ownership to unowned files and directories"


  # =====================[ SECTION 7.1.13: Review SUID and SGID files manually ]=====================
  start_section "7.1.13"

  run_command '
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | tee "$LOG_DIR/section_logs/7.1.13/suid_sgid_files.log"
' "7.1.13 Discover SUID and SGID files for manual review"

  log_message "Manual review required: Check $LOG_DIR/section_logs/7.1.13/suid_sgid_files.log for potential rogue binaries."

fi

########################################################################################
if [[ -z "$TARGET_SECTION" || "$TARGET_SECTION" == "7.2" ]]; then

  # =====================[ SECTION 7.2.1: Ensure accounts use shadowed passwords ]=====================
  start_section "7.2.1"
  run_command <<'EOF'
pwconv
EOF
  log_message "7.2.1 Completed: Migrated passwords to /etc/shadow using pwconv"


  # =====================[ SECTION 7.2.2: Ensure /etc/shadow password fields are not empty ]=====================
  start_section "7.2.2"
  run_command <<'EOF'
awk -F: '($2 == "") {print $1}' /etc/shadow | while read -r user; do
  echo "Locking account with empty password: $user"
  passwd -l "$user"
done
EOF
  log_message "7.2.2 Completed: Locked accounts with empty password fields"


  # =====================[ SECTION 7.2.3: Ensure all groups in /etc/passwd exist in /etc/group ]=====================
  start_section "7.2.3"
  run_command <<EOF
awk -F: '{print \$1,\$4}' /etc/passwd | while read -r user gid; do
  if ! grep -qE "^.*:.*:\$gid:" /etc/group; then
    echo "Group ID \$gid referenced by user \$user does not exist in /etc/group"
  fi
done | tee "$LOG_DIR/section_logs/7.2.3/missing_groups.log"
EOF
  log_message "Manual remediation required: Review $LOG_DIR/section_logs/7.2.3/missing_groups.log and add missing groups to /etc/group as needed."


  # =====================[ SECTION 7.2.4: Ensure shadow group is empty ]=====================
  start_section "7.2.4"
  run_command <<'EOF'
sed -ri 's/(^shadow:[^:]*:[^:]*:)([^:]+$)/\1/' /etc/group
EOF
  run_command <<'EOF'
awk -F: '$4 == 42 { print $1 }' /etc/passwd | while read -r user; do
  echo "User $user has shadow as primary group. Consider changing it with: usermod -g <newgroup> $user"
done | tee "$LOG_DIR/section_logs/7.2.4/shadow_primary_users.log"
EOF
  log_message "Manual remediation may be required: Review $LOG_DIR/section_logs/7.2.4/shadow_primary_users.log and change primary group if needed."


  # =====================[ SECTION 7.2.5: Ensure no duplicate UIDs exist ]=====================
  start_section "7.2.5"
  run_command <<'EOF'
awk -F: '{print $3}' /etc/passwd | sort | uniq -d | while read -r dup_uid; do
  echo "Duplicate UID: $dup_uid"
  awk -F: -v uid="$dup_uid" '$3 == uid {print \" - \" \$1}' /etc/passwd
done | tee "$LOG_DIR/section_logs/7.2.5/duplicate_uids.log"
EOF
  log_message "Manual remediation required: Review $LOG_DIR/section_logs/7.2.5/duplicate_uids.log and assign unique UIDs as needed. Also audit file ownership for affected users."


  # =====================[ SECTION 7.2.6: Ensure no duplicate GIDs exist ]=====================
  start_section "7.2.6"
  run_command <<'EOF'
awk -F: '{print $3}' /etc/group | sort | uniq -d | while read -r dup_gid; do
  echo "Duplicate GID: $dup_gid"
  awk -F: -v gid="$dup_gid" '$3 == gid {print \" - \" \$1}' /etc/group
done | tee "$LOG_DIR/section_logs/7.2.6/duplicate_gids.log"
EOF
  run_command <<'EOF'
grpck
EOF
  log_message "Manual remediation required: Review $LOG_DIR/section_logs/7.2.6/duplicate_gids.log and assign unique GIDs as needed. Also audit file ownership for affected groups."


  # =====================[ SECTION 7.2.7: Ensure no duplicate user names exist ]=====================
  start_section "7.2.7"
  run_command <<'EOF'
cut -d: -f1 /etc/passwd | sort | uniq -d | while read -r dup_user; do
  echo "Duplicate username: $dup_user"
  grep "^$dup_user:" /etc/passwd
done | tee "$LOG_DIR/section_logs/7.2.7/duplicate_usernames.log"
EOF
  log_message "Manual remediation required: Review $LOG_DIR/section_logs/7.2.7/duplicate_usernames.log and rename or remove duplicate usernames as needed."


  # =====================[ SECTION 7.2.8: Ensure no duplicate group names exist ]=====================
  start_section "7.2.8"
  
  run_command <<'EOF'
  cut -d: -f1 /etc/group | sort | uniq -d | while read -r dup_group; do
    echo "Duplicate group name: $dup_group"
    grep "^$dup_group:" /etc/group
  done | tee "$LOG_DIR/section_logs/7.2.8/duplicate_groupnames.log"
  EOF
  
  log_message "Manual remediation required: Review $LOG_DIR/section_logs/7.2.8/duplicate_groupnames.log and rename or remove duplicate group names as needed."


  # =====================[ SECTION 7.2.9: Ensure local interactive user home directories are configured ]=====================
  start_section "7.2.9"

  run_command <<'EOF'
l_output2=""
shells_regex=$(awk -F/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\/,g;p}' | paste -s -d '|' -)
l_valid_shells="^(${shells_regex})$"

unset a_uarr && a_uarr=()
while read -r l_epu l_eph; do
  a_uarr+=("$l_epu $l_eph")
done <<< "$(awk -v pat="$l_valid_shells" -F: '$NF ~ pat { print $1 \" \" $(NF-1) }' /etc/passwd)"

for entry in "${a_uarr[@]}"; do
  l_user=$(echo "$entry" | awk '{print $1}')
  l_home=$(echo "$entry" | awk '{print $2}')

  if [ -d "$l_home" ]; then
    l_mask="0027"
    l_max="$(printf '%o' $((0777 & ~$l_mask)))"
    read -r l_own l_mode <<< "$(stat -Lc '%U %#a' "$l_home")"

    if [ "$l_user" != "$l_own" ]; then
      echo -e " - User: \"$l_user\" Home \"$l_home\" is owned by: \"$l_own\"\n - changing ownership to: \"$l_user\""
      chown "$l_user" "$l_home"
    fi

    if [ $((l_mode & l_mask)) -gt 0 ]; then
      echo -e " - User: \"$l_user\" Home \"$l_home\" is mode: \"$l_mode\" should be mode: \"$l_max\" or more restrictive\n - removing excess permissions"
      chmod g-w,o-rwx "$l_home"
    fi
  else
    echo -e " - User: \"$l_user\" Home \"$l_home\" doesn't exist\n - Please create a home in accordance with local site policy"
  fi
done
EOF

  log_message "7.2.9 Completed: Validated and corrected local interactive user home directory ownership and permissions"


  # =====================[ SECTION 7.2.10: Ensure local interactive user dot files access is configured ]=====================
  start_section "7.2.10"

  run_command <<'EOF'
shells_regex=$(awk -F/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\/,g;p}' | paste -s -d '|' -)
l_valid_shells="^(${shells_regex})$"

a_user_and_home=()
while read -r l_user l_home; do
  [[ -n "$l_user" && -n "$l_home" ]] && a_user_and_home+=("$l_user:$l_home")
done <<< "$(awk -v pat="$l_valid_shells" -F: '$NF ~ pat { print $1 \" \" $(NF-1) }' /etc/passwd)"

for entry in "${a_user_and_home[@]}"; do
  l_user="${entry%%:*}"
  l_home="${entry##*:}"
  [ ! -d "$l_home" ] && continue
  l_group="$(id -gn "$l_user" | xargs)"

  find "$l_home" -xdev -type f -name ".*" -print0 | while IFS= read -r -d $'\0' l_hdfile; do
    read -r l_mode l_owner l_gowner <<< "$(stat -Lc '%#a %U %G' "$l_hdfile")"
    case "$(basename "$l_hdfile")" in
      .forward | .rhost )
        echo " - File: \"$l_hdfile\" exists — please review and manually delete this file"
        ;;
      .netrc )
        l_mask="0177"; l_change="u-x,go-rwx"
        [ $(( l_mode & l_mask )) -gt 0 ] && chmod "$l_change" "$l_hdfile"
        [ "$l_owner" != "$l_user" ] && chown "$l_user" "$l_hdfile"
        [ "$l_gowner" != "$l_group" ] && chgrp "$l_group" "$l_hdfile"
        ;;
      .bash_history )
        l_mask="0177"; l_change="u-x,go-rwx"
        [ $(( l_mode & l_mask )) -gt 0 ] && chmod "$l_change" "$l_hdfile"
        ;;
      * )
        l_mask="0133"; l_change="u-x,go-wx"
        [ $(( l_mode & l_mask )) -gt 0 ] && chmod "$l_change" "$l_hdfile"
        [ "$l_owner" != "$l_user" ] && chown "$l_user" "$l_hdfile"
        [ "$l_gowner" != "$l_group" ] && chgrp "$l_group" "$l_hdfile"
        ;;
    esac
  done
done
EOF

  log_message "7.2.10 Completed: Secured dotfiles in interactive user home directories"

fi
########################################################################################






# =====================[ END OF CIS Ubuntu 24.04 HARDENING SCRIPT ]=====================

echo ""
echo -e "\e[32m✅ CIS Ubuntu 24.04 hardening complete.\e[0m"
echo -e "\e[34m📌 Please review any warnings or manual steps noted during execution.\e[0m"
echo -e "\e[33m🔁 A reboot may be required for certain changes to take effect.\e[0m"
echo -e "\e[36m🗂️ Logs saved to: $LOG_DIR\e[0m"
echo ""

# 📊 Summary of results
echo -e "\e[36m📊 Summary of results:\e[0m"

# Print per-section summary
for section in $(printf "%s\n" "${!SUCCESS_COUNT[@]}" | sort -V); do
  success_count=${SUCCESS_COUNT[$section]:-0}
  error_count=${ERROR_COUNT[$section]:-0}
  echo -n "  - $section:"
  echo -ne " \e[32m✅ $success_count success(es)\e[0m"
  echo -ne ", \e[31m❌ $error_count error(s)\e[0m"
  echo ""
done

# 📄 Global error log summary
ERROR_LOG="$LOG_DIR/error.log"
if [ -s "$ERROR_LOG" ]; then
  echo ""
  echo -e "\e[31m❗ Errors were recorded during execution.\e[0m"
  echo -e "\e[33m📄 Review them in: $ERROR_LOG\e[0m"
else
  echo ""
  echo -e "\e[32m✅ No errors recorded in global log.\e[0m"
fi

# 📁 Log file paths
echo ""
echo -e "\e[36m📁 Log files for this run:\e[0m"
echo "    ├── Success log: $LOG_DIR/success.log"
echo "    ├── Error log:   $LOG_DIR/error.log"
echo "    ├── Info log:    $LOG_DIR/info.log"
echo "    └── Details log: $LOG_DIR/details.log"

echo ""
echo -e "\e[36m🛡️ Stay secure. Stay compliant.\e[0m"

