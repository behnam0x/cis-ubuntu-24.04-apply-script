# 🛡️ CIS Ubuntu 24.04 Hardening Script

This Bash script automates the application of security configurations based on the [CIS Benchmark for Ubuntu Linux 24.04](https://www.cisecurity.org/benchmark/ubuntu_linux). It helps system administrators enforce best practices for system hardening, reduce attack surface, and improve compliance posture.

---

## 🚀 What It Does

- Applies Level 1 CIS controls for Ubuntu 24.04
- Configures system-wide security settings:
  - File permissions and ownership
  - Audit policies and logging
  - Kernel and network parameters
  - User account and password policies
  - Service and daemon restrictions
  - GRUB bootloader protection
- Uses modular functions for each control group
- Logs actions and results for auditability
- Designed for interactive or automated execution

---

## 📦 Requirements

- Ubuntu 24.04 (fresh or existing install)
- Root privileges (`sudo`)
- Core system utilities:
  - `awk`, `sed`, `grep`, `ufw`, `auditctl`, `systemctl`, `apt`, `dpkg`, `passwd`, `chage`, `find`, `stat`, `sysctl`, `crontab`

Install missing tools:
```bash
sudo apt update
sudo apt install auditd ufw
```

---

## 🧪 How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/behnam0x/cis-ubuntu-24.04-apply-script.git
   cd cis-ubuntu-24.04-apply-script
   ```

2. Make the script executable:
   ```bash
   chmod +x cis-hardening-ubuntu-24.sh
   ```

3. Run the script with root privileges:
   ```bash
   sudo ./cis-hardening-ubuntu-24.sh
   ```

---

## 📊 Logging and Audit Trail

All actions performed by the script are logged to:

```
/var/log/cis-ubuntu-apply.log
```

This log includes:
- Timestamps for each control applied
- Command outputs and status messages
- Success or failure indicators for each step

Use this log to:
- Audit changes made to the system
- Troubleshoot failed steps
- Verify compliance with CIS controls

---

## 🔐 GRUB Password Protection

The script includes a section to secure the GRUB bootloader with a password. This prevents unauthorized users from editing boot parameters or entering recovery mode.

To customize the GRUB password:

1. Open the script and locate the GRUB configuration section.
2. Replace the placeholder password with your own:
   ```bash
   grub-mkpasswd-pbkdf2
   ```
   Copy the resulting hash and insert it into:
   ```bash
   GRUB_PASSWORD_HASH="grub.pbkdf2.sha512.10000.XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
   ```

3. The script will automatically update `/etc/grub.d/40_custom` and regenerate the GRUB config.

> ⚠️ Make sure to test GRUB changes carefully. A misconfigured bootloader can prevent system startup.

---

## ⚙️ Customization Options

You can customize the script by editing variables and toggling modules:

- **GRUB password**: Set your own hash as shown above
- **Excluded services**: Comment out functions for services you want to keep
- **Audit rules**: Modify or extend auditd configurations
- **Firewall settings**: Adjust UFW rules to match your network policy
- **Password policies**: Tune `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_WARN_AGE` in `/etc/login.defs`

---

## ⚠️ Important Precautions

> **Before running this script:**

- 🧷 **Take a snapshot or full backup** of your system. CIS hardening modifies critical system settings and may impact services, user access, or compatibility with existing applications.
- 🧪 **Test on a non-production machine** first to evaluate the impact.
- 🔍 **Review the script manually** if you have custom configurations or sensitive workloads.

---

## 📄 License

This project is licensed under the [MIT License](https://github.com/behnam0x/cis-ubuntu-24.04-apply-script/blob/main/LICENSE). Feel free to modify and share.

---

## 🙋‍♂️ Contributions

Pull requests and suggestions are welcome! If you have improvements, additional CIS rules, or want to adapt this for other Ubuntu versions, feel free to contribute.

---

## 🌐 Related Resources

- [CIS Benchmark for Ubuntu Linux](https://www.cisecurity.org/benchmark/ubuntu_linux)


