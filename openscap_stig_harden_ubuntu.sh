#!/bin/bash

# Ubuntu Security Hardening Script (Extended)
# Original Author: Alok Majumder
# Additional Modifications by: William Ileka
# GitHub: https://github.com/alokemajumder
# License: MIT License
#
# DISCLAIMER:
# This script is provided "AS IS" without warranty of any kind, express or implied. 
# By using this script, you agree that the author shall not be held liable for any damages 
# resulting from its use.

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

#-----------
# 1. Updates & Upgrades
#-----------
echo "Updating and upgrading installed packages..."
apt update && apt upgrade -y

#-----------
# 2. Install Essential Security Tools
#-----------
echo "Installing security tools..."
apt install -y aide auditd debsums apparmor apparmor-utils clamav clamav-daemon unattended-upgrades \
               ufw openscap-scanner fail2ban libpam-pwquality

#-----------
# 3. Configure AIDE
#-----------
echo "Configuring AIDE..."
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

#-----------
# 4. Configure Auditd
#-----------
echo "Backing up and configuring auditd..."
cp /etc/audit/auditd.conf /etc/audit/auditd.conf.backup
cat << 'EOF' > /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log
log_group = root
log_format = ENRICHED
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 20
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = HOSTNAME
max_log_file = 8
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
EOF
systemctl restart auditd

#-----------
# 5. Configure AppArmor
#-----------
echo "Configuring AppArmor..."
aa-enforce /etc/apparmor.d/*

#-----------
# 6. Configure ClamAV Scans
#-----------
echo "Scheduling ClamAV scans..."
echo "Please enter how often you want ClamAV scans to run (daily, weekly, monthly):"
read scan_frequency
cron_path="/etc/cron.$scan_frequency"
if [ ! -d "$cron_path" ]; then
  echo "Invalid frequency. Make sure you type daily, weekly, or monthly."
else
  echo "0 1 * * * root clamscan --infected --remove --recursive /" > "$cron_path/clamav_scan"
fi

#-----------
# 7. Configure Automatic Security Updates
#-----------
echo "Enabling unattended-upgrades..."
dpkg-reconfigure --priority=low unattended-upgrades

#-----------
# 8. Basic Firewall Setup (UFW)
#-----------
echo "Configuring UFW..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw --force enable

#-----------
# 9. Configure OpenSCAP
#-----------
echo "Configuring OpenSCAP scans..."
echo "Please enter how often you want OpenSCAP scans to run (daily, weekly, monthly):"
read oscap_frequency
oscap_cron_path="/etc/cron.$oscap_frequency"
if [ -d "$oscap_cron_path" ]; then
  cat << 'EOF' > "$oscap_cron_path/oscap_scan"
30 2 * * * root oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_standard \
  --report /var/log/oscap_report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu1804-ds.xml
EOF
fi

#-----------
# 10. SSH Hardening
#    (Disable root login, disable password auth, enforce key-based auth, etc.)
#-----------
echo "Hardening SSH settings..."

# Backup sshd_config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Update sshd_config
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/^#\?ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
# Optionally, set a non-default SSH port (e.g., 2222). Adjust firewall if you do:
# sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config
# ufw allow 2222

systemctl restart sshd

#-----------
# 11. PAM & Password Policies
#-----------
echo "Setting stronger password policies via PAM..."
cp /etc/pam.d/common-password /etc/pam.d/common-password.backup

# Configure libpam-pwquality (enforce complex passwords)
sed -i '/pam_pwquality.so/d' /etc/pam.d/common-password
echo 'password requisite pam_pwquality.so retry=3 minlen=12 difok=4 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' \
  >> /etc/pam.d/common-password

#-----------
# 12. Fail2Ban
#-----------
echo "Configuring Fail2Ban for SSH protection..."
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sed -i 's/^\[sshd\]/[sshd]\nenabled = true/' /etc/fail2ban/jail.local
systemctl enable fail2ban
systemctl start fail2ban

#-----------
# 13. Sysctl Hardening (Network & Kernel Hardening)
#-----------
echo "Applying sysctl tweaks for network security..."
cp /etc/sysctl.conf /etc/sysctl.conf.backup
cat << 'EOF' >> /etc/sysctl.conf

# Disable IP forwarding
net.ipv4.ip_forward=0

# Disable source routing
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0

# Log spoofed packets, source routed packets, redirects
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1

# Enable SYN flood protection
net.ipv4.tcp_syncookies=1

# Disable IPv6 if not needed (uncomment if IPv6 is unnecessary in your environment)
# net.ipv6.conf.all.disable_ipv6=1
# net.ipv6.conf.default.disable_ipv6=1
EOF

sysctl -p

#-----------
# 14. Final Report
#-----------
echo "Generating final report..."
cat << 'EOF' > /var/log/hardening_report.txt
System Hardening Completed
=========================

Steps Taken:
1. Installed and configured: AIDE, auditd, AppArmor, ClamAV, OpenSCAP, unattended upgrades, fail2ban, UFW.
2. SSH hardened: root login disabled, password auth disabled (key-based only), changed sshd_config parameters.
3. Password policy enforced using libpam-pwquality.
4. Sysctl hardened to reduce network-based attacks.
5. Scheduled scans for ClamAV and OpenSCAP.
6. Enabled fail2ban to reduce brute-force attempts.

Next Steps:
- Verify new SSH configuration (key-based login).
- Consider further customizing AppArmor profiles.
- Regularly check AIDE logs, auditd logs, fail2ban logs.
- Keep your applications & dependencies patched.
- Test your backups & disaster recovery plan.

EOF

echo "Ubuntu hardening process completed. Please review /var/log/hardening_report.txt."
exit 0
