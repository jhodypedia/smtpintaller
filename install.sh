#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Auto Install SMTP Server for pansa.my.id (Ubuntu)
# Components: Postfix + Dovecot (SASL), Let's Encrypt TLS,
#             OpenDKIM, OpenDMARC, UFW rules
# Ports: 25, 587 (submission), 465 (smtps), 993 (imaps)
# Usage: sudo bash install_smtp.sh
# =========================================================

# --- Fixed domain config (custom for you) ---
DOMAIN="pansa.my.id"
POSTMASTER="postmaster@pansa.my.id"
USE_LE=1   # 1 = Let's Encrypt, 0 = self-signed

# --- Sanity checks ---
if [[ $EUID -ne 0 ]]; then
  echo "Harus dijalankan sebagai root (sudo)." >&2
  exit 1
fi

if [[ -z "${DOMAIN}" || -z "${POSTMASTER}" ]]; then
  echo "DOMAIN/POSTMASTER kosong. Periksa variabel di atas." >&2
  exit 1
fi

. /etc/os-release
if [[ "${ID}" != "ubuntu" ]]; then
  echo "Script ini untuk Ubuntu." >&2
  exit 1
fi

echo "[1/13] Update & install paket..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
  postfix postfix-pcre libsasl2-modules \
  dovecot-core dovecot-imapd dovecot-lmtpd dovecot-pop3d \
  opendkim opendkim-tools opendmarc \
  ufw rsyslog ca-certificates curl gnupg

if [[ $USE_LE -eq 1 ]]; then
  apt-get install -y certbot
fi

echo "[2/13] Set hostname & hosts..."
hostnamectl set-hostname "mail.${DOMAIN}" || true
if ! grep -q "mail.${DOMAIN}" /etc/hosts; then
  IPV4=$(curl -4 -s https://ifconfig.me || true)
  if [[ -z "${IPV4}" ]]; then IPV4="YOUR.SERVER.IP"; fi
  echo "${IPV4} mail.${DOMAIN} mail" >> /etc/hosts
fi

echo "[3/13] Konfigurasi Postfix dasar..."
postconf -e "myhostname = mail.${DOMAIN}"
postconf -e "mydomain = ${DOMAIN}"
postconf -e "myorigin = \$mydomain"
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = all"
postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost"
postconf -e "relay_domains ="
postconf -e "home_mailbox = Maildir/"
postconf -e "mailbox_command ="
postconf -e "smtpd_helo_required = yes"
postconf -e "disable_vrfy_command = yes"
postconf -e "smtpd_helo_restrictions = permit_mynetworks, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname"
postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination"
postconf -e "smtpd_client_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_rbl_client zen.spamhaus.org"
postconf -e "smtpd_sender_restrictions = reject_non_fqdn_sender, reject_unknown_sender_domain"
postconf -e "smtpd_relay_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination"

# SASL via Dovecot
postconf -e "smtpd_sasl_auth_enable = yes"
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"
postconf -e "smtpd_sasl_security_options = noanonymous"

# TLS placeholders
TLS_DIR="/etc/ssl/mail"
CERT_FILE="${TLS_DIR}/${DOMAIN}.crt"
KEY_FILE="${TLS_DIR}/${DOMAIN}.key"
mkdir -p "${TLS_DIR}"; chmod 700 "${TLS_DIR}"

echo "[4/13] Sertifikat TLS..."
if [[ $USE_LE -eq 1 ]]; then
  systemctl stop postfix || true
  systemctl stop dovecot || true
  # Gunakan standalone HTTP challenge; pastikan port 80 bebas
  certbot certonly --standalone \
    -d "${DOMAIN}" -d "mail.${DOMAIN}" \
    --agree-tos -m "${POSTMASTER}" -n || true
  CERT_FILE="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
  KEY_FILE="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
  if [[ ! -f "${CERT_FILE}" || ! -f "${KEY_FILE}" ]]; then
    echo "Let's Encrypt gagal. Periksa DNS/port 80. Anda bisa rerun script." >&2
    exit 1
  fi
else
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "${KEY_FILE}" -out "${CERT_FILE}" \
    -subj "/CN=mail.${DOMAIN}"
  chmod 600 "${KEY_FILE}"
fi

postconf -e "smtpd_tls_cert_file = ${CERT_FILE}"
postconf -e "smtpd_tls_key_file = ${KEY_FILE}"
postconf -e "smtpd_use_tls = yes"
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtp_tls_security_level = may"
postconf -e "smtpd_tls_auth_only = yes"
postconf -e "smtpd_tls_loglevel = 1"
# (opsional) protokol modern
postconf -e "smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1"

echo "[5/13] Enable submission (587) & smtps (465)..."
MASTER="/etc/postfix/master.cf"
cp -a "$MASTER" "$MASTER.bak.$(date +%s)"
# aktifkan submission blok default (umumnya ter-comment)
sed -ri 's/^#(submission\s+inet)/\1/' "$MASTER" || true
sed -ri 's/^#(\s+-o syslog_name=postfix\/submission)/\1/' "$MASTER" || true
sed -ri 's/^#(\s+-o smtpd_tls_security_level=encrypt)/\1/' "$MASTER" || true
sed -ri 's/^#(\s+-o smtpd_sasl_auth_enable=yes)/\1/' "$MASTER" || true
sed -ri 's/^#(\s+-o smtpd_client_restrictions=permit_sasl_authenticated,reject)/\1/' "$MASTER" || true
# tambahkan smtps jika belum ada
if ! grep -qE '^[ ]*smtps[ ]+inet' "$MASTER"; then
cat >> "$MASTER" <<'EOF'

smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
EOF
fi

echo "[6/13] Konfigurasi Dovecot (SASL + TLS + Maildir)..."
D10AUTH="/etc/dovecot/conf.d/10-auth.conf"
D10SSL="/etc/dovecot/conf.d/10-ssl.conf"
D10MASTER="/etc/dovecot/conf.d/10-master.conf"
D10MAIL="/etc/dovecot/conf.d/10-mail.conf"

sed -ri 's/^#?disable_plaintext_auth\s*=.*/disable_plaintext_auth = yes/' "$D10AUTH"
sed -ri 's/^#?auth_mechanisms\s*=.*/auth_mechanisms = plain login/' "$D10AUTH"

sed -ri "s|^#?ssl\s*=.*|ssl = required|" "$D10SSL"
sed -ri "s|^#?ssl_cert\s*=.*|ssl_cert = <${CERT_FILE}|" "$D10SSL"
sed -ri "s|^#?ssl_key\s*=.*|ssl_key = <${KEY_FILE}|" "$D10SSL"

# auth socket untuk postfix
if ! grep -q "/var/spool/postfix/private/auth" "$D10MASTER"; then
  cp -a "$D10MASTER" "$D10MASTER.bak.$(date +%s)"
  sed -i '/^service auth {/,/^}/ d' "$D10MASTER"
  cat >> "$D10MASTER" <<'EOF'
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF
fi

# Maildir di home user
sed -ri 's|^#?mail_location\s*=.*|mail_location = maildir:~/Maildir|' "$D10MAIL"

echo "[7/13] Konfigurasi OpenDKIM..."
mkdir -p /etc/opendkim/keys/"${DOMAIN}"
chown -R opendkim:opendkim /etc/opendkim
chmod go-rwx /etc/opendkim/keys/"${DOMAIN}"

if [[ ! -f /etc/opendkim/keys/"${DOMAIN}"/mail.private ]]; then
  sudo -u opendkim opendkim-genkey -D /etc/opendkim/keys/"${DOMAIN}"/ -d "${DOMAIN}" -s mail
  chown opendkim:opendkim /etc/opendkim/keys/"${DOMAIN}"/mail.private
fi

KEYTABLE="/etc/opendkim/key.table"
SIGNINGTABLE="/etc/opendkim/signing.table"
TRUSTEDHOSTS="/etc/opendkim/trusted.hosts"

cat > "$KEYTABLE" <<EOF
mail._domainkey.${DOMAIN} ${DOMAIN}:mail:/etc/opendkim/keys/${DOMAIN}/mail.private
EOF
cat > "$SIGNINGTABLE" <<EOF
*@${DOMAIN} mail._domainkey.${DOMAIN}
EOF
cat > "$TRUSTEDHOSTS" <<EOF
127.0.0.1
localhost
mail.${DOMAIN}
${DOMAIN}
EOF

OPENDKIM_CONF="/etc/opendkim.conf"
cp -a "$OPENDKIM_CONF" "$OPENDKIM_CONF.bak.$(date +%s)"
sed -ri 's/^#?UMask.*/UMask                  007/' "$OPENDKIM_CONF"
sed -ri 's|^#?KeyTable.*|KeyTable              /etc/opendkim/key.table|' "$OPENDKIM_CONF"
sed -ri 's|^#?SigningTable.*|SigningTable          refile:/etc/opendkim/signing.table|' "$OPENDKIM_CONF"
sed -ri 's|^#?ExternalIgnoreList.*|ExternalIgnoreList   refile:/etc/opendkim/trusted.hosts|' "$OPENDKIM_CONF"
sed -ri 's|^#?InternalHosts.*|InternalHosts         refile:/etc/opendkim/trusted.hosts|' "$OPENDKIM_CONF"
if ! grep -q '^Socket\s\+inet:8891@localhost' "$OPENDKIM_CONF"; then
  echo "Socket                 inet:8891@localhost" >> "$OPENDKIM_CONF"
fi

# Kaitkan milter ke Postfix
postconf -e "milter_default_action = accept"
postconf -e "milter_protocol = 6"
postconf -e "smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8893"
postconf -e "non_smtpd_milters = inet:127.0.0.1:8891, inet:127.0.0.1:8893"

echo "[8/13] Konfigurasi OpenDMARC..."
OPENDMARC_CONF="/etc/opendmarc.conf"
cp -a "$OPENDMARC_CONF" "$OPENDMARC_CONF.bak.$(date +%s)" || true
sed -ri "s|^#?AuthservID.*|AuthservID mail.${DOMAIN}|" "$OPENDMARC_CONF"
sed -ri "s|^#?TrustedAuthservIDs.*|TrustedAuthservIDs mail.${DOMAIN}, mail|" "$OPENDMARC_CONF"
sed -ri "s|^#?IgnoreHosts.*|IgnoreHosts /etc/opendkim/trusted.hosts|" "$OPENDMARC_CONF"
sed -ri "s|^#?Socket.*|Socket inet:8893@localhost|" "$OPENDMARC_CONF"

echo "[9/13] Enable & start services..."
systemctl enable opendkim opendmarc dovecot postfix
systemctl restart opendkim
systemctl restart opendmarc
systemctl restart dovecot
systemctl restart postfix

if [[ $USE_LE -eq 1 ]]; then
  echo "[10/13] Enable auto-renew certificate..."
  systemctl enable certbot.timer || true
  systemctl start certbot.timer || true
fi

echo "[11/13] Buat user autentikasi SMTP (mailuser)..."
if ! id -u mailuser >/dev/null 2>&1; then
  useradd -m -s /usr/sbin/nologin mailuser || true
fi
RAND_PASS="$(openssl rand -base64 12)"
echo "mailuser:${RAND_PASS}" | chpasswd
echo "${RAND_PASS}" > /root/.mailuser_init_password
chmod 600 /root/.mailuser_init_password

echo "[12/13] Firewall (UFW)..."
ufw allow 25/tcp || true
ufw allow 587/tcp || true
ufw allow 465/tcp || true
ufw allow 993/tcp || true
ufw allow OpenSSH || true
yes | ufw enable || true

echo "[13/13] Cetak ringkasan & DNS..."
DKIM_TXT_FILE="/etc/opendkim/keys/${DOMAIN}/mail.txt"
DKIM_RECORD="(DKIM file belum ditemukan)"
if [[ -f "${DKIM_TXT_FILE}" ]]; then
  DKIM_RECORD="$(sed -e 's/[[:space:]]\+/ /g' "${DKIM_TXT_FILE}")"
fi

cat <<SUMMARY

==================== INSTALASI SELESAI ====================

Domain     : ${DOMAIN}
Hostname   : mail.${DOMAIN}
SASL User  : mailuser
Password   : $(cat /root/.mailuser_init_password)

Ports      : 25 (SMTP), 587 (Submission STARTTLS), 465 (SMTPS), 993 (IMAPS)

TLS        : $([[ $USE_LE -eq 1 ]] && echo "Let's Encrypt" || echo "Self-signed")
Cert file  : ${CERT_FILE}
Key file   : ${KEY_FILE}

Tambahkan DNS berikut (di panel DNS Anda):

1) A record
   ${DOMAIN}         -> IP_SERVER
   mail.${DOMAIN}    -> IP_SERVER

2) MX record
   ${DOMAIN}.  IN  MX 10 mail.${DOMAIN}.

3) SPF (TXT)
   ${DOMAIN}.  IN  TXT "v=spf1 a mx ~all"

4) DKIM (TXT) — selector: mail
   Nama  : mail._domainkey.${DOMAIN}
   Nilai : ${DKIM_RECORD}

5) DMARC (TXT)
   _dmarc.${DOMAIN}.  IN  TXT "v=DMARC1; p=quarantine; rua=mailto:${POSTMASTER}; ruf=mailto:${POSTMASTER}; adkim=s; aspf=s"

Konfigurasi klien/aplikasi SMTP:
  Host       : mail.${DOMAIN}
  Port       : 587 (STARTTLS) atau 465 (SSL/TLS)
  Username   : mailuser
  Password   : (lihat di atas)
  TLS/SSL    : Wajib

Cek layanan:
  systemctl status postfix dovecot opendkim opendmarc
Log:
  tail -f /var/log/mail.log

Catatan:
- Jika pakai Cloudflare, set 'mail.${DOMAIN}' = DNS only (bukan proxied).
- Tunggu propagasi DNS untuk DKIM/DMARC (biasanya menit-jam).
- Ganti password 'mailuser' setelah uji coba:  sudo passwd mailuser

===========================================================

SUMMARY
