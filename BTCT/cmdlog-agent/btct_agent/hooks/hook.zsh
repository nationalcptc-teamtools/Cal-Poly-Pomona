# btct-cmdlog: zsh capture hook (sourced from ~/.zshrc by `btct_agent install`).
#
# zsh gives preexec the typed command as $1 (full, multi-line preserved) and
# never fires on shell internals, so no arming gymnastics are needed. Records go
# to a per-PID spool file the daemon tails; a regular-file append never blocks,
# so a dead/slow daemon can't freeze the terminal.

[ -n "${__BTCT_HOOK_LOADED:-}" ] && return 0
__BTCT_HOOK_LOADED=1
[[ -o interactive ]] || return 0

zmodload zsh/datetime 2>/dev/null            # provides $EPOCHREALTIME
autoload -Uz add-zsh-hook

__btct_dir="${XDG_RUNTIME_DIR:-/tmp}/btct-$(id -u)"
mkdir -p "$__btct_dir/spool" 2>/dev/null
chmod 700 "$__btct_dir" 2>/dev/null
__btct_spool="$__btct_dir/spool/shell.$$"
__btct_eid=""

__btct_b64() { print -rn -- "$1" | base64 -w0 2>/dev/null || print -rn -- "$1" | base64 | tr -d '\n'; }

__btct_preexec() {
    __btct_eid="$$-${RANDOM}-${SECONDS}"
    printf 'btct1\tpre\t%s\t%s\t%s\t%s\t%s\n' \
        "$__btct_eid" "$$" "${EPOCHREALTIME:-$(date +%s)}" \
        "$(__btct_b64 "$1")" "$(__btct_b64 "$PWD")" >> "$__btct_spool" 2>/dev/null
}

__btct_precmd() {
    local ec=$?
    if [[ -n "$__btct_eid" ]]; then
        printf 'btct1\tpost\t%s\t%s\t%s\n' \
            "$__btct_eid" "$ec" "${EPOCHREALTIME:-$(date +%s)}" >> "$__btct_spool" 2>/dev/null
        __btct_eid=""
    fi
}

add-zsh-hook preexec __btct_preexec
add-zsh-hook precmd  __btct_precmd
