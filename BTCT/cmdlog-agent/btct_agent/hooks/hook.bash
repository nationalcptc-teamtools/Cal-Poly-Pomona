# btct-cmdlog: bash capture hook (sourced from ~/.bashrc by `btct_agent install`).
#
# Appends a `pre` record before each typed command and a `post` record (exit +
# time) after it, to a per-PID spool file the daemon tails. Writing to a regular
# file never blocks, so a dead/slow daemon can never freeze this terminal.
#
# This is a hand-rolled DEBUG-trap hook. It defeats the classic pitfalls by
# ARMING in a PROMPT_COMMAND function that runs LAST, so the trap only fires for
# the first real command after a prompt: not for pipeline sub-commands, not for
# PROMPT_COMMAND's own internals, not during completion. If you prefer, drop in
# the upstream bash-preexec.sh and register __btct_preexec/__btct_precmd instead.
#
# Known limitation: a multi-line command is captured as its first line only
# (bash `history 1` + regex). Single-line commands (i.e. essentially all pentest
# tooling) are captured whole.

[ -n "${__BTCT_HOOK_LOADED:-}" ] && return 0
__BTCT_HOOK_LOADED=1
case "$-" in *i*) ;; *) return 0 ;; esac   # interactive shells only

__btct_dir="${XDG_RUNTIME_DIR:-/tmp}/btct-$(id -u)"
mkdir -p "$__btct_dir/spool" 2>/dev/null
chmod 700 "$__btct_dir" 2>/dev/null
__btct_spool="$__btct_dir/spool/shell.$$"
__btct_armed=""
__btct_eid=""

__btct_b64() { printf '%s' "$1" | base64 -w0 2>/dev/null || printf '%s' "$1" | base64 | tr -d '\n'; }
__btct_now() { printf '%s' "${EPOCHREALTIME:-$(date +%s)}"; }

__btct_emit_pre() {
    __btct_eid="$$-${RANDOM}-${SECONDS}"
    printf 'btct1\tpre\t%s\t%s\t%s\t%s\t%s\n' \
        "$__btct_eid" "$$" "$(__btct_now)" "$(__btct_b64 "$1")" "$(__btct_b64 "$PWD")" \
        >> "$__btct_spool" 2>/dev/null
}

__btct_debug() {
    [ -n "${COMP_LINE:-}" ] && return          # skip programmable completion
    [ -z "$__btct_armed" ] && return           # only the first command after a prompt
    __btct_armed=""                            # disarm so pipeline sub-commands don't refire
    local h line
    h=$(HISTTIMEFORMAT='' builtin history 1 2>/dev/null)
    if [[ "$h" =~ ^[[:space:]]*[0-9]+[[:space:]]+(.*)$ ]]; then
        line="${BASH_REMATCH[1]}"
    else
        line="$h"
    fi
    [ -n "$line" ] && __btct_emit_pre "$line"
}

__btct_precmd() {
    local ec=$?
    if [ -n "$__btct_eid" ]; then
        printf 'btct1\tpost\t%s\t%s\t%s\n' "$__btct_eid" "$ec" "$(__btct_now)" \
            >> "$__btct_spool" 2>/dev/null
        __btct_eid=""
    fi
    return "$ec"
}
# Arm as the very LAST step before the prompt: this is what confines the trap
# to the user's next real command.
__btct_arm() { __btct_armed=1; }

trap '__btct_debug' DEBUG
if [[ "$(declare -p PROMPT_COMMAND 2>/dev/null)" == "declare -a"* ]]; then
    # bash 5.1+ array PROMPT_COMMAND: precmd first, arm last.
    PROMPT_COMMAND=(__btct_precmd "${PROMPT_COMMAND[@]}" __btct_arm)
else
    PROMPT_COMMAND="__btct_precmd${PROMPT_COMMAND:+; $PROMPT_COMMAND}; __btct_arm"
fi
