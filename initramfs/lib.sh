# shellcheck shell=sh
# Functions shared by the door, the supervisor and the boot scripts. POSIX sh: busybox ash at boot,
# dash and busybox in the tests. Source paths.sh first.

# One line on the console, never fatal, with the seconds since boot.
tu_log() {
	tu_up=''
	read -r tu_up _ 2>/dev/null </proc/uptime || :
	printf 'tailnet-unlock: [%s] %s\n' "${tu_up:-?}" "$*" 2>/dev/null >>"$TU_CONSOLE" || :
}

# A JSON string for a value, or null when it is empty. Values here are machine tokens (dataset
# names, versions, fingerprints); any character outside that set becomes '?', so nothing can break
# out of the string.
tu_jstr() {
	if [ -z "${1-}" ]; then
		printf 'null'
		return 0
	fi
	printf '"%s"' "$(printf '%s' "$1" | tr -c 'A-Za-z0-9 _.:/@+=-' '?')"
}

# A JSON list of strings from a space-separated list of tokens.
tu_jlist() {
	tu_sep=''
	printf '['
	for tu_item in $1; do
		printf '%s' "$tu_sep"
		tu_jstr "$tu_item"
		tu_sep=','
	done
	printf ']'
}

# The first line of a file in the run directory, or empty.
tu_get() {
	tu_line=''
	[ -r "$TU_RUN/$1" ] && IFS= read -r tu_line <"$TU_RUN/$1"
	printf '%s' "$tu_line"
}

# Write one value to a file in the run directory: written beside it, then renamed. Fails (and
# leaves the old value and no temporary file) when the write does, as it does on a full tmpfs;
# every caller whose door depends on the value says so on the console.
tu_put() {
	if ( umask 077 && printf '%s\n' "$2" >"$TU_RUN/.$1.new" ) 2>/dev/null &&
		mv -f "$TU_RUN/.$1.new" "$TU_RUN/$1" 2>/dev/null; then
		return 0
	fi
	rm -f "$TU_RUN/.$1.new" 2>/dev/null
	return 1
}

# Add one to a counter in the run directory.
tu_count() {
	tu_n=$(tu_get "$1")
	tu_put "$1" "$(( ${tu_n:-0} + 1 ))"
}

tu_boot_id() {
	tu_id=''
	IFS= read -r tu_id 2>/dev/null <"$TU_BOOT_ID_FILE"
	printf '%s' "$tu_id"
}

# The state and parent of a process from /proc/<pid>/stat, as "<state> <ppid>". The command name
# sits in parentheses and may hold spaces, so the fields are read after the last ") ".
tu_stat() {
	tu_line=''
	IFS= read -r tu_line 2>/dev/null <"/proc/$1/stat" || return 1
	tu_rest=${tu_line##*) }
	tu_st=${tu_rest%% *}
	tu_rest=${tu_rest#* }
	printf '%s %s' "$tu_st" "${tu_rest%% *}"
}

# True while a process exists and is not a zombie.
tu_alive() {
	[ -n "${1-}" ] || return 1
	tu_sp=$(tu_stat "$1") || return 1
	case "$tu_sp" in
	'' | Z* | X*) return 1 ;;
	esac
	return 0
}

# Every descendant of a process, read from /proc by parent PID (never by name).
tu_descendants() {
	for tu_dir in /proc/[0-9]*; do
		tu_pid=${tu_dir#/proc/}
		tu_sp=$(tu_stat "$tu_pid") || continue
		[ "${tu_sp#* }" = "$1" ] || continue
		printf '%s\n' "$tu_pid"
		tu_descendants "$tu_pid"
	done
}

# True when a process is a number that can be signalled and its command line holds a name: a PID
# read from a file may belong to something else by now (PIDs are reused), and is never signalled.
tu_named() {
	[ -n "${2-}" ] || return 1
	case "${1-}" in
	'' | 0 | 1 | *[!0-9]*) return 1 ;;
	esac
	tu_cmd=$(tr '\0' ' ' 2>/dev/null <"/proc/$1/cmdline") || return 1
	case "$tu_cmd" in
	*"$2"*) return 0 ;;
	esac
	return 1
}

# Stop one process and its descendants: TERM, up to $2 seconds, then KILL. $3 is a word that must
# be in the process's command line (dropbear, tailscaled, supervise), so a recorded PID that the
# system has since given to another process is left alone.
tu_stop() {
	tu_target=${1-}
	[ -n "$tu_target" ] || return 0
	tu_named "$tu_target" "${3-}" || return 0
	tu_children=$(tu_descendants "$tu_target")
	# shellcheck disable=SC2086 # one PID per word, split on purpose
	kill -TERM "$tu_target" $tu_children 2>/dev/null || :
	tu_waited=0
	while tu_alive "$tu_target" && [ "$tu_waited" -lt "${2:-10}" ]; do
		sleep 1
		tu_waited=$((tu_waited + 1))
	done
	if tu_named "$tu_target" "$3"; then
		# shellcheck disable=SC2086 # one PID per word, split on purpose
		kill -KILL "$tu_target" $tu_children 2>/dev/null || :
	fi
	return 0
}

# Overwrite a file with zeros, then delete it.
tu_shred() {
	[ -f "$1" ] || return 0
	tu_size=$(wc -c 2>/dev/null <"$1") || tu_size=0
	dd if=/dev/zero of="$1" bs=1 count="${tu_size:-0}" conv=notrunc 2>/dev/null || :
	rm -f "$1"
}

# Stop both daemons from their recorded PIDs and delete the door material: the door key, the node
# state copy, the unseal work directories and the recovery key's copy. What stays is public or
# sealed and is on /boot beside the image anyway (the container, the authorized_keys, the
# configuration). Idempotent: the supervisor's TERM handler, init-bottom and the panic script all
# call it.
tu_wipe() {
	tu_stop "$(tu_get tailscaled.child)" 10 tailscaled
	tu_stop "$(tu_get dropbear.child)" 5 dropbear
	rm -f "$TU_RUN/tailscaled.child" "$TU_RUN/dropbear.child"
	tu_shred "$TU_RUN/door_key"
	tu_shred "$TU_RUN/unlock.state"
	tu_shred "$TU_ETC/recovery_host_key"
	for tu_dir in "$TU_RUN"/unseal.*; do
		[ -d "$tu_dir" ] || continue
		for tu_file in "$tu_dir"/*; do tu_shred "$tu_file"; done
		rmdir "$tu_dir" 2>/dev/null || :
	done
	rm -f "$TU_RUN/tailscaled.sock" "$TU_RUN/dropbear.pid"
}

# Ask the supervisor to stop (it wipes on TERM), then wipe anyway from the recorded PIDs.
tu_stop_supervisor() {
	tu_stop "$(tu_get supervise.pid)" "${1:-15}" supervise
	rm -f "$TU_RUN/supervise.pid"
	tu_wipe
}

# The noshell rule (DESIGN.md 7.3, exit paths): the measured profile, or the word on the command
# line, so an image without a valid configuration still keeps the shell shut.
tu_noshell() {
	[ "${TU_PROFILE-}" = measured ] && return 0
	tu_words=''
	read -r tu_words 2>/dev/null <"$TU_CMDLINE" || :
	case " $tu_words " in
	*" tailnet-unlock.noshell "* | *" tailnet-unlock.noshell=1 "*) return 0 ;;
	esac
	return 1
}
