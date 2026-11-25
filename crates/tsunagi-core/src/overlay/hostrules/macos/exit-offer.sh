#!/bin/sh -p
# Privileged helper for a previously authorized local account and overlay range.
# The caller supplies no PF text, file names, executable paths or uplink.
set -eu
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C
umask 077
fail() { echo "Tsunagi exit sharing: $*" >&2; exit 1; }

uid=${SUDO_UID:-}
case "$uid" in ''|*[!0-9]*) fail 'missing local user';; esac
owner=${1:-}
case "$owner" in ''|*[!0-9]*) fail 'invalid agent PID';; esac
shift
process_stamp() {
    /bin/ps -p "$1" -o uid= -o lstart= | /usr/bin/awk '{$1=$1; print}'
}
stamp=$(process_stamp "$owner")
[ "${stamp%% *}" = "$uid" ] || fail 'agent PID does not belong to the authorized account'
[ "$#" -ge 2 ] && [ "$#" -le 3 ] || fail 'expected an operation and utun'
action=$1
iface=$2
case "$iface" in utun*) unit=${iface#utun};; *) fail 'expected a utun interface';; esac
case "$unit" in ''|*[!0-9]*) fail 'invalid utun number';; esac
[ "${#unit}" -le 8 ] || fail 'invalid utun number'
case "$action:$#" in clear:2|clear:3|apply:3|forward:3) ;; *) fail 'unknown operation';; esac

state=/private/var/run/tsunagi-exit
grants=/private/etc/tsunagi-exit
/bin/mkdir -p "$state"
prefix="tsng_${uid}_${unit}_"
lock="$state/$uid.lock"
/usr/bin/shlock -f "$lock" -p "$$" || fail 'another update is in progress'
trap '/bin/rm -f "$lock"' EXIT

read_record() {
    { IFS= read -r token && IFS= read -r saved_pid && IFS= read -r saved_stamp; } < "$1" || fail 'invalid PF ownership record'
    case "$token" in ''|*[!0-9]*) fail 'invalid PF ownership token';; esac
    case "$saved_pid" in ''|*[!0-9]*) fail 'invalid PF owner';; esac
}
clear_one() {
    record=$1
    [ -f "$record" ] || return 0
    name=${record##*/}
    anchor="com.apple/${name%.token}"
    read_record "$record"
    /sbin/pfctl -q -a "$anchor" -f /dev/null
    /sbin/pfctl -X "$token" >/dev/null
    /bin/rm -f "$record"
}

if [ "$#" = 2 ]; then
    # At startup the kernel can assign a different utun. Recover orphaned
    # anchors for this account, even after PID reuse, and leave live agents alone.
    for record in "$state/tsng_${uid}_"*.token; do
        [ -f "$record" ] || continue
        read_record "$record"
        if [ "$(process_stamp "$saved_pid")" != "$saved_stamp" ]; then
            clear_one "$record"
        elif [ "$saved_pid" = "$owner" ]; then
            case "${record##*/}" in "$prefix"*) clear_one "$record";; esac
        fi
    done
    exit 0
fi
range=$3
[ "${#range}" -le 18 ] || fail 'invalid IPv4 range'
case "$range" in ''|*[!0-9./]*|*/*/*) fail 'invalid IPv4 range';; */*) ;; *) fail 'missing prefix';; esac
key="${range%/*}_${range##*/}"
name="$prefix$key"
record="$state/$name.token"
if [ -f "$record" ]; then
    read_record "$record"
    if [ "$(process_stamp "$saved_pid")" != "$saved_stamp" ]; then
        clear_one "$record"
    elif [ "$saved_pid" != "$owner" ]; then
        fail 'another live agent owns this exit anchor'
    fi
fi
if [ "$action" = clear ]; then clear_one "$record"; exit 0; fi
[ -f "$grants/grant_${uid}_$key" ] || { echo 'Tsunagi exit sharing needs administrator approval' >&2; exit 1; }

# Verify the overlay's exact subnet and mask using the kernel's own address list.
/sbin/ifconfig "$iface" | /usr/bin/awk -v range="$range" '
    function ip(s, a, i, n) {
        if (split(s, a, ".") != 4) return -1
        for (i=1; i<=4; i++) {
            if (a[i] !~ /^[0-9]+$/ || a[i] > 255) return -1
            n = n*256 + a[i]
        }
        return n
    }
    BEGIN { split(range,a,"/"); base=ip(a[1]); p=a[2]; step=2^(32-p) }
    $1=="inet" && ip($2)>=0 && base>=0 && p~/^[0-9]+$/ && p<=30 {
        for (i=3; i<NF; i++)
            if ($i=="netmask" && tolower($(i+1))==sprintf("0x%08x",4294967296-step) &&
                int(ip($2)/step)==int(base/step)) found=1
    }
    END { exit !found }
' || fail 'the authorized range is not configured on this utun'

forward() {
    if [ "$(/usr/sbin/sysctl -n net.inet.ip.forwarding)" != 1 ]; then
        /usr/sbin/sysctl -w net.inet.ip.forwarding=1 >/dev/null || return 1
    fi
    [ "$(/usr/sbin/sysctl -n net.inet.ip.forwarding)" = 1 ]
}
if [ "$action" = forward ]; then forward; exit 0; fi

route=$(/sbin/route -n get default)
out=$(printf '%s\n' "$route" | /usr/bin/awk '$1=="interface:" {print $2; exit}')
case "$out" in ''|*[!a-zA-Z0-9]*) fail 'no usable default interface';; esac
[ "$out" != "$iface" ] || fail 'the default route uses this utun'
gateway=$(printf '%s\n' "$route" | /usr/bin/awk '$1=="gateway:" && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $2; exit}')
via=$out
if [ -n "$gateway" ]; then via="($out $gateway)"; fi
anchor="com.apple/$name"
tag="tsng_forward_$iface"
fresh=false
if [ ! -f "$record" ]; then
    message=$(/sbin/pfctl -E 2>&1) || fail "$message"
    token=$(printf '%s\n' "$message" | /usr/bin/awk -F: 'tolower($1) ~ /^token *$/ {gsub(/ /,"",$2); if ($2~/^[0-9]+$/) print $2}')
    case "$token" in ''|*[!0-9]*) fail 'PF did not return an ownership token';; esac
    if ! printf '%s\n' "$token" "$owner" "$stamp" > "$record"; then /sbin/pfctl -X "$token"; exit 1; fi
    fresh=true
fi
if ! /sbin/pfctl -q -a "$anchor" -f - <<RULES
nat on $out inet from $range to any tagged $tag -> ($out)
pass out quick on $iface route-to $via inet from any to any tagged $tag no state
pass in quick on $iface inet from $range to ! $range tag $tag no state
pass out quick on $out inet from any to any flags any tagged $tag keep state (if-bound)
RULES
then
    if "$fresh"; then clear_one "$record"; fi
    fail 'could not load the exit-sharing PF anchor'
fi
if ! forward; then clear_one "$record"; fail 'IPv4 forwarding is still off'; fi
