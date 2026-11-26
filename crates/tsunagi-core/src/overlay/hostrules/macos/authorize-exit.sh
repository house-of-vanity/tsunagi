# Invoked by the system authorization dialog. Each argument is a distinct
# quoted word. The helper body is embedded in the calling binary at build time.
set -eu
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C
umask 077
uid=$1
key=$2
helper_body=$3
case "$uid" in ''|*[!0-9]*) exit 1;; esac
case "$key" in ''|*[!0-9._]*) exit 1;; esac
directory=/private/etc/tsunagi-exit
helper="$directory/offer-v1"
/bin/mkdir -p "$directory" /private/etc/sudoers.d
/bin/chmod 0755 "$directory"
tmp=$(/usr/bin/mktemp -d "$directory/.install.XXXXXXXX")
trap '/bin/rm -rf "$tmp"' EXIT
printf '%s' "$helper_body" > "$tmp/offer"
printf '#%s ALL = (root) NOPASSWD: NOSETENV: %s\n' "$uid" "$helper" > "$tmp/rule"
/usr/sbin/visudo -c -q -f "$tmp/rule"
/bin/chmod 0755 "$tmp/offer"
/bin/chmod 0440 "$tmp/rule"
/bin/mv -f "$tmp/offer" "$helper"
/bin/mv -f "$tmp/rule" "/private/etc/sudoers.d/tsunagi-exit-$uid"
: > "$directory/grant_${uid}_$key"
