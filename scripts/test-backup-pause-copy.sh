#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
kind_node=goauthy-pause-copy-$(openssl rand -hex 6)
cleanup() {
 status=$?
 trap - 0 1 2 15
 docker rm -f "$kind_node" >/dev/null 2>&1 || true
 rm -rf "$work"
 exit "$status"
}
trap cleanup 0 1 2 15
awk '/^copy_scheduled_backup_observer_file\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { capture=0 }' "$root/scripts/e2e-kind-backup-restore.sh" >"$work/helper.sh"
. "$work/helper.sh"
docker run -d --name "$kind_node" --tmpfs /tmp:noexec busybox:1.36.1 sleep 120 >/dev/null
printf 'observer\000bytes\n' >"$work/input"
copy_scheduled_backup_observer_file "$work/input" /tmp/observer
 docker exec "$kind_node" cat /tmp/observer >"$work/output"
cmp "$work/input" "$work/output"
[ "$(docker exec "$kind_node" stat -c '%a' /tmp/observer)" = 600 ]
printf '%s\n' 'Observer copy into live tmpfs preserves bytes and private mode'

printf '#!/bin/sh\nprintf observer-executable\n' >"$work/executable"
docker exec "$kind_node" mkdir -p /usr/local/bin
copy_scheduled_backup_observer_file "$work/executable" /usr/local/bin/observer
docker exec "$kind_node" chmod 0700 /usr/local/bin/observer
[ "$(docker exec "$kind_node" /usr/local/bin/observer)" = observer-executable ]
printf '%s\n' 'Observer executes outside noexec tmpfs'
