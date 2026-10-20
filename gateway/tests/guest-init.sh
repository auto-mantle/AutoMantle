#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
fail() {
    echo "AUTOMANTLE_TEST_FAILED: $*"
    /sbin/poweroff -f
    while :; do sleep 1; done
}
test "$(ls /sys/class/net)" = lo || fail 'unexpected guest network interface'
test -b /dev/vdb || fail 'scratch disk missing'
if touch /automantle-should-not-be-writable 2>/dev/null; then
    fail 'root disk is writable'
fi
mount /dev/vdb /mnt || fail 'cannot mount scratch'
test ! -e /mnt/previous-run || fail 'scratch leaked across runs'
printf 'private workspace\n' > /mnt/previous-run || fail 'cannot write scratch'
sync
echo AUTOMANTLE_ISOLATION_OK
case "$(cat /proc/cmdline)" in
    *automantle_test=hang*) while :; do sleep 1; done ;;
    *automantle_test=delay*) sleep 8 ;;
esac
echo AUTOMANTLE_TEST_OK
/sbin/poweroff -f
while :; do sleep 1; done
