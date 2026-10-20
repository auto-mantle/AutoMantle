#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
fail() {
    echo "STORAGE_FAILED: $*"
    sync
    /sbin/poweroff -f
    while :; do sleep 1; done
}
test "$(ls /sys/class/net)" = lo || fail 'unexpected network interface'
mount /dev/vdb /mnt || fail 'scratch cannot mount'
test ! -e /mnt/scratch-state || fail 'scratch leaked across runs'
echo disposable > /mnt/scratch-state || fail 'scratch is not writable'
case "$(cat /proc/cmdline)" in
    *storage_test=prepare*)
        echo installed-harness > /storage-installation || fail 'root is not writable'
        echo synthetic-login > /storage-login || fail 'login state cannot save'
        ;;
    *)
        test "$(cat /storage-installation)" = installed-harness || fail 'installation was lost or mutated'
        test "$(cat /storage-login)" = synthetic-login || fail 'login state was lost'
        test ! -e /storage-task || fail 'task workspace leaked'
        case "$(cat /proc/cmdline)" in
            *storage_test=runtime*|*storage_test=hang*)
                echo task > /storage-task || fail 'runtime root is not writable'
                echo changed > /storage-installation || fail 'runtime root is not writable'
                ;;
        esac
        ;;
esac
sync
echo STORAGE_OK
case "$(cat /proc/cmdline)" in
    *storage_test=terminal*) /bin/sh -i </dev/ttyS0 >/dev/ttyS0 2>&1; sync; /sbin/poweroff -f ;;
    *storage_test=hang*) while :; do sleep 1; done ;;
esac
/sbin/poweroff -f
while :; do sleep 1; done
