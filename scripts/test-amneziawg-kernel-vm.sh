#!/bin/bash
# Disposable Debian test container only; never an installation path for netOS.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get -o APT::Update::Error-Mode=any update
apt-get install -y --no-install-recommends linux-image-amd64 linux-headers-amd64 \
  qemu-system-x86 busybox-static build-essential iproute2 kmod cpio gzip ca-certificates

work=$(mktemp -d /tmp/netos-awg-vm.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
root="$work/root"
mkdir -p "$root"/{bin,usr/bin,usr/sbin,proc,sys,dev,tmp,run,lib/modules}
chmod 1777 "$root/tmp"
cp -a /workspace/native-tools "$work/tools"
cp -a /workspace/native-kernel "$work/kernel"
kernel=$(find /lib/modules -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -V | tail -1)
test -n "$kernel"
test -d "/lib/modules/$kernel/build"
printf 'Guest kernel: %s\n' "$kernel"
make -C "$work/tools/src" -j2 LDFLAGS=-static
make -C "$work/kernel/src" -j2 KERNELRELEASE="$kernel" KERNELDIR="/lib/modules/$kernel/build"
cp -a "/lib/modules/$kernel" "$root/lib/modules/"
install -m 0644 "$work/kernel/src/amneziawg.ko" "$root/lib/modules/$kernel/"
depmod -b "$root" "$kernel"
install -m 0755 "$work/tools/src/wg" "$root/usr/bin/awg"
install -m 0755 /test-binary "$root/test-binary"
install -m 0755 /usr/bin/busybox "$root/bin/busybox"
ln -s busybox "$root/bin/sh"
install -m 0755 "$(command -v ip)" "$root/usr/sbin/ip"
# Copy only iproute2's runtime libraries, including the dynamic loader.
while IFS= read -r library; do
  cp -L --parents "$library" "$root"
done < <(ldd "$(command -v ip)" | awk '{for(i=1;i<=NF;i++) if($i ~ /^\//) print $i}')
mknod "$root/dev/console" c 5 1
mknod "$root/dev/null" c 1 3
cat > "$root/init" <<'INIT'
#!/bin/sh
export PATH=/usr/sbin:/usr/bin:/bin
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
if /bin/busybox modprobe amneziawg; then
  NETOS_AWG_KERNEL_TEST=1 NETOS_AWG_TOOLS_BINARY=/usr/bin/awg \
    /test-binary -test.run '^TestAmneziaWGNativeKernelContract$' -test.v -test.timeout 120s
  result=$?
else
  result=125
fi
echo "NETOS_AWG_VM_RESULT=$result"
/bin/busybox poweroff -f
INIT
chmod 0755 "$root/init"
(cd "$root" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 > "$work/initramfs.gz")
# TCG avoids any dependency on nested virtualization or privileged containers.
timeout 180s qemu-system-x86_64 -accel tcg -m 1536 -smp 2 \
  -kernel "/boot/vmlinuz-$kernel" -initrd "$work/initramfs.gz" \
  -append 'console=ttyS0 panic=-1' -display none -serial stdio -no-reboot -nic none \
  | tee "$work/console.log"
grep -qx 'NETOS_AWG_VM_RESULT=0' <(tr -d '\r' < "$work/console.log")
