#!/bin/sh
# run-agl-qemu.sh - launch the AGL head-unit VM for the canary lab.
#
# AGL plays the connected head-unit / telematics ECU (the "rich" Linux world).
# It reaches the Pi's Central Gateway (192.168.2.1:30509, SOME/IP) through QEMU
# user-mode NAT, so no host bridge is needed for the basic kill chain. SSH into
# the guest is forwarded to localhost:2222.
#
# Prereqs on the PC: qemu-system-x86_64 and the AGL demo image (.vmdk). Point
# AGL_IMG at your copy. KVM is used automatically when /dev/kvm exists.
set -e

MEM="${MEM:-4096}"

[ -f "$AGL_IMG" ] || { echo "AGL image not found: $AGL_IMG"; echo "set AGL_IMG=/path/to/agl-demo-platform-qemux86-64.vmdk"; exit 1; }

# KVM makes it fast. If /dev/kvm is missing (no nested virt), it falls back to TCG.
KVM=""
[ -e /dev/kvm ] && KVM="-enable-kvm -cpu host"

# Graphics: this AGL demo image (kernel 4.8-yocto) is old. Its Weston starts on
# either a DRM GPU (/dev/dri) or a plain framebuffer (/dev/fb0), so the video device
# just has to give it one. In QEMU, -vga cirrus gives the DRM path (cirrus is the
# image's only DRM driver). virtio-gpu gives neither in this image and stays black.
# (VirtualBox also works, via its VMSVGA controller and a VESA /dev/fb0 -> Weston's
# fbdev backend, see agl/README.) VGA_MODE=virtio is for newer AGL images.
VGA="-vga cirrus -display gtk"
[ "$VGA_MODE" = "virtio" ] && VGA="-device virtio-vga-gl -display gtk,gl=on"

# user-mode NAT (SLIRP): outbound traffic from the guest to 192.168.2.1 is routed
# through the host, so the guest reaches the Pi with no bridge. hostfwd exposes
# the guest's SSH on localhost:2222.
exec qemu-system-x86_64 $KVM -machine q35 -m "$MEM" -smp 2 \
  -drive file="$AGL_IMG",if=virtio,format=vmdk \
  -device virtio-net-pci,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  $VGA \
  -device qemu-xhci -device usb-tablet
