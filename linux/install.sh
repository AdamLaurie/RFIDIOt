#!/bin/sh
# install.sh - install RFIDIOt's Linux udev rules and modprobe blacklist.
#
# Run as root (it writes to /etc/udev/rules.d and /etc/modprobe.d):
#   sudo ./linux/install.sh
#
# What it installs (from this directory):
#   42-libnfc-scl3711.rules  - plugdev access to PN53x USB readers (SCL3711 etc.)
#   42-elatec-twn4.rules      - keep the ELATEC TWN4 awake (no autosuspend churn)
#                               + plugdev access for the raw-CCID backend
#   blacklist-libnfc.conf     - stop the in-kernel pn533 driver grabbing PN53x readers
#
# After running: unplug and replug any affected reader (or reboot) so the new
# rules apply. Add yourself to the plugdev group if you are not already in it:
#   sudo usermod -aG plugdev "$USER"   # then log out and back in
#
# To undo: remove the copied files from /etc/udev/rules.d and /etc/modprobe.d,
# then reload (udevadm) / replug.

set -eu

here=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (try: sudo $0)" >&2
    exit 1
fi

rules_dir=/etc/udev/rules.d
modprobe_dir=/etc/modprobe.d

echo "Installing udev rules into $rules_dir ..."
for r in 42-libnfc-scl3711.rules 42-elatec-twn4.rules; do
    install -m 0644 "$here/$r" "$rules_dir/$r"
    echo "  $r"
done

echo "Installing modprobe blacklist into $modprobe_dir ..."
install -m 0644 "$here/blacklist-libnfc.conf" "$modprobe_dir/blacklist-libnfc.conf"
echo "  blacklist-libnfc.conf"

echo "Reloading udev rules ..."
udevadm control --reload-rules
udevadm trigger

# Unload the in-kernel NFC modules now if present (the blacklist stops them
# auto-loading again); ignore failures if they are not loaded or are busy.
echo "Unloading in-kernel pn533/nfc modules (if loaded) ..."
modprobe -r pn533_usb pn533 nfc 2>/dev/null || true

cat <<'EOF'

Done. Now:
  - Unplug and replug each reader so the new rules take effect.
  - Make sure you are in the plugdev group (id -nG | grep plugdev); if not:
        sudo usermod -aG plugdev "$USER"    # then log out and back in
  - For the raw-CCID backend (rfidiot -r ccid[:bus:dev]) the reader must be
    free, so stop pcscd first:
        sudo systemctl stop pcscd pcscd.socket
    (standard PC/SC use with -r <n> needs pcscd running, as usual.)
EOF
