# RFIDIOt Linux helpers (udev rules, modprobe blacklist)

Install everything with:

```sh
sudo ./linux/install.sh
# then unplug/replug the reader(s)
```

or copy the individual files by hand (each file has its own install note at the
top). The pieces:

## `42-libnfc-scl3711.rules`
Gives the `plugdev` group read/write on PN53x USB readers (SCM SCL3711, ACS
ACR122U, NXP PN533/SCL3710) so **libnfc** - and RFIDIOt via `pynfc` - can claim
them without `sudo`.

## `blacklist-libnfc.conf`
Stops the in-kernel `pn533_usb`/`pn533`/`nfc` drivers from grabbing PN53x readers
on plug-in (otherwise libnfc fails with *"Unable to set USB configuration"*).
Disables the in-kernel NFC subsystem system-wide; remove the file to restore it.

## `42-elatec-twn4.rules`
Two fixes for the **ELATEC TWN4**:

1. **No USB autosuspend** (`power/control="on"`). In CCID / PC-SC firmware the
   TWN4 drops off the bus when auto-suspended and re-enumerates repeatedly, so
   its device number keeps changing and opening the node fails with `EIO`.
   Pinning it awake makes it stable - for ordinary `pcscd` / `-r <n>` use **and**
   for the raw-CCID path.
2. **`plugdev` access** to the USB node, so RFIDIOt's raw-CCID backend can open
   it without `sudo`.

### Reader modes / how RFIDIOt drives a TWN4

The firmware flashed on the TWN4 decides how it appears and which option to use:

| Firmware | USB id | Appears as | RFIDIOt option |
| --- | --- | --- | --- |
| Simple Protocol (`PRS…`) | `09d8:0420` | serial CDC (`/dev/ttyACM*`) | `-R READER_TWN4` |
| PC-SC / CCID (`NPF…/S1SC…`) | `09d8:0427`/`0428` | CCID smart-card reader | `-r <n>` (via pcscd), or `-r ccid[:bus:dev]` (raw, no pcscd) |

**Raw CCID vs pcscd:** `-r ccid[:bus:dev]` talks straight to the reader's CCID
bulk endpoints over usbdevfs (no daemon). It needs the reader free, so stop the
daemon first:

```sh
sudo systemctl stop pcscd pcscd.socket   # socket too, or it respawns pcscd
```

Find the `bus:dev` with `lsusb` (e.g. `Bus 003 Device 057` → `-r ccid:3:57`), or
just `-r ccid` for the first CCID reader. Standard `-r <n>` use needs pcscd
running, as usual.
