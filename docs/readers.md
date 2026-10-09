# Reader launch reference

How to launch each supported reader, organised by the specific **model** it was
tested on. Every RFIDIOt tool takes the same global reader-selection options
(they are parsed by `rfidiot/__init__.py` before the tool sees its own args), so
the commands below work with `rfidiot-cli.py`, `ChAP.py`, `mrpkey.py`,
`readtag.py`, and the rest. Run any tool with `-h` for the full option list.

## Global selector options at a glance

| Option | Meaning |
| --- | --- |
| `-f <n>` | libnfc device number `<n>` (implies `-R READER_LIBNFC`) |
| `-f <connstring>` | open a specific libnfc device directly, e.g. `pn53x_usb` or `pn53x_usb:003:087` (no intrusive probe that would grab other readers) |
| `-f ccid` / `-f ccid:<bus>:<dev>` | **direct-CCID ACR122U back-end** (talks straight to the PN532 over usbdevfs; for ACR122U units libnfc/pcscd misidentify) |
| `-r <n>` | PC/SC reader number `<n>` (implies `-R READER_PCSC`; subtype ACS/OMNIKEY/SCM auto-detected) |
| `-R READER_*` | select a reader type explicitly (e.g. `-R READER_CHAMELEON`) |
| `-l <port>` | serial port for the serial readers, e.g. `/dev/ttyUSB0` |
| `-N` | list libnfc devices and exit (does not open one) |
| `-L` | list PC/SC readers and exit |

Reader-type constants (`rfidiot/RFIDIOt.py`): `READER_ACG` 0x01, `READER_FROSCH`
0x02, `READER_DEMOTAG` 0x03, `READER_PCSC` 0x04, `READER_OMNIKEY` 0x05,
`READER_SCM` 0x06, `READER_ACS` 0x07, `READER_LIBNFC` 0x08, `READER_NONE` 0x09,
`READER_ANDROID` 0x10, `READER_CHAMELEON` 0x11.

## Quick model → launch table

| Model | Launch | Back-end | Status |
| --- | --- | --- | --- |
| **SCL3711** (PN53x USB) | `-f 0` or `-f pn53x_usb` | libnfc `pn53x_usb` | primary dev reader |
| **ACR122U / Touchatag (tikitag)** | `-f 0` | libnfc `acr122_usb` | EMV + ePassport verified |
| **ACR122U-WB-R** | `-f ccid` | direct CCID (usbdevfs) | EMV + ePassport verified |
| **OMNIKEY CardMan 5321** | `-r 0` (contact) / `-r 1` (contactless) | PC/SC (OMNIKEY) | dev reader |
| **Chameleon Ultra** | `-R READER_CHAMELEON` | serial (USB CDC) | EMV + 14443-A verified |
| **PN532 module** (emulator) | `pn532mitm.py` / `pn532emulate.py` | ACS / PC-SC | MITM relay verified |

---

## SCL3711 (libnfc PN53x USB stick)

The primary development reader. A standard libnfc PN53x device.

```sh
python3 rfidiot-cli.py -f 0 IDENTIFY          # first libnfc device
python3 rfidiot-cli.py -f pn53x_usb IDENTIFY  # by driver (first match)
python3 rfidiot-cli.py -f pn53x_usb:003:087   # a specific bus:dev
python3 rfidiot-cli.py -N                      # list libnfc devices
```

The in-kernel `pn533_usb` driver otherwise grabs these sticks; `linux/` holds a
udev rule and a modprobe blacklist so libnfc can claim it non-root.

## ACR122U / Touchatag (tikitag)

An older-firmware ACR122U (PID `072f:90cc`), driven through libnfc's
`acr122_usb` driver. libnfc opens it as the first (or numbered) device:

```sh
python3 ChAP.py -f 0 -c                        # contactless EMV + cert chain
python3 mrpkey.py -f 0 <MRZ>                   # ePassport
```

RFIDIOt auto-detects the ACR122U (by the `acr122` libnfc connstring prefix) and,
for ISO 14443-4 cards, takes over the T=CL block protocol in software so long
chained responses don't overflow the reader's reassembly buffer (the `63 27`
bug). No extra flag needed. `pcscd` must not be holding the reader.

**Verified:** full contactless EMV read incl. the chained 248-byte issuer
certificate (`ChAP.py -f 0 -c`); full ePassport incl. the 18 KB DG2
(`mrpkey.py -f 0 <MRZ>`).

## ACR122U-WB-R (direct-CCID back-end)

A newer retail ACR122U. It also enumerates with the ACR38 PID `072f:90cc`, and
**every off-the-shelf driver misidentifies it**: libnfc 1.8.0's `acr122_usb`
init fails ("Unable to open NFC device"), and libccid loads its ACR38 *contact*
driver and mis-negotiates the contactless card as T=0 (which then wedges the
reader). The PN532 behind it is fine, so RFIDIOt drives it directly over its
CCID bulk endpoints:

```sh
python3 ChAP.py -f ccid -c                     # first ACS reader
python3 mrpkey.py -f ccid:3:48 <MRZ>           # a specific bus:dev
```

`-f ccid` opens the first ACS (`072f:*`) USB device; `-f ccid:<bus>:<dev>` pins
one. `pcscd` **must be stopped** (`sudo systemctl stop pcscd pcscd.socket`) so
the back-end can claim the interface. Software T=CL (with the WTX timeout
extension) is auto-enabled for 14443-4, exactly as on the libnfc path. Only the
14443-A / ISO-7816 path is implemented on this back-end.

**Verified:** `ChAP.py -f ccid -c` (EMV + offline cert chain CA 1984 → Issuer
1408 → ICC 1024) and `mrpkey.py -f ccid <MRZ>` (BAC + secure messaging +
EF.COM/SOD/DG1/DG2/DG14, 18 KB DG2 via T=CL chaining, PA hashes OK).

## OMNIKEY CardMan 5321 (PC/SC)

A dual-interface PC/SC reader. The **contact** slot works with the open libccid
driver; the **contactless** (13.56 MHz) interface needs HID's proprietary
`ifdokccid` driver, which then appears as a *second* PC/SC slot:

```sh
python3 rfidiot-cli.py -L                      # list PC/SC readers + their index
python3 send_apdu.py -r 0 ...                  # contact slot
python3 ChAP.py -r 1 -c                         # contactless slot (HID driver)
```

Needs `pcscd` running (`sudo apt install pcscd libccid pcsc-tools`). The PC/SC
path handles both T=0 and T=1 cards and auto-detects the subtype
(ACS / OMNIKEY / SCM).

## Chameleon Ultra (serial)

Used as an ISO 14443-A reader over its USB CDC serial port:

```sh
python3 rfidiot-cli.py -R READER_CHAMELEON IDENTIFY
python3 ChAP.py -R READER_CHAMELEON -c
```

The USB CDC port is auto-detected by default. Type A only (no Type B). The same
software T=CL engine handles chained 14443-4 responses.

**Verified:** contactless EMV (`ChAP.py`) and 14443-A select/identify.

## PN532 module (emulator / MITM)

A bare PN532 breakout driven as a card emulator via the ACS / PC-SC path (not
libnfc), used by the MITM / emulation tools rather than the generic selectors:

```sh
python3 pn532mitm.py -r 1 0                     # emulator + reader, relay traffic
python3 pn532emulate.py ...
```

**Verified:** full ePassport MITM relay (BAC + secure messaging) over the ACS
path.

---

## Serial readers (ACG / Frosch / DemoTag) and Android

Supported but not hardware-tested in the Python 3 line:

```sh
python3 readtag.py -R READER_ACG    -l /dev/ttyUSB0
python3 readtag.py -R READER_FROSCH -l /dev/ttyUSB0
python3 readtag.py -R READER_ANDROID            # Android NFC over a socket
```

## Enumerate what's attached

```sh
python3 rfidiot-cli.py -N        # libnfc devices (numbers for -f)
python3 rfidiot-cli.py -L        # PC/SC readers (numbers for -r)
```
