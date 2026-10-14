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
| `-r ccid` / `-r ccid:<bus>:<dev>` | **raw-CCID back-end** for a standard CCID reader (e.g. an ELATEC TWN4 in PC/SC firmware) straight over usbdevfs, no pcscd; stop pcscd first |
| `-R READER_*` | select a reader type explicitly (e.g. `-R READER_CHAMELEON`) |
| `-l <port>` | serial port for the serial readers, e.g. `/dev/ttyUSB0` |
| `-N` | list libnfc devices and exit (does not open one) |
| `-L` | list PC/SC readers and exit |

Reader-type constants (`rfidiot/RFIDIOt.py`): `READER_ACG` 0x01, `READER_FROSCH`
0x02, `READER_DEMOTAG` 0x03, `READER_PCSC` 0x04, `READER_OMNIKEY` 0x05,
`READER_SCM` 0x06, `READER_ACS` 0x07, `READER_LIBNFC` 0x08, `READER_NONE` 0x09,
`READER_ANDROID` 0x10, `READER_CHAMELEON` 0x11, `READER_TWN4` 0x12.

## Back-ends (what each launch option actually drives)

RFIDIOt has several reader back-ends. The option you pass selects the back-end,
not just the device - and for the ACR122U and the ELATEC TWN4 two different
back-ends exist, so the same hardware can be driven more than one way.

| Launch | Back-end | Transport | What it is |
| --- | --- | --- | --- |
| `-f <n>` / `-f <connstring>` | **libnfc** (`READER_LIBNFC`) | libnfc shared lib | any libnfc PN53x device (SCL3711, ACR122U via `acr122_usb`, …); raw frames + card emulation |
| `-f ccid` / `-f ccid:<bus>:<dev>` | **ACR122 direct-CCID** (`ACR122CCID`) | usbdevfs, **PN532 chip** | talks straight to the ACR122U's PN532 (PN532 commands wrapped in the reader's escape); the only route for the ACR122U-WB-R, and the route for emulation/MITM. Not for non-ACS readers |
| `-r <n>` | **PC/SC** (`READER_PCSC`, subtype auto-detected) | `pcscd` + libccid | any PC/SC smart-card reader; ISO 7816 APDUs (+ MIFARE pseudo-APDUs). Subtypes: ACS / OMNIKEY / SCM / generic |
| `-r ccid` / `-r ccid:<bus>:<dev>` | **raw CCID** (`CCIDDev`) | usbdevfs, **standard CCID** | any standard CCID reader (e.g. an ELATEC TWN4 in PC/SC firmware) driven directly, no `pcscd`; runs the whole PC/SC code path (select, EMV, ePassport, FF 86 MIFARE). Reader does the RF/T=CL itself. Stop `pcscd` first |
| `-R READER_TWN4` | **ELATEC Simple Protocol** (`pytwn4`) | serial (USB CDC / UART) | a TWN4 in Simple Protocol firmware; ISO 14443-A/B + APDU, software T=CL |
| `-R READER_CHAMELEON` | **Chameleon Ultra** | serial (USB CDC) | ISO 14443-A reader |
| `-R READER_ACG` / `READER_FROSCH` / `READER_DEMOTAG` | **serial** | serial (`-l <port>`) | legacy serial readers (ACG LFX for 125 kHz LF, Frosch Hitag, DemoTag) |
| `-R READER_ANDROID` | **Android** (`pyandroid`) | TCP socket | a phone running a companion app as the reader (dormant / Py3-broken - see TODO 15) |

The two **direct-CCID** paths are different protocols over the same USB plumbing:
`-f ccid` speaks the ACR122U's **PN532** (so it can emulate, and it can reach the
WB-R whose CCID face is only a contact slot); `-r ccid` speaks **standard CCID**
to any reader whose firmware already does the ISO work (so it is read-only, but
works on readers that are not PN532-based). Neither needs `pcscd`; `-r <n>` does.

## Reader launch methods

Every way RFIDIOt can drive each reader. Many readers have more than one method -
which you get depends only on the option you pass (and, for the TWN4, the firmware
flashed). See **Back-ends** above for what each back-end is; verified = exercised
on hardware in these sessions.

| Reader | Launch | Back-end | Verified / notes |
| --- | --- | --- | --- |
| **SCL3711** (`04e6:5591`) | `-f 0` / `-f pn53x_usb[:bus:dev]` | libnfc | primary dev reader; raw frames, MIFARE, UID emulation (`emulateuid`) and full ISO 14443-4 emulation/relay with a chosen UID (`relayuid`, host-side T=CL - so Type 4 works on a PN533) |
| | `-r <n>` | PC/SC, subtype SCM | needs SCM/Identiv's driver (libccid doesn't list `04e6:5591`); not verified |
| **ACR122U / Touchatag (tikitag)** | `-f 0` / `-f acr122_usb[:bus:dev]` | libnfc | EMV + ePassport + MIFARE verified |
| | `-r <n>` | PC/SC, subtype ACS | libccid "ACR122U PICC Interface" (`072f:2200`); used by `pn532emulate` / `pn532mitm` |
| | `-f ccid[:bus:dev]` | direct CCID (PN532) | stop `pcscd` first; emulation-capable |
| **ACR122U-WB-R** (`072f:90cc`) | `-f ccid[:bus:dev]` | direct CCID (PN532) | the **only** working route (libnfc won't open it; libccid IDs it as an ACR38 contact reader). EMV + ePassport + MIFARE + Type 4 emulation verified |
| **OMNIKEY CardMan 5321** | `-r 0` | PC/SC, subtype OMNIKEY | contact slot (libccid) |
| | `-r 1` | PC/SC, subtype OMNIKEY | contactless slot - needs HID's `ifdokccid` driver (appears as a 2nd slot) |
| **ELATEC TWN4** - *Simple Protocol fw* (`09d8:0420`) | `-R READER_TWN4` (`-l <port>` for UART) | ELATEC Simple Protocol (serial) | firmware `PRS…`; EMV + ePassport (A/B, BAC + PACE) verified |
| **ELATEC TWN4** - *PC/SC fw* (`09d8:0427`/`0428`) | `-r <n>` | PC/SC (via `pcscd`) | firmware `NPF…/S1SC…`; EMV + ePassport + MIFARE verified |
| | `-r ccid[:bus:dev]` | raw CCID (`CCIDDev`) | same firmware, straight over usbdevfs, **no `pcscd`** (stop it first); IDENTIFY + MIFARE + ePassport verified |
| **Chameleon Ultra** | `-R READER_CHAMELEON` | serial (USB CDC) | ISO 14443-A reader; EMV + 14443-A verified. Slot emulation via `chameleon.py` |
| **PN532 module** (bare) | `pn532emulate.py` / `pn532mitm.py` | ACS PC/SC or libnfc | card emulation / MITM relay (see those tools) |
| **ACG** (serial) | `-R READER_ACG -l <port>` | serial | incl. 125 kHz LF (LFX models); not hardware-tested in Py3 |
| **Frosch HTRM112** (serial) | `-R READER_FROSCH -l <port>` | serial | Hitag / 125 kHz; not hardware-tested in Py3 |
| **IAIK DemoTag** (serial) | `-R READER_DEMOTAG -l <port>` | serial | vestigial; not hardware-tested in Py3 |
| **Android phone** | `-R READER_ANDROID` | TCP socket (`pyandroid`) | companion-app reader; dormant / Py3-broken (see TODO 15) |

The firmware on a TWN4 decides its route: a Simple Protocol TWN4 is a serial
device, a PC/SC one is a CCID reader (driven via `pcscd` with `-r <n>` or directly
with `-r ccid`), and reflashing switches between them.

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

It can also be used as a PC/SC reader (`-r <n>`) with SCM/Identiv's proprietary
driver installed - see [Readers with more than one back-end](#readers-with-more-than-one-back-end).

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
extension) is auto-enabled for 14443-4, exactly as on the libnfc path. Both
ISO 14443-A and **14443-B** (e.g. Type B ePassports) are supported for ISO-7816;
Jewel and iClass are not.

**Verified:** `ChAP.py -f ccid -c` (EMV + offline cert chain CA 1984 → Issuer
1408 → ICC 1024) and `mrpkey.py -f ccid <MRZ>` (BAC + secure messaging +
EF.COM/SOD/DG1/DG2/DG14, 18 KB DG2 via T=CL chaining, PA hashes OK) on both a
Type A and a Type B ePassport.

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

## ELATEC TWN4 (Simple Protocol)

An ELATEC TWN4 (tested: TWN4 MultiTech 2, firmware `TWN4/B1.50/NCF5.25/PRS1.04/AV`)
running ELATEC's **Simple Protocol** app (`PRS` in the version string), used as
an ISO 14443-A/B reader:

```sh
python3 rfidiot-cli.py -R READER_TWN4 IDENTIFY
python3 ChAP.py -R READER_TWN4 -c
python3 mrpkey.py -R READER_TWN4 <MRZ> [PACE]
```

The USB CDC port is auto-detected (`09d8:0420`); for a true serial (UART) TWN4
pass the port with `-l`. The tool refuses a TWN4 whose firmware isn't the
Simple Protocol app; a TWN4 flashed with ELATEC's PC/SC firmware is a CCID
reader instead and is used with `-r <n>` (not verified here).

The TWN4's own ISO 14443-4 exchange (`ISO14443_4_TDX`) can return at most 255
bytes, and its own RATS asks for 256-byte frames, so long responses (EMV
certificate records) would fail. RFIDIOt therefore sends RATS itself (FSD 128)
and runs T=CL in software over raw `ISO14443_3_TDX` frames with host-side CRC,
the same engine as the ACR122U and Chameleon back-ends. Only ISO 14443-A/B
select + APDU are implemented so far (no MIFARE, LF, 15693, iCLASS, LEGIC yet).

**Verified:** `ChAP.py -c` (Debit Mastercard, all records incl. a 256-byte
issuer certificate record, chain CA 1984 → Issuer 1968 → ICC 1408) and
`mrpkey.py` on a Type B ePassport with BAC and with PACE (AES-256), 18 KB DG2,
PA hashes OK; `rfidiot-cli` IDENTIFY/SELECT/HSS/APDU, `cardselect`, `isotype`.

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

## Which tools work with which readers

What a tool can do depends on which back-end implements the library calls it
uses. This is from the code (the `READER_*` branches in `rfidiot/RFIDIOt.py` and
the tools' own reader checks); see the model sections above for what has been
hardware-verified.

### Capabilities by back-end

| Capability | libnfc (`-f <n>`) | direct CCID (`-f ccid`) | PC/SC (`-r <n>`) | Chameleon | TWN4 | ACG / Frosch serial | Android |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ISO 14443-A select / UID | yes | yes | yes | yes | yes | ACG yes | yes |
| ISO 14443-B select | yes | yes | card/driver dependent | no | yes | not checked | not checked |
| ISO 7816 APDUs | yes | yes | yes | yes | yes | no | yes |
| MIFARE Classic auth / read / write | yes | yes | yes (ACS, OMNIKEY) | yes | no | ACG yes | no |
| MIFARE Ultralight read | yes | yes | yes | yes | no | ACG yes | no |
| 125 kHz LF (EM4x02, Hitag 2, Q5, FDX-B) | no | no | no | no | no (not implemented yet) | yes | no |
| HID Prox / iCLASS | no | no | OMNIKEY only | no | no (not implemented yet) | no | no |
| Card emulation | PN53x target mode (incl. full Type 4 via `relayuid` host-side T=CL) | PN532 target mode | ACS (ACR122U) only | its own slots | no | no | no |

### Tools by what they need

| Needs | Tools | Readers |
| --- | --- | --- |
| a 14443 select | `cardselect.py`, `multiselect.py`, `isotype.py`, `rfidiot-cli.py` (IDENTIFY, SELECT) | any HF back-end |
| ISO 7816 APDUs | `ChAP.py`, `mrpkey.py`, `jcoptool.py`, `jcopsetatrhist.py`, `rfidiot-cli.py` (APDU, SCRIPT) | libnfc, direct CCID, PC/SC, Chameleon, TWN4 (Chameleon: Type A only) |
| | `jcopmifare.py` (uses `hsselect`) | libnfc, direct CCID, PC/SC |
| | `send_apdu.py` (uses the PC/SC APDU call directly) | PC/SC only |
| MIFARE Classic / Ultralight | `readmifare1k.py`, `readmifaresimple.py`, `writemifare1k.py`, `formatmifare1kvalue.py`, `loginall.py`, `bruteforce.py`, `copytag.py`, `readtag.py`, `readmifareultra.py`, `rfidiot-cli.py` (MF, DUMP) | libnfc, direct CCID, PC/SC, Chameleon, ACG - **not the TWN4** |
| 125 kHz LF | `lfxtype.py`, `readlfx.py`, `writelfx.py`, `q5reset.py`, `hitag2reset.py`, `hitag2brute.py`, and the write side of `unique.py`, `fdxbnum.py`, `transit.py` | ACG (LFX) and Frosch serial readers only |
| | `froschtest.py` | Frosch only |
| | `eeprom.py` | ACG only |
| HID Prox | `hidprox.py` | OMNIKEY (PC/SC) only |
| card emulation | `pn532emulate.py` | libnfc PN53x, or an ACR122U over PC/SC (`-r`) or `-f ccid`. Its **Type 4** path lets the chip run T=CL, so it needs a **PN532** (ACR122U): a **PN533** (SCL3711) hands the RATS up and is refused here — use `relayuid.py` for Type 4 on a PN533. Type 2 works on either. Over `-f ccid` it can't be interrupted mid-wait (a tool that stops early waits for any reader to be presented; a hard kill needs a replug) |
| | `emulateuid.py` | **libnfc PN53x only** (SCL3711): emulate any 4/7/10-byte UID at the ISO 14443-3 layer (beats the chip's hard-wired `08`), via AutoColl priming. UID layer only — no APDUs |
| | `relayuid.py` | **libnfc PN53x** emulator (SCL3711) presenting a chosen/cloned UID **and** full ISO 14443-4, with the host running T=CL in raw target mode (so Type 4 works on a PN533). Relays APDUs to a real card on a local reader (`-c ccid`/`eccid`/libnfc) or a remote agent (`-c tcp:HOST:PORT` + `relayuid -S`). Verified: passport (BAC/DG2) and EMV (cert chain), single-host and over a socket |
| | `pn532mitm.py` | the emulator side must be an ACR122U over PC/SC, or a libnfc / `-f ccid` ACR122U when it talks to the reader side over a socket (`reader:HOST:PORT`); the reader side must be ACS PC/SC, unless the emulator is remote (`emulator:HOST:PORT`) - then any reader that sends APDUs, Type A or B card. Emulator presents the fixed `08` UID (chip runs T=CL); for a chosen/cloned UID over a socket use `relayuid`. Verified: TWN4 reading a Type B ePassport, ACR122U-WB-R (`-f ccid`) emulating, SCL3711 as the victim |
| | `chameleon.py`, `rfidiot-cli.py` (CHAMELEON) | Chameleon Ultra only (`-R READER_CHAMELEON`) |
| other | `demotag.py` (IAIK DemoTag, vestigial), `nfcid.py` (Android only) | as named |
| no reader | `passiveauth.py`, `sod.py`, `mifarekeys.py`, `AID_lookup.py`, `AID-get-data.py`, the generate/decode side of `unique.py`, `fdxbnum.py`, `transit.py` | none |

## Enumerate what's attached

```sh
python3 rfidiot-cli.py -N        # libnfc devices (numbers for -f)
python3 rfidiot-cli.py -L        # PC/SC readers (numbers for -r)
```
