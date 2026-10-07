# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

RFIDIOt is a collection of Python tools and a shared library for exploring RFID/NFC
technology (author: Adam Laurie, http://rfidiot.org/). The repo is a research toolkit:
a single reader-abstraction library plus many small, self-contained command-line
scripts that each perform one RFID task (read/write/clone tags, dump MIFARE, read
ePassports, read contactless EMV cards, brute-force keys, emulate cards, etc.).

**This is Python 3.** `master` is now the Python 3 toolkit; the original Python 2.7
code is archived on the `python2.7` branch (tag `v1.0-python2.7`). The initial Python
3 release is tagged `v1.0-python3`. Run everything with `python3`. Do not reintroduce
Python 2 idioms. The Python 3 port was largely the work of Pete Shipley (evilpete).

## Install / build / run

```sh
pip install -r requirements.txt     # pycryptodome, pyscard, cryptography
sudo python3 ./setup.py install     # installs the 'rfidiot' library + scripts
```

Some tools need extras: `mrpkey.py` uses Pillow (PIL) to display passport photos and
`openssl` for certificate handling; `passiveauth.py` uses `openssl` for all
certificate/CMS handling (no third-party crypto lib);
`jcoptool.py` needs `pyasn1`. libnfc must be installed (shared library) for libnfc
readers; PC/SC readers need the daemon + CCID driver and the daemon running
(`sudo apt install pcscd libccid pcsc-tools` on Debian/Ubuntu). The PC/SC path
handles both T=0 and T=1 cards. Note: the OMNIKEY CardMan 5321's contact slot works
with libccid, but its contactless interface needs HID's proprietary driver
(ifdokccid); once installed the contactless appears as a second PC/SC slot (`-r 1`).

There is no unit-test suite and no CI. The `test*.sh` scripts are hardware
smoke-tests against a physically-connected reader. The `Makefile` only automates
uploading JavaCard applets via `gpshell` — it does not build the Python code.
`mrpkey.py -n TEST` reproduces the ICAO 9303 BAC/secure-messaging worked example with
no reader, which is the quickest way to sanity-check crypto changes.

Run any tool directly against an attached reader, e.g.:

```sh
python3 readtag.py                          # default reader (from config)
python3 rfidiot-cli.py -f 0 SELECT DUMP 00 0f   # libnfc device 0
python3 mrpkey.py -g -f 0 <MRZ-key>         # read an ePassport over libnfc
```

Reader selection: `-R READER_*` picks a reader type; `-f <n>` selects libnfc device
`<n>` (implies `READER_LIBNFC`); `-r <n>` selects a PC/SC reader; `-N` lists libnfc
devices, `-L` lists PC/SC devices. `-h` on any tool prints the full option list.

## Architecture

Three layers:

1. **`rfidiot/RFIDIOt.py`** — the `rfidiot` class (the whole library). It abstracts
   every supported reader behind one API and implements the protocol logic (ISO 7816
   APDUs, MIFARE Classic/Ultralight, ISO 14443 A/B, Hitag, 125 kHz LF tags, ICAO 9303
   ePassport BAC/secure messaging). Reader dispatch is `if self.readertype ==
   self.READER_*` branches throughout — the reader-type constants (`READER_ACG`,
   `READER_PCSC`, `READER_LIBNFC`, `READER_FROSCH`, `READER_ANDROID`, `READER_DEMOTAG`,
   `READER_NONE`, and PC/SC subtypes `READER_ACS`/`READER_OMNIKEY`/`READER_SCM`) are
   class attributes. Adding reader support to a method usually means adding a branch.

2. **`rfidiot/__init__.py`** — the runtime entry point every client script imports.
   On `import rfidiot` it parses `sys.argv` global options, applies config overrides,
   instantiates the reader, and exposes two module globals:
   - `rfidiot.card` — a ready-to-use `RFIDIOt.rfidiot` instance
   - `rfidiot.args` — the remaining non-option command-line arguments
   Scripts consume these; they do not construct the reader themselves. NB: importing
   `rfidiot` (or any submodule, e.g. `from rfidiot.iso3166 import ...`) runs this and
   builds `rfidiot.card` from the current `sys.argv`. The parser only consumes the
   global reader options it knows (`_GLOBAL_OPTS`) and passes anything else through
   into `rfidiot.args`, so a tool can define its own options on top (it then
   `getopt`s `rfidiot.args` itself — see `ChAP.py`). `-h` prints the global options
   and exits (no reader needed).

3. **Client scripts** (repo root). Standard pattern:
   ```python
   import rfidiot
   card = rfidiot.card
   args = rfidiot.args
   card.info('toolname vX')
   card.select()
   ...  # card.readblock(), card.login(), card.send_apdu(), card.nfc.sendAPDU(), etc.
   ```
   Notable tools:
   - `mrpkey.py` — flagship ePassport reader/decoder (BAC, secure messaging, DG1/DG2/…),
     with a Passive Authentication hook (see below). Add the `PACE` keyword after the
     MRZ to access the chip with PACE instead of BAC (via `rfidiot/pace.py`).
   - `rfidiot-cli.py` — general command dispatcher (`IDENTIFY`, `APDU`, `DUMP`,
     `MF AUTH/READ/WRITE/CLONE`, `SELECT`, `SCRIPT`); good reference for driving the library.
   - `ChAP.py` — "Chip And PIN": contact/contactless EMV reader. An ordinary client:
     it uses `rfidiot.card`, so reader selection is the standard global options
     (`-f <n>` libnfc, `-r <n>` PC/SC, `-R`); its own feature flags are parsed from
     `rfidiot.args`. Decodes the full EMV BER-TLV (PDOL-driven GPO, CVM list, etc.)
     and, with `-c`, recovers and verifies the SDA/DDA certificate chain against a
     bundled `CA_PUBLIC_KEYS` table.
     Run with no PIN argument to stay read-only (no `VERIFY`).
   - `passiveauth.py` — ePassport Passive Authentication: `passiveauth.py <EF_SOD.BIN>
     <masterlist.ml> [DG_DIR]`. Verifies DG hashes + SOD←DS signature + DS←CSCA against
     a public CSCA master list; `passive_authenticate()` returns `SAFE`/`TAMPERED`/
     `UNTRUSTED`/`None`. `mrpkey.py` calls it automatically when `$RFIDIOT_MASTERLIST`
     (or `~/.rfidiot/masterlist.ml`, `/etc/rfidiot/masterlist.ml`) is set, flagging the
     passport SAFE/UNSAFE.

### Support modules in `rfidiot/`
- `pace.py` — PACE (ICAO 9303 Part 11) access protocol: ECDH with Generic Mapping,
  3DES-CBC/AES secure messaging. Reader-agnostic (drives an `rfidiot.card`); uses
  pycryptodome's `ECC` for the curve maths. `mrpkey.py` calls it on the `PACE` keyword.
- `pynfc.py` — ctypes wrapper around the native **libnfc** shared library
  (`READER_LIBNFC`); libnfc enums/structs, aligned to libnfc 1.8. `sendAPDU()` is the
  raw transceive used for everything over libnfc.
- `pyandroid.py` — Android NFC device over a socket (`READER_ANDROID`).
- `pn532.py` — PN532 chipset constants/helpers.
- `iso3166.py` — country-code tables for the ePassport tools.
- `rfidiotglobals.py` — the global `Debug` flag shared across modules.

## Configuration

Reader defaults live in `rfidiot/__init__.py`. Override precedence: command-line
options > `$RFIDIOtconfig_opts` (path to an options file) > `./RFIDIOtconfig.opts` >
`/etc/RFIDIOtconfig.opts` > `$RFIDIOtconfig` (inline options string). The `.opts`
file holds a single line of options exactly as on the command line.

## Dependencies

Python 3 with `pycryptodome` (`Crypto.Cipher.DES/DES3`, `Crypto.Hash.SHA` — ePassport
BAC and EMV offline crypto) and `pyscard` (PC/SC; needs `pcscd`). `passiveauth.py`
does all its X.509/CMS/CSCA handling by shelling out to `openssl` (no Python crypto
library), which also makes it tolerant of real-world passport cert encoding quirks.
`pyserial` is imported lazily for serial
readers (ACG/Frosch/DemoTag). libnfc (shared library) is required for `READER_LIBNFC`.
Missing pyscard/pcscd only warns at import time.

## Conventions when editing

- **Data is passed around as hex strings** (uppercase on the PCSC/libnfc paths), and
  helpers on the `rfidiot` class do conversions: `ToHex`/`ToBinary` (bytes↔hex;
  `ToBinary` returns a **bytearray**), `ListToHex`, `ReadablePrint` (bytes/bytearray→
  printable ASCII), `ToBinaryString`. Mind the Py3 bytes/str/bytearray distinction:
  `data[i]` on bytes is an `int`, iterating bytes yields `int`s, `/` is float division
  (use `//` for indices/lengths), and `.decode/.encode("hex")` do not exist (use the
  helpers). See `docs/python3-typing-audit.md` for the recurring Py2→Py3 pitfalls.
- Reader-specific behavior belongs in `RFIDIOt.py` behind a `READER_*` branch, not in
  client scripts. Per `rfidiot-cli.py`'s header, scripts are deliberately written
  "longhand" for clarity so individual functions can be extracted.
- Hardware tooling: the primary dev reader is a libnfc PN53x (SCL3711). `linux/`
  holds a udev rule and a modprobe blacklist so libnfc can claim such readers
  non-root (the in-kernel `pn533_usb` driver otherwise grabs them).
- `TODO.md` tracks remaining work (DESFire script import, the typing sweep in the
  untested serial/socket tools, hardware-verification tasks).
