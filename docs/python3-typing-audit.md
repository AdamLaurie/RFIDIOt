# Python 3 data-typing audit (python3 branch)

Audit of the binary-vs-hex-vs-ascii type confusion introduced by the Python 2 → 3
port. In Python 2 `str` doubled as both bytes and text, so RFIDIOt freely mixed raw
bytes, hex strings, and `chr()`/`ord()` byte-strings behind the same variables and
helpers. Python 3 makes `bytes`, `bytearray`, and `str` distinct, so those mixed
assumptions now either crash or silently corrupt data.

## Root cause: no single contract for `card.data` / `uid` / `errorcode`

The same logical attribute holds a *different type depending on the reader path*:

| Attribute | ACG serial | FROSCH | PCSC / ACS | libnfc | Android |
|-----------|-----------|--------|-----------|--------|---------|
| `self.data` | **bytes** | hex str | hex str (UPPER) | hex str (UPPER) | **bytes** |
| `self.uid` | **bytes** | hex str | hex str | hex str (UPPER) | **bytes** |
| `self.errorcode` | **bytes** / int | hex str | hex str | hex str | **bytes** |

Consumers are written assuming **hex `str`** (e.g. `readblock` does
`int(self.data[x:x+2], 16)`, scripts slice hex pairs, `ToBinary(self.data)`), so the
`bytes` outliers — **ACG serial** and **Android socket** — break. This single
inconsistency is the source of most downstream bugs.

## Three conflated representations

1. **raw bytes** — pyserial `.read()/.readline()`, libnfc ctypes arrays, socket `recv`.
2. **hex text** — and even this is inconsistent: `ListToHex`/`%02X` produce UPPERcase,
   `ToHex`/`%02x` produce lowercase. `errorcode` is compared `==` against uppercase
   constants, so any lowercase/bytes assignment silently never matches.
3. **latin-1 "byte-string" `str`** — `self.binary`, `BitReverse`, `crc`, `crc16`,
   `frosch_bcc` built with `chr()`/`ord()`; a pure Py2 idiom.

The helpers `ToHex` / `ToBinaryString` / `ReadablePrint` / `NibbleReverse` contain
`isinstance(data, str) → encode latin-1` guards that **silently paper over** caller
type confusion (a hex string like `"DEADBEEF"` gets mis-encoded to `4445...` instead
of raising). These hide bugs rather than enforcing a contract.

## Findings by severity

### A. Hard crashes (AttributeError / TypeError on normal use)

- **`.decode("hex")` / `.encode("hex")`** — do not exist in Py3.
  - `rfidiot-cli.py`: L179 (DUMP), L187 (FILE), L281 (CLONE), L302, L335 (MF DUMP),
    L370 (MF READ), L441.
  - `mrpkey.py`: L645, L1716, L1734, L1738, L1748.
  - `hidprox.py`: L61, L78 (`pcsc_atr[6:].decode("hex")`).
- **True division `/` used as index / length / APDU Lc / format arg** — yields float.
  - `mrpkey.py`: pervasive (L629, L701, L804, L817, L894, L911, L946, L1044, L1059,
    L1668, L1690, L1770, L1894, L1896, L1901).
  - `transit.py` L99–101; `fdxbnum.py` L103–104; `pn532emulate.py` L126/132;
    `pn532mitm.py` L291/297; `jcopsetatrhist.py` L61/62/74. Fix: `//`.
- **`ord()` on already-int bytes elements / bytearray**
  - `mrpkey.py` L731, L739, L1718–1719, L1732; `jcoptool.py` L149;
    `pn532mitm.py` L91/107/113 (LRC); `Run_Test.py` L188.
  - Library: `BitReverse` (L2266, `ord(data[y])`), `crc` (L2168), `crc16` (L2181),
    `frosch_bcc` (L2052) all `ord()`-iterate and break on bytes. `BitReverse` is fed
    `ToBinary()` output (now a bytearray) via `HexBitReverse`/`HexToQ5` → broken chain.
- **`str + bytes` concatenation**
  - `fdxbnum.py` L75/139/156, `transit.py` (serial `card.data`); frosch read path
    `RFIDIOt.py` L2010–2050 (`ret = "" ; ret += self.ser.read(1)`).
- **Undefined name `rfidio`** (typo for `rfidiot`) — `RFIDIOt.py` L2150, L2155, L2160,
  L2165 (`EMToUnique*`, `HexToQ5`, `crcccitt`). NameError on first call.
- **`.uppper()` typo** — `transit.py` L73 (AttributeError).
- **Latent NameError** — `hidprox.py` L54–106: `fc`/`cn`/`octal` set only inside a
  matching `if prox ==` branch; unmatched input falls through to use them.

### B. Silent corruption (wrong output, no error)

- `_ReadablePrint` (L2348): given bytes, iterates ints → returns all dots.
- `BinaryToManchester` (L2448): given bytes, every bit treated as "1".
- `errorcode` type/case mismatches: `bytes`/lowercase/`int` assignments never `==`
  the uppercase string constants (`ISO_OK`, etc.), so error checks silently pass/fail
  wrong. `RFIDIOt.py` L1814 assigns a single **int** (`bytes[0]`) to errorcode.
- `self.MIFAREbinary` is `+=`'d (L1950/1963) but **never reset** in the method →
  accumulates across reads / possible AttributeError on first use.
- `ReadablePrint` originally missed `bytearray` (already fixed in commit 9819ef8).

### C. Cosmetic

- Printing `ToBinary(...)` (bytearray) via `%s` → `bytearray(b'...')`: `jcoptool.py`
  L146–161.
- Missing `f` prefix on f-strings → literal `{...}` printed: `transit.py` L71,
  `readmifaresimple.py` L211, `copytag.py` L68.
- `print()` of raw bytes → `b'...'`.

### D. Helper-level inconsistencies to resolve

- `ToBinary` (L2408) returns **bytearray** but is annotated `-> str` and named like a
  string producer; only accepts hex `str` input.
- `ListToHex` UPPER vs `ToHex` lower case.
- `NibbleReverse` accepts str; `NibbleSwap` (guard commented out) does not.
- Two functions named `ReadablePrint` / `_ReadablePrint` with different byte handling.
- `_BinaryPrint`/`BinaryPrint` duplicate (instance vs static).

## Scripts that are already clean

`readtag.py`, `readmifare1k.py`, `readmifareultra.py`, `isotype.py`, `unique.py`,
`readlfx.py`, `writelfx.py`, `cardselect.py`, `bruteforce.py`, `hitag2brute.py`,
`lfxtype.py`, `multiselect.py`, `loginall.py`, `writemifare1k.py`, `q5reset.py`,
`ChAP.py`. These all consistently treat `card.data` as a hex `str` — which is why the
majority-path readers (PCSC/libnfc) work today.

## Recommended contract

Pick **one** canonical internal type and enforce it at the reader boundaries, with a
single small display layer. Two viable targets (see decision below):

- **Option 1 — bytes internal** (matches "maintain binary content throughout"):
  `card.data`/`uid`/`atr` are `bytes`; `errorcode` a 2-byte `bytes` or an int SW.
  Convert at ingress (decode serial/socket, `bytes(list)` for pyscard, ctypes→bytes),
  encode at egress (`ser.write`/`socket.send`). Display only via helpers:
  `ToHex(b) -> str` (choose ONE case), `ReadablePrint(b) -> str`. Requires rewriting
  every consumer that currently does `int(self.data[x:x+2],16)` / hex-pair slicing.

- **Option 2 — normalized hex `str` internal** (least churn): make the two outlier
  paths (ACG, Android) also produce hex `str`; keep the rest. Matches what all clean
  scripts already assume. Not literally "binary", but a single unambiguous text form.

Independent of the choice: replace all `/`→`//` where used as index/len/Lc; remove the
`isinstance(str)→latin-1` guards so mis-typed calls fail loudly; standardise hex case;
fix the `rfidio` typo, `.decode/.encode("hex")`, and `ord()`-on-bytes sites; reset
`MIFAREbinary`.

## Suggested phased remediation

1. **Boundary normalisation** — convert ACG serial + Android socket paths to the
   chosen canonical type; fix `ser.write`/`socket.send` encoding. (Unblocks those
   readers, removes the core inconsistency.)
2. **Helpers** — one documented contract per helper, bytes-only or str-only inputs,
   single hex case, drop silent guards, dedupe the `*Print` twins.
3. **Crash sites** — sweep `.decode/.encode("hex")`, `/`→`//`, `ord()`-on-bytes,
   `str+bytes`, `rfidio` typo. Highest value: `rfidiot-cli.py`, `mrpkey.py`.
4. **Silent-corruption + cosmetic** — errorcode comparisons, `_ReadablePrint`,
   `BinaryToManchester`, f-string prefixes, bytearray `%s` prints.

Each phase should be validated against real hardware per reader/tag type, since there
is no automated test coverage for the reader paths.
