#!/usr/bin/python3
#  pypn5180.py - NXP PN5180 reader back-end (READER_PN5180), driven from a PC
#  over an FT232H USB bridge with pyftdi (SPI + a few GPIO lines).
#
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
#
#    This code is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#  [EXPERIMENTAL / BRING-UP] The PN5180 (NXP high-performance NFC frontend:
#  ISO 14443-A/B, ISO 15693 / ICODE, ISO 18092 / FeliCa) is a register-level
#  part controlled over SPI with a BUSY handshake line - it has no USB of its
#  own. The generic breakout boards (e.g. RAKSTORE / Hailege) expose the bare
#  SPI header, so on a PC we reach it through an FT232H in MPSSE mode via pyftdi:
#  SPI on AD0-AD3, and GPIO on the spare pins for BUSY / RST (/ optional IRQ).
#
#  Command set and register/EEPROM map follow the NXP PN5180A0xx datasheet and
#  product data sheet; the ISO 14443-A activation sequence is modelled on NXP's
#  AN and on the widely used Arduino PN5180 library by Andreas Trappmann
#  (github.com/ATrappmann/PN5180-Library, credited as reference).
#
#  Default FT232H pin map (override in the constructor):
#     AD0 SCK   AD1 MOSI   AD2 MISO   AD3 NSS/CS   (SPI, pyftdi SpiController)
#     AD4 BUSY (in)   AD5 RST (out, active low)   AD6 IRQ (in, optional)
#  Wire the PN5180's 3V3 logic to the FT232H (the module regulates 5V->3V3).
#
#  APDUs: like the TWN4 back-end, T=CL runs in software (pynfc._tcl_exchange)
#  over raw ISO 14443-3 frames; the PN5180 handles CRC/parity in hardware.
#
#  NB: NOT yet hardware-verified (no board wired at the time of writing) - this
#  is bring-up code. TODO.md section 21 tracks it.

import time

from .pynfc import _tcl_exchange

VERSION = "0.1b"

# ---- PN5180 SPI instruction set (first byte of each frame) -----------------
PN5180_WRITE_REGISTER = 0x00
PN5180_WRITE_REGISTER_OR_MASK = 0x01
PN5180_WRITE_REGISTER_AND_MASK = 0x02
PN5180_READ_REGISTER = 0x04
PN5180_WRITE_EEPROM = 0x06
PN5180_READ_EEPROM = 0x07
PN5180_SEND_DATA = 0x09
PN5180_READ_DATA = 0x0A
PN5180_SWITCH_MODE = 0x0B
PN5180_MIFARE_AUTHENTICATE = 0x0C
PN5180_LOAD_RF_CONFIG = 0x11
PN5180_RF_ON = 0x16
PN5180_RF_OFF = 0x17

# ---- registers -------------------------------------------------------------
SYSTEM_CONFIG = 0x00
IRQ_ENABLE = 0x01
IRQ_STATUS = 0x02
IRQ_CLEAR = 0x03
TRANSCEIVE_CONTROL = 0x04
RX_STATUS = 0x13
CRC_RX_CONFIG = 0x12
CRC_TX_CONFIG = 0x19
RF_STATUS = 0x1D
SYSTEM_STATUS = 0x24

# SYSTEM_CONFIG command field (bits [2:0])
SYSTEM_CONFIG_COMMAND_MASK = 0xFFFFFFF8
SYSTEM_CONFIG_COMMAND_IDLE = 0x00000000
SYSTEM_CONFIG_COMMAND_TRANSCEIVE = 0x00000003

# IRQ status bits
RX_IRQ_STAT = 0x00000001
TX_IRQ_STAT = 0x00000002
IDLE_IRQ_STAT = 0x00000004
GENERAL_ERROR_IRQ_STAT = 0x00000040
IRQ_CLEAR_ALL = 0x000FFFFF

# RF_STATUS: transceive state in bits [26:24]
RF_STATUS_TRANSCEIVE_SHIFT = 24
RF_STATUS_TRANSCEIVE_MASK = 0x07
TRANSCEIVE_STATE_WAIT_TRANSMIT = 1

# ---- EEPROM addresses ------------------------------------------------------
EE_DIE_IDENTIFIER = 0x00       # 16 bytes
EE_PRODUCT_VERSION = 0x10      # 2 bytes
EE_FIRMWARE_VERSION = 0x12     # 2 bytes
EE_EEPROM_VERSION = 0x14       # 2 bytes

# ---- LOAD_RF_CONFIG indices (TX, RX) for ISO 14443-A at 106 kbit/s ---------
RF_CFG_ISO14443A_106_TX = 0x00
RF_CFG_ISO14443A_106_RX = 0x80

# FT232H default GPIO pin map (bit positions on the FTDI port: AD0..AD7 = 0..7)
PIN_BUSY = 4
PIN_RST = 5
PIN_IRQ = 6


class PN5180Error(Exception):
    pass


class _TagA:
    "one ISO 14443-A target, as the RFIDIOt select() branch reads it"
    def __init__(self, uid, atqa, sak, ats=""):
        self.uid = uid
        self.atqa = atqa
        self.sak = sak
        self.ats = ats


class PN5180:
    """PN5180 over FT232H/pyftdi. Open, bring-up (version/RF), ISO 14443-A
    select, raw frames and software-T=CL APDUs. `url` is a pyftdi FTDI URL
    (default 'ftdi://ftdi:232h/1'); pins override the default AD4/AD5/AD6 map."""

    def __init__(self, url=None, debug=False, timeout=3,
                 freq=1_000_000, pin_busy=PIN_BUSY, pin_rst=PIN_RST, pin_irq=PIN_IRQ):
        self.debug = debug
        self.timeout = timeout
        self.url = url or "ftdi://ftdi:232h/1"
        self._pin_busy = pin_busy
        self._pin_rst = pin_rst
        self._pin_irq = pin_irq
        self._iblock = 0            # T=CL block number
        self._cid = None
        self.ats = ""
        try:
            from pyftdi.spi import SpiController
        except ImportError:
            raise PN5180Error("pyftdi is required for the PN5180 back-end "
                              "(pip install pyftdi)")
        self._spi = SpiController(cs_count=1)
        try:
            self._spi.configure(self.url)
        except Exception as e:
            raise PN5180Error("could not open FT232H '%s': %s" % (self.url, e))
        # SPI mode 0 (CPOL=0, CPHA=0), MSB first, CS on AD3
        self._port = self._spi.get_port(cs=0, freq=freq, mode=0)
        self._gpio = self._spi.get_gpio()
        busy_m = 1 << self._pin_busy
        rst_m = 1 << self._pin_rst
        irq_m = 1 << self._pin_irq
        # RST is our only output; BUSY/IRQ are inputs. NB only the OUTPUT pin is
        # put in the pyftdi SpiController GPIO direction mask: including an input
        # pin (e.g. BUSY) in the mask makes its read come back stuck-high on
        # pyftdi's SpiGpioPort - leaving it unmanaged reads the real pin state.
        self._gpio.set_direction(rst_m, rst_m)
        self._rst_mask = rst_m
        self._busy_mask = busy_m
        self._irq_mask = irq_m
        self.reset()
        self.product_version = self._read_eeprom(EE_PRODUCT_VERSION, 2)
        self.firmware_version = self._read_eeprom(EE_FIRMWARE_VERSION, 2)
        self.eeprom_version = self._read_eeprom(EE_EEPROM_VERSION, 2)
        self.version = "PN5180 fw %d.%d" % (self.firmware_version[1], self.firmware_version[0])
        self.readername = "NXP %s (%s)" % (self.version, self.url)
        if self.debug:
            print("  pn5180: product %s firmware %s eeprom %s"
                  % (self.product_version.hex(), self.firmware_version.hex(),
                     self.eeprom_version.hex()))

    # ------------------------------------------------------------------ GPIO
    def _rst(self, level):
        "drive RST (active low): level True = high (run), False = low (reset)"
        self._gpio.write(self._rst_mask if level else 0)

    def _busy(self):
        "read the BUSY line (True = busy/high)"
        return bool(self._gpio.read() & self._busy_mask)

    def _wait_busy(self, want_low=True, timeout=1.0):
        "poll BUSY until it reaches the wanted level, or raise on timeout"
        deadline = time.time() + timeout
        while (self._busy() != (not want_low)):
            # want_low: loop while BUSY is high; else loop while BUSY is low
            if time.time() > deadline:
                raise PN5180Error("BUSY stuck %s" % ("high" if want_low else "low"))
        return

    def reset(self):
        """hardware reset via RST, then wait for the idle IRQ.

        NB (2026-10-25 bring-up): driving RST through pyftdi's SpiController GPIO
        (AD5) proved unreliable on the bench - the write did not reliably pull the
        pin, leaving the PN5180 held in reset (RST low -> every SPI read 0xFF). If
        the chip reads all-FF, measure RST: it must be ~VDD (high). The robust
        workaround is a hardware pull-up on RST (or tie it high) rather than relying
        on this GPIO write; a future revision may drive RST over a dedicated FTDI
        GPIO instead of the SpiController's shared port."""
        self._rst(True)
        time.sleep(0.01)
        self._rst(False)             # assert reset (active low)
        time.sleep(0.01)
        self._rst(True)              # release
        time.sleep(0.01)
        # after reset the chip raises the IDLE IRQ; clear all IRQs to start clean
        try:
            self._wait_busy(want_low=True, timeout=0.5)
        except PN5180Error:
            pass
        self.write_register(IRQ_CLEAR, IRQ_CLEAR_ALL)

    # --------------------------------------------------- low-level SPI frames
    def _command(self, tx: bytes, rx_len=0):
        """one PN5180 SPI command with the BUSY handshake: send tx (CS framed),
        wait for the chip to finish, then - if rx_len - read the response in a
        second CS-framed transfer. Returns the response bytes (or b'')."""
        # 0. chip must be ready (BUSY low) before a command
        self._wait_busy(want_low=True, timeout=self.timeout)
        # 1. send: pyftdi frames CS low..write..CS high in one call
        self._port.write(bytes(tx))
        # 2. the chip pulses BUSY high while it processes; wait for it to finish.
        #    (over USB-GPIO the high pulse can be missed, so we just wait for the
        #    ready/low state with a short settle first.)
        time.sleep(0.001)
        self._wait_busy(want_low=True, timeout=self.timeout)
        if not rx_len:
            return b""
        # 3. read the response (CS framed), clocking out 0xFF
        resp = bytes(self._port.read(rx_len))
        time.sleep(0.001)
        self._wait_busy(want_low=True, timeout=self.timeout)
        return resp

    # --------------------------------------------------- register / EEPROM
    def write_register(self, reg, value):
        self._command(bytes([PN5180_WRITE_REGISTER, reg]) + int(value).to_bytes(4, "little"))

    def _or_register(self, reg, mask):
        self._command(bytes([PN5180_WRITE_REGISTER_OR_MASK, reg]) + int(mask).to_bytes(4, "little"))

    def _and_register(self, reg, mask):
        self._command(bytes([PN5180_WRITE_REGISTER_AND_MASK, reg]) + int(mask).to_bytes(4, "little"))

    def read_register(self, reg):
        return int.from_bytes(self._command(bytes([PN5180_READ_REGISTER, reg]), 4), "little")

    def _read_eeprom(self, addr, length):
        return self._command(bytes([PN5180_READ_EEPROM, addr, length]), length)

    # --------------------------------------------------- RF / transceive
    def load_rf_config(self, tx_conf, rx_conf):
        self._command(bytes([PN5180_LOAD_RF_CONFIG, tx_conf, rx_conf]))

    def rf_on(self):
        self._command(bytes([PN5180_RF_ON, 0x00]))

    def rf_off(self):
        self._command(bytes([PN5180_RF_OFF, 0x00]))

    def _set_crc(self, on):
        "enable/disable hardware CRC on both TX and RX (bit 0 of each config)"
        if on:
            self._or_register(CRC_TX_CONFIG, 0x01)
            self._or_register(CRC_RX_CONFIG, 0x01)
        else:
            self._and_register(CRC_TX_CONFIG, 0xFFFFFFFE)
            self._and_register(CRC_RX_CONFIG, 0xFFFFFFFE)

    def _send_data(self, data: bytes, valid_bits=0):
        "SEND_DATA: valid_bits = number of valid bits in the last byte (0 = all 8)"
        if len(data) > 260:
            raise PN5180Error("frame too long for SEND_DATA (%d)" % len(data))
        self._command(bytes([PN5180_SEND_DATA, valid_bits & 0x07]) + bytes(data))

    def _read_data(self, n):
        if n <= 0:
            return b""
        return self._command(bytes([PN5180_READ_DATA, 0x00]), n)

    def _wait_rx(self, timeout=None):
        "wait for the RX IRQ (a reply received); raise on error/timeout"
        deadline = time.time() + (timeout or self.timeout)
        while True:
            irq = self.read_register(IRQ_STATUS)
            if irq & GENERAL_ERROR_IRQ_STAT:
                raise PN5180Error("transceive general error (IRQ 0x%06X)" % irq)
            if irq & RX_IRQ_STAT:
                return irq
            if time.time() > deadline:
                raise PN5180Error("no RX within %.1fs (IRQ 0x%06X)" % (timeout or self.timeout, irq))

    def _transceive(self, data: bytes, valid_bits=0, timeout=None):
        """send one ISO 14443-3 frame and return the raw reply bytes (whatever
        the RX buffer holds - CRC already stripped by hardware when CRC_RX on)."""
        # idle, clear IRQs, then put the datapath into Transceive
        self._and_register(SYSTEM_CONFIG, SYSTEM_CONFIG_COMMAND_MASK)
        self.write_register(IRQ_CLEAR, IRQ_CLEAR_ALL)
        self._or_register(SYSTEM_CONFIG, SYSTEM_CONFIG_COMMAND_TRANSCEIVE)
        # wait until the transceiver is ready to transmit (best-effort)
        deadline = time.time() + 0.1
        while time.time() < deadline:
            st = (self.read_register(RF_STATUS) >> RF_STATUS_TRANSCEIVE_SHIFT) & RF_STATUS_TRANSCEIVE_MASK
            if st == TRANSCEIVE_STATE_WAIT_TRANSMIT:
                break
        self._send_data(data, valid_bits)
        self._wait_rx(timeout)
        nbytes = self.read_register(RX_STATUS) & 0x1FF
        return self._read_data(nbytes)

    # --------------------------------------------------- ISO 14443-A
    def field_reset(self):
        "RF off/on to reset the field and any activated card"
        self.rf_off()
        time.sleep(0.005)
        self.load_rf_config(RF_CFG_ISO14443A_106_TX, RF_CFG_ISO14443A_106_RX)
        self.rf_on()
        time.sleep(0.005)

    def select(self, cardtype="A"):
        """ISO 14443-A REQA + anticollision + SELECT (cascade levels 1-3).
        Returns a _TagA (uid/atqa/sak/ats) or None. Only Type A for now."""
        if cardtype != "A":
            if self.debug:
                print("  pn5180: only ISO 14443-A implemented so far")
            return None
        self.field_reset()
        # REQA (7-bit frame, no CRC) -> ATQA (SENS_RES, 2 bytes)
        self._set_crc(False)
        try:
            atqa = self._transceive(b"\x26", valid_bits=7, timeout=0.2)
        except PN5180Error:
            return None
        if len(atqa) < 2:
            return None
        sens_res = atqa[:2]

        uid = b""
        sak = b""
        for cl, sel in enumerate((0x93, 0x95, 0x97)):
            # anticollision: SEL + NVB 0x20, CRC off -> 5 bytes (UID CLn + BCC)
            self._set_crc(False)
            cln = self._transceive(bytes([sel, 0x20]), timeout=0.2)
            if len(cln) < 5:
                return None
            uid_bcc = cln[:5]
            if (uid_bcc[0] ^ uid_bcc[1] ^ uid_bcc[2] ^ uid_bcc[3]) != uid_bcc[4]:
                if self.debug:
                    print("  pn5180: BCC mismatch at CL%d" % (cl + 1))
                return None
            # SELECT: SEL + NVB 0x70 + UID CLn + BCC, CRC on -> SAK (+CRC stripped)
            self._set_crc(True)
            sakr = self._transceive(bytes([sel, 0x70]) + uid_bcc, timeout=0.2)
            if len(sakr) < 1:
                return None
            sak = sakr[:1]
            # cascade tag 0x88 means this CLn's first byte is a continuation
            if uid_bcc[0] == 0x88:
                uid += uid_bcc[1:4]
            else:
                uid += uid_bcc[0:4]
            if not (sak[0] & 0x04):        # UID complete (no cascade)
                break
        tag = _TagA(uid.hex().upper(), sens_res.hex().upper(), sak.hex().upper())
        self.uid = tag.uid
        self.sens_res = tag.atqa
        self.sel_res = tag.sak
        # ISO 14443-4 card (SAK bit 0x20): send RATS, keep the ATS
        if sak and (sak[0] & 0x20):
            tag.ats = self._rats()
            self.ats = tag.ats
            self._iblock = 0
        return tag

    def _rats(self, fsdi=8, cid=0):
        "send RATS (request ISO 14443-4) and return the ATS hex (CRC stripped)"
        self._set_crc(True)
        try:
            ats = self._transceive(bytes([0xE0, (fsdi << 4) | (cid & 0x0F)]), timeout=0.2)
        except PN5180Error:
            return ""
        return ats.hex().upper()

    # --------------------------------------------------- APDUs (software T=CL)
    def _raw_frame(self, frame_hex, timeout=None):
        "one T=CL frame for _tcl_exchange: (True, reply_hex) or (False, -1)"
        self._set_crc(True)
        try:
            rx = self._transceive(bytes.fromhex(frame_hex), timeout=timeout)
        except PN5180Error:
            return False, -1
        if not rx:
            return False, -1
        return True, rx.hex().upper()

    def sendAPDU(self, apdu, timeout=None):
        "ISO 14443-4 APDU: (True, response_hex incl. SW1SW2) or (False, -1)"
        apdu = "".join(list(apdu)).upper()
        try:
            ok, resp, self._iblock = _tcl_exchange(
                self._raw_frame, apdu, self._iblock, timeout, None, self._cid
            )
        except Exception:
            return False, -1
        return ok, resp

    # --------------------------------------------------- lifecycle
    def close(self):
        try:
            self.rf_off()
        except Exception:
            pass
        try:
            self._spi.terminate()
        except Exception:
            pass
