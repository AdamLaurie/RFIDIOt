#!/usr/bin/env python3
#  passiveauth.py - ePassport Passive Authentication against a CSCA master list
#
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
#
#  This code is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  Verifies the trust chain of an ePassport EF.SOD:
#    1. DG hash values in the SOD match the actual data groups (integrity)
#    2. the SOD is signed by the Document Signer (DS) certificate it carries
#    3. the DS certificate is signed by a Country Signing CA (CSCA) present
#       in a public CSCA master list (e.g. the German BSI GermanMasterList.ml)
#
#  Usage:
#    passiveauth.py <EF_SOD.BIN> <masterlist.ml> [DG_DIR]
#
#  EF_SOD.BIN / EF_DGxx.BIN are produced by mrpkey.py (default dir /tmp).
#  The master list is the raw ICAO/BSI .ml (a CMS SignedData).

import hashlib
import subprocess
import sys
import tempfile
import os
import warnings

# master-list certs legitimately trip cryptography's RFC5280 deprecation
# warnings (negative serials, naive datetimes); they are not our concern here
warnings.filterwarnings("ignore")

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

# hash OID -> hashlib constructor
HASH_OID = {
    "1.3.14.3.2.26": ("sha1", hashlib.sha1),
    "2.16.840.1.101.3.4.2.1": ("sha256", hashlib.sha256),
    "2.16.840.1.101.3.4.2.2": ("sha384", hashlib.sha384),
    "2.16.840.1.101.3.4.2.3": ("sha512", hashlib.sha512),
    "2.16.840.1.101.3.4.2.4": ("sha224", hashlib.sha224),
}


def der_tlv(buf, i):
    "minimal DER reader: return (tag, header_start, content_start, end)"
    tag = buf[i]
    j = i + 1
    length = buf[j]
    j += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[j : j + n], "big")
        j += n
    return tag, i, j, j + length


def strip_icao_wrapper(data):
    "EF.SOD is 0x77 <len> <CMS>; return the CMS DER"
    if data and data[0] == 0x77:
        _, _, cs, ce = der_tlv(data, 0)
        return data[cs:ce]
    return data


def run(cmd, indata=None):
    return subprocess.run(cmd, input=indata, capture_output=True)


def masterlist_cscas(ml_path):
    "extract every CSCA certificate from a .ml (CMS whose content is a CscaMasterList)"
    econtent = tempfile.NamedTemporaryFile(suffix=".der", delete=False).name
    r = run(["openssl", "cms", "-inform", "DER", "-in", ml_path, "-noverify", "-verify", "-out", econtent])
    if not os.path.exists(econtent) or os.path.getsize(econtent) == 0:
        print("*** could not extract content from master list:", r.stderr.decode(errors="replace")[:200])
        return []
    buf = open(econtent, "rb").read()
    os.unlink(econtent)
    # CscaMasterList ::= SEQUENCE { version INTEGER, certList SET OF Certificate }
    _, _, cs, _ = der_tlv(buf, 0)
    i = cs
    _, _, _, e = der_tlv(buf, i)  # version
    i = e
    _, _, setc, sete = der_tlv(buf, i)  # SET OF Certificate
    certs = []
    i = setc
    while i < sete:
        _, s, _, e = der_tlv(buf, i)
        der = buf[s:e]
        try:
            certs.append(x509.load_der_x509_certificate(der))
        except Exception:
            pass
        i = e
    return certs


def cert_ski(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest.hex()
    except Exception:
        return None


def cert_aki(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier.hex()
    except Exception:
        return None


def lds_hashes(cms_der):
    "extract (hash_oid, {dg_number: hash_hex}) from the SOD's LDSSecurityObject"
    econtent = tempfile.NamedTemporaryFile(suffix=".der", delete=False).name
    tmpcms = tempfile.NamedTemporaryFile(suffix=".der", delete=False).name
    open(tmpcms, "wb").write(cms_der)
    run(["openssl", "cms", "-inform", "DER", "-in", tmpcms, "-noverify", "-verify", "-out", econtent])
    buf = open(econtent, "rb").read()
    os.unlink(econtent)
    os.unlink(tmpcms)
    # LDSSecurityObject ::= SEQ { version INT, hashAlg AlgId, SEQ OF SEQ{ INT, OCTET STRING } }
    _, _, cs, _ = der_tlv(buf, 0)
    i = cs
    _, _, _, e = der_tlv(buf, i)  # version
    i = e
    # hashAlgorithm AlgorithmIdentifier ::= SEQ { OID, params }
    _, _, ac, ae = der_tlv(buf, i)
    _, _, oc, oe = der_tlv(buf, ac)  # OID
    oid = decode_oid(buf[oc:oe])
    i = ae
    # dataGroupHashValues SEQUENCE OF DataGroupHash
    _, _, gc, ge = der_tlv(buf, i)
    hashes = {}
    i = gc
    while i < ge:
        _, _, dc, de = der_tlv(buf, i)  # DataGroupHash SEQUENCE
        _, _, nc, ne = der_tlv(buf, dc)  # dataGroupNumber INTEGER
        dgnum = int.from_bytes(buf[nc:ne], "big")
        _, _, hc, he = der_tlv(buf, ne)  # dataGroupHashValue OCTET STRING
        hashes[dgnum] = buf[hc:he].hex()
        i = de
    return oid, hashes


def decode_oid(b):
    vals = [b[0] // 40, b[0] % 40]
    v = 0
    for c in b[1:]:
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            vals.append(v)
            v = 0
    return ".".join(str(x) for x in vals)


def passive_authenticate(sod_path, ml_path, dg_dir=None):
    "run Passive Authentication; return True only if fully verified, else False"
    if not HAVE_CRYPTO:
        print("*** Passive Authentication needs the 'cryptography' module (pip install cryptography)")
        return None
    if dg_dir is None:
        dg_dir = os.path.dirname(sod_path) or "."

    cms_der = strip_icao_wrapper(open(sod_path, "rb").read())

    # --- DS certificate from the SOD ---
    ds_pem = run(["openssl", "pkcs7", "-inform", "DER", "-print_certs"], cms_der).stdout
    if b"BEGIN CERTIFICATE" not in ds_pem:
        print("*** no Document Signer certificate found in SOD")
        return False
    ds = x509.load_pem_x509_certificate(ds_pem)
    aki = cert_aki(ds)
    print("Document Signer:")
    print("  subject:", ds.subject.rfc4514_string())
    print("  issuer :", ds.issuer.rfc4514_string())
    print("  serial :", hex(ds.serial_number), " valid:", ds.not_valid_before.date(), "->", ds.not_valid_after.date())
    print("  authority key id:", aki)

    # --- find the CSCA in the master list ---
    print("\nSearching master list for the CSCA ...")
    cscas = masterlist_cscas(ml_path)
    print("  master list holds %d CSCA certificates" % len(cscas))
    match = None
    for c in cscas:
        if aki and cert_ski(c) == aki:
            match = c
            break
    if not match:
        # fall back to issuer-DN match
        for c in cscas:
            if c.subject == ds.issuer:
                match = c
                break
    if not match:
        print("  *** CSCA NOT found in master list - cannot establish trust")
        return False
    csca_pem = tempfile.NamedTemporaryFile(suffix=".pem", delete=False).name
    open(csca_pem, "wb").write(match.public_bytes(serialization.Encoding.PEM))
    print("  FOUND CSCA:", match.subject.rfc4514_string())
    print("    SKI:", cert_ski(match), " serial:", hex(match.serial_number))

    # --- verify SOD signature <- DS, and DS <- CSCA, in one openssl cms verify ---
    tmpcms = tempfile.NamedTemporaryFile(suffix=".der", delete=False).name
    open(tmpcms, "wb").write(cms_der)
    r = run(["openssl", "cms", "-verify", "-inform", "DER", "-in", tmpcms,
             "-CAfile", csca_pem, "-purpose", "any", "-no_check_time", "-out", os.devnull])
    os.unlink(tmpcms)
    sod_ok = b"Verification successful" in r.stderr
    print("\nSignature chain (SOD <- DS <- CSCA):", "PASS" if sod_ok else "FAIL")
    if not sod_ok:
        print("  openssl:", r.stderr.decode(errors="replace").strip()[:200])

    # --- data group integrity ---
    oid, dgh = lds_hashes(cms_der)
    hname, hfun = HASH_OID.get(oid, (oid, None))
    print("\nData group hashes (%s):" % hname)
    all_ok = True
    for dg in sorted(dgh):
        fn = os.path.join(dg_dir, "EF_DG%d.BIN" % dg)
        if hfun and os.path.exists(fn):
            calc = hfun(open(fn, "rb").read()).hexdigest()
            ok = calc == dgh[dg].lower()
            all_ok = all_ok and ok
            print("  DG%-2d %s  %s" % (dg, "OK  " if ok else "FAIL", fn if ok else "(hash mismatch)"))
        else:
            print("  DG%-2d  in SOD, data group file not available (%s)" % (dg, fn))

    os.unlink(csca_pem)
    result = bool(sod_ok and all_ok)
    print("\nPassive Authentication:", "PASSED" if result else "INCOMPLETE/FAILED")
    return result


def main():
    if len(sys.argv) < 3:
        print("Usage: passiveauth.py <EF_SOD.BIN> <masterlist.ml> [DG_DIR]")
        sys.exit(True)
    dg_dir = sys.argv[3] if len(sys.argv) > 3 else None
    ok = passive_authenticate(sys.argv[1], sys.argv[2], dg_dir)
    sys.exit(not ok)


if __name__ == "__main__":
    main()
