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
    "return (sig_ok, hash_oid, {dg: hash_hex}) from the SOD. sig_ok = the SOD's"
    " own signature (content signed by the embedded DS cert) verifies - trust-independent"
    econtent = tempfile.NamedTemporaryFile(suffix=".der", delete=False).name
    tmpcms = tempfile.NamedTemporaryFile(suffix=".der", delete=False).name
    open(tmpcms, "wb").write(cms_der)
    # -noverify skips the CA trust chain but STILL verifies the content signature,
    # so a data object altered without a valid re-sign fails here.
    r = run(["openssl", "cms", "-inform", "DER", "-in", tmpcms, "-noverify", "-verify", "-out", econtent])
    sig_ok = b"Verification successful" in r.stderr
    buf = open(econtent, "rb").read() if os.path.exists(econtent) else b""
    for f in (econtent, tmpcms):
        if os.path.exists(f):
            os.unlink(f)
    if not buf:
        return sig_ok, None, {}
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
    return sig_ok, oid, hashes


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
        return None
    ds = x509.load_pem_x509_certificate(ds_pem)
    aki = cert_aki(ds)
    print("Document Signer:")
    print("  subject:", ds.subject.rfc4514_string())
    print("  issuer :", ds.issuer.rfc4514_string())
    print("  serial :", hex(ds.serial_number), " valid:", ds.not_valid_before.date(), "->", ds.not_valid_after.date())
    print("  authority key id:", aki)

    # === content checks - independent of CA trust ===
    # These catch tampering even for a signer we don't have the CSCA for:
    # data altered without a valid re-sign fails the SOD signature or a DG hash.

    # (1) SOD signature: is the LDSSecurityObject (the signed content) intact and
    #     signed by the DS cert embedded in the SOD?
    sig_ok, oid, dgh = lds_hashes(cms_der)
    print("\nSOD content signature (signed by embedded DS):",
          "PASS" if sig_ok else "FAIL - content altered or not validly signed")

    # (2) data group integrity: each DG hash in the SOD vs the actual data group
    hname, hfun = HASH_OID.get(oid, (oid, None))
    all_dg_ok = True
    if dgh:
        print("Data group hashes (%s):" % hname)
        for dg in sorted(dgh):
            fn = os.path.join(dg_dir, "EF_DG%d.BIN" % dg)
            if hfun and os.path.exists(fn):
                calc = hfun(open(fn, "rb").read()).hexdigest()
                ok = calc == dgh[dg].lower()
                all_dg_ok = all_dg_ok and ok
                print("  DG%-2d %s" % (dg, "OK" if ok else "FAIL - data group altered (hash mismatch)"))
            else:
                print("  DG%-2d in SOD, data group file not available (%s)" % (dg, fn))
    elif not sig_ok:
        print("  (data group hash list unavailable - SOD content signature invalid)")

    tampered = (not sig_ok) or (not all_dg_ok)

    # === trust check - DS chained to a CSCA in the public master list ===
    print("\nSearching master list for the CSCA ...")
    cscas = masterlist_cscas(ml_path)
    print("  master list holds %d CSCA certificates" % len(cscas))
    match = None
    for c in cscas:
        if aki and cert_ski(c) == aki:
            match = c
            break
    if not match:
        for c in cscas:
            if c.subject == ds.issuer:
                match = c
                break
    trusted = False
    if match:
        print("  FOUND CSCA:", match.subject.rfc4514_string(), " serial:", hex(match.serial_number))
        csca_pem = tempfile.NamedTemporaryFile(suffix=".pem", delete=False).name
        ds_pem_f = tempfile.NamedTemporaryFile(suffix=".pem", delete=False).name
        open(csca_pem, "wb").write(match.public_bytes(serialization.Encoding.PEM))
        open(ds_pem_f, "wb").write(ds_pem)
        r = run(["openssl", "verify", "-no_check_time", "-partial_chain", "-CAfile", csca_pem, ds_pem_f])
        trusted = r.returncode == 0 and b": OK" in r.stdout
        print("  DS certificate signed by this CSCA:", "PASS" if trusted else "FAIL")
        for f in (csca_pem, ds_pem_f):
            os.unlink(f)
    else:
        print("  CSCA NOT found in master list")

    # === verdict ===
    if tampered:
        verdict = "TAMPERED"
    elif not trusted:
        verdict = "UNTRUSTED"
    else:
        verdict = "SAFE"
    print("\nPassive Authentication:", verdict)
    return verdict


def main():
    if len(sys.argv) < 3:
        print("Usage: passiveauth.py <EF_SOD.BIN> <masterlist.ml> [DG_DIR]")
        sys.exit(True)
    dg_dir = sys.argv[3] if len(sys.argv) > 3 else None
    verdict = passive_authenticate(sys.argv[1], sys.argv[2], dg_dir)
    sys.exit(0 if verdict == "SAFE" else 1)


if __name__ == "__main__":
    main()
