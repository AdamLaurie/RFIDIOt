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


def masterlist_cscas(ml_path, quiet=False):
    "extract every CSCA certificate from a .ml (CMS whose content is a CscaMasterList)"
    econtent = tempfile.NamedTemporaryFile(suffix=".der", delete=False).name
    r = run(["openssl", "cms", "-inform", "DER", "-in", ml_path, "-noverify", "-verify", "-out", econtent])
    if not os.path.exists(econtent) or os.path.getsize(econtent) == 0:
        if not quiet:
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


def _load_all_certs(pem_blob):
    "load every PEM certificate in a blob (openssl may emit the DS and the CSCA)"
    certs = []
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    pos = 0
    while True:
        b = pem_blob.find(begin, pos)
        if b < 0:
            break
        e = pem_blob.find(end, b)
        if e < 0:
            break
        block = pem_blob[b:e + len(end)]
        pos = e + len(end)
        try:
            certs.append(x509.load_pem_x509_certificate(block))
        except Exception:
            pass
    return certs


def _find_csca(cscas, ds, aki):
    "pick the CSCA that issued the DS: by AKI->SKI, else by matching issuer name"
    for c in cscas:
        if aki and cert_ski(c) == aki:
            return c
    for c in cscas:
        if c.subject == ds.issuer:
            return c
    return None


def _verify_chain(csca, ds):
    "openssl verify: is the DS certificate signed by this CSCA?"
    csca_pem = tempfile.NamedTemporaryFile(suffix=".pem", delete=False).name
    ds_pem_f = tempfile.NamedTemporaryFile(suffix=".pem", delete=False).name
    try:
        open(csca_pem, "wb").write(csca.public_bytes(serialization.Encoding.PEM))
        open(ds_pem_f, "wb").write(ds.public_bytes(serialization.Encoding.PEM))
        r = run(["openssl", "verify", "-no_check_time", "-partial_chain", "-CAfile", csca_pem, ds_pem_f])
        return r.returncode == 0 and b": OK" in r.stdout
    finally:
        for f in (csca_pem, ds_pem_f):
            os.unlink(f)


def cert_uris(cert):
    "issuer-locating URLs the cert itself names: AIA caIssuers first, then CPS policy URIs"
    uris = []
    try:
        from cryptography.x509.oid import AuthorityInformationAccessOID
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        for ad in aia:
            if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                uris.append(ad.access_location.value)
    except Exception:
        pass
    try:
        pols = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
        for p in pols:
            for q in (p.policy_qualifiers or []):
                if isinstance(q, str):
                    uris.append(q)                       # bare CPS URI
                else:
                    u = getattr(q, "cps_uri", None)      # UserNotice has no uri
                    if u:
                        uris.append(u)
    except Exception:
        pass
    out = []
    for u in uris:
        if isinstance(u, str) and u.lower().startswith(("http://", "https://")) and u not in out:
            out.append(u)
    return out


def _certs_from_blob(blob):
    "parse X.509 certs from arbitrary bytes: PEM bag, single DER, PKCS7, or ICAO master list"
    if b"-----BEGIN CERTIFICATE-----" in blob:
        c = _load_all_certs(blob)
        if c:
            return c
    try:
        return [x509.load_der_x509_certificate(blob)]
    except Exception:
        pass
    tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False).name
    open(tmp, "wb").write(blob)
    try:
        for form in ("DER", "PEM"):
            r = run(["openssl", "pkcs7", "-inform", form, "-in", tmp, "-print_certs"])
            if b"BEGIN CERTIFICATE" in r.stdout:
                c = _load_all_certs(r.stdout)
                if c:
                    return c
        c = masterlist_cscas(tmp, quiet=True)   # CMS whose content is a CscaMasterList
        if c:
            return c
    finally:
        os.unlink(tmp)
    return []


def fetch_cscas_from_uris(uris, timeout=15):
    "fetch each document-named URL; return (certs, url) for the first that yields certs"
    import urllib.request
    for u in uris:
        print("  fetching document-named location:", u)
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "RFIDIOt-passiveauth"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                blob = resp.read(8 * 1024 * 1024)
        except Exception as e:
            print("    fetch failed:", str(e)[:150])
            continue
        certs = _certs_from_blob(blob)
        if certs:
            print("    retrieved %d certificate(s)" % len(certs))
            return certs, u
        print("    no certificate found (got %d bytes - likely an HTML policy page)" % len(blob))
    return [], None


def _first_pem_block(pem_blob):
    "the first -----BEGIN/END CERTIFICATE----- block (bytes), or None"
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    b = pem_blob.find(begin)
    if b < 0:
        return None
    e = pem_blob.find(end, b)
    if e < 0:
        return None
    return pem_blob[b:e + len(end)]


def cert_uris_openssl(ds_pem):
    "AIA caIssuers + CPS URIs from a DS cert PEM via openssl (works when cryptography can't parse it)"
    import re
    tmp = tempfile.NamedTemporaryFile(suffix=".pem", delete=False).name
    open(tmp, "wb").write(ds_pem)
    try:
        txt = run(["openssl", "x509", "-in", tmp, "-noout", "-text"]).stdout.decode("utf-8", "replace")
    finally:
        os.unlink(tmp)
    uris = []
    for m in re.finditer(r"CA Issuers - URI:(\S+)", txt):
        uris.append(m.group(1))
    for m in re.finditer(r"CPS:\s*(\S+)", txt):
        uris.append(m.group(1))
    out = []
    for u in uris:
        if u.lower().startswith(("http://", "https://")) and u not in out:
            out.append(u)
    return out


def _verify_chain_pem(csca, ds_pem):
    "openssl verify: is the DS certificate (PEM bytes) signed by this CSCA (cert object)?"
    csca_pem = tempfile.NamedTemporaryFile(suffix=".pem", delete=False).name
    ds_f = tempfile.NamedTemporaryFile(suffix=".pem", delete=False).name
    try:
        open(csca_pem, "wb").write(csca.public_bytes(serialization.Encoding.PEM))
        open(ds_f, "wb").write(ds_pem)
        r = run(["openssl", "verify", "-no_check_time", "-partial_chain", "-CAfile", csca_pem, ds_f])
        return r.returncode == 0 and b": OK" in r.stdout
    finally:
        for f in (csca_pem, ds_f):
            os.unlink(f)


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


def passive_authenticate(sod_path, ml_path=None, dg_dir=None, fetch=False):
    """run Passive Authentication; return a verdict string.

    SAFE       - data groups intact and the DS chains to a CSCA in the master list
    SELFSIGNED - data groups intact and the DS chains to a CSCA, but that CSCA came
                 from the document itself - embedded in the SOD, or fetched from a URL
                 the document named (circular - NOT a trust anchor)
    UNTRUSTED  - internally consistent but no usable CSCA / signer not in the list
    TAMPERED   - SOD signature or a data-group hash failed
    None       - could not run (no crypto module, no DS cert, etc.)

    ml_path may be None/empty to run the content checks and the self-provided-CSCA
    fallback without a public master list. fetch=True additionally follows the URLs
    the document names (AIA caIssuers / CPS) to retrieve a CSCA - still UNTRUSTED,
    because the document chose where to look.
    """
    if not HAVE_CRYPTO:
        print("*** Passive Authentication needs the 'cryptography' module (pip install cryptography)")
        return None
    if dg_dir is None:
        dg_dir = os.path.dirname(sod_path) or "."

    cms_der = strip_icao_wrapper(open(sod_path, "rb").read())

    # --- certificates carried in the SOD: the Document Signer (DS), and
    #     sometimes the issuing CSCA, which some documents include alongside it ---
    certs_pem = run(["openssl", "pkcs7", "-inform", "DER", "-print_certs"], cms_der).stdout
    if b"BEGIN CERTIFICATE" not in certs_pem:
        print("*** no Document Signer certificate found in SOD")
        return None
    sod_certs = _load_all_certs(certs_pem)
    # the DS is the signer (end-entity): prefer a cert that is not self-signed.
    # Note: 'cryptography' may reject a real-world DS cert that openssl accepts
    # (e.g. German passports encode the ECDSA AlgorithmIdentifier with a NULL
    # parameters field, which the strict parser rejects), leaving sod_certs empty.
    ds = next((c for c in sod_certs if c.subject != c.issuer), sod_certs[0] if sod_certs else None)
    aki = cert_aki(ds) if ds else None
    print("Document Signer:")
    if ds is not None:
        print("  subject:", ds.subject.rfc4514_string())
        print("  issuer :", ds.issuer.rfc4514_string())
        print("  serial :", hex(ds.serial_number), " valid:", ds.not_valid_before.date(), "->", ds.not_valid_after.date())
        print("  authority key id:", aki)
    else:
        # fall back to the human-readable subject=/issuer= lines openssl printed
        for line in certs_pem.splitlines():
            if line.startswith((b"subject=", b"issuer=")):
                print("  " + line.decode("utf-8", "replace"))
        print("  (the 'cryptography' module could not parse this certificate - openssl can -")
        print("   so the content checks below still run, but the CSCA chain check is skipped)")

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

    # === trust check - DS chained to a CSCA ===
    # The DS PEM, used for openssl-based verification even when 'cryptography'
    # cannot parse the cert into an object (ds is None).
    ds_pem_block = _first_pem_block(certs_pem)
    match, self_provided, chain_ok, self_source = None, False, False, None

    # 1. TRUSTED anchor: a CSCA from the supplied master list
    if ds is not None and ml_path:
        print("\nSearching master list for the CSCA ...")
        cscas = masterlist_cscas(ml_path)
        print("  master list holds %d CSCA certificates" % len(cscas))
        cand = _find_csca(cscas, ds, aki)
        if cand:
            chain_ok = _verify_chain(cand, ds)
            match = cand
            print("  FOUND CSCA:", cand.subject.rfc4514_string(), " serial:", hex(cand.serial_number))
            print("  DS certificate signed by this CSCA:", "PASS" if chain_ok else "FAIL")
    elif not ml_path:
        print("\nNo master list supplied - trust cannot be established against a public anchor.")

    # 2. UNTRUSTED fallback: a CSCA the document itself provides. NOT a trust
    #    anchor (the document chooses it), but it checks the chain is internally
    #    consistent. Sources, in order:
    #      (a) a CSCA embedded in the SOD alongside the DS
    #      (b) a CSCA fetched from a URL the document names (AIA/CPS), if fetch=True
    if not chain_ok and ds is not None:
        extra = [c for c in sod_certs
                 if (c.serial_number, c.issuer) != (ds.serial_number, ds.issuer)]
        cand = _find_csca(extra, ds, aki)
        if cand and _verify_chain(cand, ds):
            match, self_provided, chain_ok = cand, True, True
            self_source = "carried in the SOD by the document"
    if not chain_ok and fetch and ds_pem_block:
        uris = cert_uris(ds) if ds is not None else cert_uris_openssl(ds_pem_block)
        if uris:
            print("\nDocument-directed CSCA retrieval (UNTRUSTED - location named by the document):")
            fcerts, furl = fetch_cscas_from_uris(uris)
            for c in fcerts:
                if _verify_chain_pem(c, ds_pem_block):
                    match, self_provided, chain_ok = c, True, True
                    self_source = "fetched from %s (a URL named by the document)" % furl
                    break
            if not chain_ok and fcerts:
                print("  retrieved certificate(s), but none validated the DS signature")
        else:
            print("\n  document names no retrievable CSCA URL (AIA/CPS) to fetch")

    if self_provided and chain_ok:
        print("  DOCUMENT-PROVIDED CSCA:", match.subject.rfc4514_string(),
              " serial:", hex(match.serial_number))
        print("  DS certificate signed by this CSCA: PASS")
        print("  *** CAVEAT: this CSCA was %s," % self_source)
        print("      so the chain is circular - it proves internal consistency only, NOT")
        print("      authenticity. A cloned or forged chip can present (or point at) its own")
        print("      matching CSCA. This is NOT a trust anchor.")
    elif not chain_ok:
        if ds is None and not fetch:
            print("\nCSCA chain check skipped - the DS certificate could not be parsed by")
            print("'cryptography' (content integrity above is unaffected; verified via openssl).")
            print("  (set RFIDIOT_CSCA_FETCH=1 to still follow the URLs the document names - UNTRUSTED)")
        elif ml_path:
            print("  CSCA NOT found in master list (and none usable provided by the document)")
        else:
            print("  no usable CSCA (none trusted, embedded, or fetched) - cannot establish the DS chain")
            if not fetch:
                print("  (set RFIDIOT_CSCA_FETCH=1 to follow the URLs the document names - UNTRUSTED)")

    trusted = chain_ok and not self_provided

    # === verdict ===
    if tampered:
        verdict = "TAMPERED"
    elif trusted:
        verdict = "SAFE"
    elif self_provided and chain_ok:
        verdict = "SELFSIGNED"
    else:
        verdict = "UNTRUSTED"
    print("\nPassive Authentication:", verdict)
    return verdict


def main():
    if len(sys.argv) < 2:
        print("Usage: passiveauth.py <EF_SOD.BIN> [masterlist.ml] [DG_DIR]")
        sys.exit(True)
    ml = sys.argv[2] if len(sys.argv) > 2 else None
    dg_dir = sys.argv[3] if len(sys.argv) > 3 else None
    fetch = os.environ.get("RFIDIOT_CSCA_FETCH", "").lower() in ("1", "true", "yes", "on")
    verdict = passive_authenticate(sys.argv[1], ml, dg_dir, fetch=fetch)
    sys.exit(0 if verdict == "SAFE" else 1)


if __name__ == "__main__":
    main()
