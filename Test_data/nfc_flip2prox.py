#!/usr/bin/env python3
"""
    nfc_flip2prox.py
    Written By: Peter Shipley github.com/evilpete

    From pkg https://github.com/evilpete/flipper_toolbox
"""

# pylint: disable=line-too-long

import os
import sys
import binascii
# import pprint
import json


FLIPPER_NFC_FILETYPE = 'Flipper NFC device'
blk_data = []

_debug = 0


def read_data(inFile):

    with open(inFile, 'r', encoding="utf-8") as fd:

        line = fd.readline().strip()

        if line.startswith("Filetype:"):
            a = line.split(':', 1)
            if not a[1].strip().startswith(FLIPPER_NFC_FILETYPE):
                print(f"Error: {inFile} is not a Flipper NFC data file")
                if _debug:
                    print(f">>{line}<<")
                sys.exit(1)
        else:
            print(f"Error: {inFile} is not a Flipper NFC data file")
            if _debug:
                print(f">>>{line}<<<")
            sys.exit(1)

        for line in fd:
            line = line.strip()

            if not line or line[0] == '#':        # skip blank lines
                continue

            if line.startswith("Device type:"):
                a = line.split(':', 1)
                if not a[1].strip().startswith('Mifare'):
                    print(f"Error: {inFile} is not a Mifare data file: {a[1].strip()}")
                    if _debug:
                        print(f">>>>{line}<<<<")
                        print(f">>>>{a[0]}<<<<")
                        print(f">>>>{a[1]}<<<<")
                    sys.exit(1)

            if line.startswith("Block"):
                b = line.split(':', 1)[1].strip()
                blk_data.append(b.split())


def write_mct_data(outFile):
    i = 0
    sec_cnt = 0
    with open(f'{outFile}.mct', 'w', encoding="utf-8") as fd:
        for b in blk_data:
            if (i % 4) == 0:
                print(f"+Sector: {sec_cnt}", file=fd)
                sec_cnt += 1
            i += 1
            # hex_str = "".join(b).upper()
            # print(hex_str, file=fd)
            print("".join(b).upper(), file=fd)


def write_bin_data(outFile):
    with open(outFile + '.bin', 'wb') as fd:
        for b in blk_data:
            # hex_str = "".join(b)
            # bin_str = binascii.unhexlify(hex_str)
            # fd.write(bin_str)
            fd.write(binascii.unhexlify("".join(b)))


# {"id":"5b4bebb8-f32e-4021-a65b-f73f9fc29e6e","uid":"1C CA 76 A0","sak":8,"atqa":[0,4],"name":"chaminade","tag":3,"color":"#ff5722",
# [ str(int(x, 16)) for x in aa]
# [1C CA 76 A0] 00 [08] 04 00 03 4D 90 1A FF 4A 0A 1D
def write_cham_data(outFile):

    dat_s = blk_data[0]
    dat_i = [int(x, 16) for x in dat_s]
    j_data = [[]] * 256
    dat = {
        "id": ' '.join(dat_s[:4]),
        "uid": ' '.join(dat_s[:4]),
        "sak": dat_i[5],
        "atqa": [dat_i[7], dat_i[6]],
        "name": out_filen,
        "tag": 3,
        "color": "#ff5722",
        "data": j_data,
    }

    i = 0
    for b in blk_data:
        j_data[i] = [int(x, 16) for x in b]
        i += 1

    # with open(outFile + ".pp", 'w', encoding="utf-8") as fd:
    #     pprint.pprint(dat, stream=fd)

    with open(outFile + "_cm.json", 'w', encoding="utf-8") as fd:
        json.dump(dat, fd)


def write_eml_data(outFile):
    with open(outFile + ".eml", 'w', encoding="utf-8") as fd:
        for b in blk_data:
            hex_str = "".join(b).upper()
            print(hex_str, file=fd)


def write_mcj_data(outFile):
    b_data = {}
    dat = {
        "Created": "MifareClassicTool",
        "FileType": "mfcard",
        "blocks": b_data
    }

    i = 0
    for b in blk_data:
        b_data[str(i)] = "".join(b).upper()
        i += 1

    with open(outFile + "_mct.json", 'w', encoding="utf-8") as fd:
        json.dump(dat, fd, indent=2)


write_funcs = {
    'eml': (write_eml_data, "proxmark emulator"),       # proxmark emulator
    'bin': (write_bin_data, "proxmark/Chameleon bin format"),       # proxmark
    'mct': (write_mct_data, "MIFARE Classic Tool"),      # MIFARE Classic Tool
    'mfj': (write_mcj_data, "MIFARE Classic Tool Json"),      # MIFARE Classic Tool Json
    'json': (write_cham_data, "proxmark/Chameleonn Json format"),     # Chameleon Json format
}

if __name__ == '__main__':

    out_format = None
    out_filen = None

    av = sys.argv[1:]

    if av and av[0] == '-h':
        print("\tnfc_conv.py [-f output_format] input_filename [output_filename]")

        print("\n\tValid formats:")
        for k, v in write_funcs.items():
            print(f"\t\t{k}:\t{v[1]}")
        sys.exit(1)


    if av and av[0] == '-f':
        av.pop(0)
        if av:
            out_format = av.pop(0)
        else:
            print("Error: '-f' option requires format name")
            sys.exit(1)
        if out_format not in write_funcs:
            print("Error: unknown format")
            print("    Known Formats:", " ".join(write_funcs.keys()))
            sys.exit(1)

    if av:
        in_filen = av.pop(0)
    else:
        print("Error: missing input filename")
        sys.exit(1)

    if av:
        fn = av.pop(0)
        out_info = os.path.splitext(fn)
        out_format = out_info[1][1:]
        out_filen = out_info[0]
    else:
        out_filen = os.path.splitext(in_filen)[0]

    if _debug:
        print(f"in file: {in_filen}")
        print(f"out file: {out_filen}")
        print(f"out format: {out_format}")

    read_data(in_filen)

    if out_format in write_funcs:
        write_funcs[out_format][0](out_filen)
    else:
        print(f"unknown output format {out_format}")

    # write_eml_data(out_filen)
