#!/usr/bin/env python3

import csv
from typing import Tuple, Optional
# import pprint

_verbose = False
AID_dat = {}


# load a csv file into a dict, also separating out the 10 char RID
def aid_load_dat(aid_filen: Optional[str] = 'AID-data.csv') -> None:

    ret_dat = {}
    rid_filen = 'AID-rim-data.csv'

    i = 0
    j = 0
    try:
        with open(aid_filen, newline='', encoding='utf-8') as csvfile:
            csvfile.readline()  # skip header
            spamreader = csv.reader(csvfile, delimiter='\t')
            # print(header)
            for row in spamreader:
                if _verbose > 1:
                    print([f"{x}:{y}" for x, y in enumerate(row)])
                if not row or row[0][0] == '#':  # skip empty row and comments
                    continue
                i += 1
                ret_dat[row[0]] = row[1:]
                rid = row[0][:10]
                if rid not in ret_dat:
                    a = [""] * 6
                    a[0] = row[1] or row[3]  # Vendor or Name
                    a[1] = row[2] # Country
                    ret_dat[rid] = a
                    j += 1
    except (FileNotFoundError, PermissionError) as _e:
        # return empty dataset
        pass

    if _verbose:
        print(f"loaded: {i}")
        print(f"rid's:  {i}")
        print(f"created: {len(ret_dat)}")

    i = 0
    j = 0
    try:
        with open(rid_filen, newline='', encoding='utf-8') as csvfile:
            csvfile.readline()  # skip header
            spamreader = csv.reader(csvfile, delimiter='\t')
            # print(header)
            for row in spamreader:
                # print([f"{x}:{type(y)}" for x, y in enumerate(row)])
                # print(row)
                if not row or row[0][0] == '#':  # skip empty row and comments
                    continue
                rid = row[0]
                if rid not in ret_dat:
                    a = [""] * 6
                    a[0] = row[1]
                    a[1] = row[2]
                    ret_dat[rid] = a
                    i += 1
                else:
                    if _verbose > 1:
                        print(row)
                        print(rid, ret_dat[rid])
                    j += 1
    except (FileNotFoundError, PermissionError) as _e:
        # return empty dataset
        pass

    if _verbose:
        print(f"loaded: {i}")
        print(f"skip: {j}")
        print(f"total: {len(ret_dat)}")

    return ret_dat


# lookup AID in AID_dat,
# if not found look up substring / registered application provider identifier (RID)
def aid_lookup(aid: str = None) -> Tuple[str, str]:

    # if there's nothing to report
    if aid is None or not AID_dat:
        return "", ""

    dat = None
    while len(aid) >= 10:
        # print(len(aid), "trying", aid)  # Debug
        if aid in AID_dat:
            dat = AID_dat[aid]
            break
        aid = aid[:-1]
        if len(aid) == 13:
            aid = aid[:10]

    if dat:
        # print([f"{x}:{y}" for x, y in enumerate(dat)])
        if dat[0]:
            aid_info = f"{dat[0]} {dat[2]}"
        else:
            aid_info = f"{dat[2] or dat[1]} {dat[4]}"
        return aid, aid_info

    return "", ""


# test AIDs,  Most are real, some with good RID but unknown/bad PIX
# See
#     https://www.eftlab.com/knowledge-base/complete-list-of-application-identifiers-aid
#     https://en.wikipedia.org/wiki/EMV#Application_selection
test_AIDs = [
    "A0000005272001", "A000000527200101",
    "D27600002545500", "D27600002545500100", "D276000124010101FFFF000000010000",
    "D2760001240102000000000000010000", "D276000144800", "D2760001448000", "D4106470004B5410000002",
    "A000000337101001", "A00000033710100144", "A0000000036000",
    "A00000000201", "A00000000401", "A00000000410101213", "A00000000410101215", "A0000000041010BB5449435301",
    "A0000000041010C0000301", "A0000000041010C0000302", "A0000000041010", "A0000000042010", "A0000000042203",
    "A0000000043010", "A000000157002NOEXIST", "A0000001570021", "A0000001570022", "A0000001570023",
    "A0000001570030", "A0000001570031", "A0000001570040", "A0000001570050", "A0000001570051",
    "A0000001570100", "A0000001570104", "A0000001570109", "A000000157010A", "A000000157010B",
    "A000000157010C", "A000000157010D", "A0000001574443", "A0000001523010", "A0000001524010",
    "A0000001574443", "A0000001884443", "A000000152301", "A0000006581011", "A0000006582010",
    "6D6966617265", "A00000000101", "A00000000201", "A000000003000000", "A000000003000XXXX",
    "A0000000030000", "A00000000300037561", "A00000000305076010", "A000000003101001", "A000000003101002",
    "A0000000031010", "A0000000031111", "A0000000032010", "A0000000032020", "A0000000033010",
    "A0000000033060", "A0000000034010", "A0000000035010", "A000000003534441",
]

if __name__ == '__main__':

    AID_dat = aid_load_dat()

    # Print found item
    for t_aid in test_AIDs:
        aid_found, aid_description = aid_lookup(t_aid)

        if not aid_found:
            print(f"{t_aid}: Not Found / Unknown")

        print(f"{t_aid}:\n\t{aid_found + ':':22s} {aid_description}")
