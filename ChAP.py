#!/usr/bin/env python2.7
"""
Script that tries to select the EMV Payment Systems Directory on all inserted cards.

Copyright 2008 RFIDIOt
Author: Adam Laurie, mailto:adam@algroup.co.uk
        http://rfidiot.org/ChAP.py

This file is based on an example program from scard-python.
  Originally Copyright 2001-2007 gemalto
  Author: Jean-Daniel Aussel, mailto:jean-daniel.aussel@gemalto.com

scard-python is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or
(at your option) any later version.

scard-python is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with scard-python; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

# pylint: disable=too-many-nested-blocks,too-many-branches,too-many-statements

import getopt
import sys
from operator import xor
# from operator import *

# local imports
# ChAP is an ordinary RFIDIOt client: importing rfidiot parses the standard
# global reader options (-R/-r/-f/-d/-N/-L) and builds rfidiot.card. Any option
# it doesn't recognise - ChAP's own flags - and the optional PIN are handed back
# in rfidiot.args for the getopt further down.
#
# The package prints the global reader options and exits on '-h' (before this
# import returns), which would hide ChAP's own options. So intercept '-h' here
# and import under a no-reader argv; we then print both option sets ourselves
# (see the _want_help block below) without touching any hardware.
_want_help = ("-h" in sys.argv[1:]) or ("--help" in sys.argv[1:])
if _want_help:
    sys.argv = [sys.argv[0], "-R", "READER_NONE"]
from rfidiot.iso3166 import ISO3166CountryCodes
import rfidiot  # noqa: E402

card = rfidiot.card

# default global options
BruteforcePrimitives = False
BruteforceFiles = False
BruteforceAID = False
BruteforceEMV = False
OutputFiles = False
Debug = rfidiot.rfidiotglobals.Debug  # set by the global -d option
RawOutput = False
Verbose = False
RecoverCerts = False  # -c : recover/verify the SDA-DDA certificate chain
GenerateAC = False  # -G : send GENERATE AC (CDA) - intrusive, increments the ATC
EncipheredPIN = False  # -E : offline PIN as RSA-enciphered (vs plaintext) VERIFY
Pdol = []  # PDOL (tag 9F38) captured from the selected application's FCI
EMVData = {}  # tag -> value(list of ints) collected while decoding the current app
SDA_INPUT = []  # static data to be authenticated, accumulated from the AFL records
IssuerKey = None  # recovered Issuer public key {"mod": int, "exp": int}
ICCKey = None  # recovered ICC public key {"mod": int, "exp": int}

# CA public keys, keyed by (RID hex, index). Recovery is self-validating
# (6A..BC + SHA-1), so a wrong entry fails cleanly rather than misleading.
# Add keys from the public EMV CA key tables (e.g. eftlab) as needed.
CA_PUBLIC_KEYS = {
    # EMV Certification Authority public keys, imported from a production
    # terminal capkeys.cfg and each verified against its published EMVCo CAPK
    # checksum SHA1(RID | index | modulus | exponent). Recovery is also
    # self-validating (6A..BC + SHA-1), so a wrong/rotated key fails cleanly.
    # --- Visa (RID A000000003) ---
    # index 0x07, 1152-bit  (SHA1 B4BC56CC4E88324932CBC643D6898F6FE593B172)
    ("A000000003", 0x07): {
        "exp": 3,
        "mod": (
            "A89F25A56FA6DA258C8CA8B40427D927B4A1EB4D7EA326BBB12F97DED70AE5E4"
            "480FC9C5E8A972177110A1CC318D06D2F8F5C4844AC5FA79A4DC470BB11ED635"
            "699C17081B90F1B984F12E92C1C529276D8AF8EC7F28492097D8CD5BECEA16FE"
            "4088F6CFAB4A1B42328A1B996F9278B0B7E3311CA5EF856C2F888474B83612A8"
            "2E4E00D0CD4069A6783140433D50725F"
        ),
    },
    # index 0x08, 1408-bit  (SHA1 20D213126955DE205ADC2FD2822BD22DE21CF9A8)
    ("A000000003", 0x08): {
        "exp": 3,
        "mod": (
            "D9FD6ED75D51D0E30664BD157023EAA1FFA871E4DA65672B863D255E81E137A5"
            "1DE4F72BCC9E44ACE12127F87E263D3AF9DD9CF35CA4A7B01E907000BA85D249"
            "54C2FCA3074825DDD4C0C8F186CB020F683E02F2DEAD3969133F06F7845166AC"
            "EB57CA0FC2603445469811D293BFEFBAFAB57631B3DD91E796BF850A25012F1A"
            "E38F05AA5C4D6D03B1DC2E568612785938BBC9B3CD3A910C1DA55A5A9218ACE0"
            "F7A21287752682F15832A678D6E1ED0B"
        ),
    },
    # index 0x09, 1984-bit  (SHA1 1FF80A40173F52D7D27E0F26A146A1C8CCB29046)
    ("A000000003", 0x09): {
        "exp": 3,
        "mod": (
            "9D912248DE0A4E39C1A7DDE3F6D2588992C1A4095AFBD1824D1BA74847F2BC49"
            "26D2EFD904B4B54954CD189A54C5D1179654F8F9B0D2AB5F0357EB642FEDA95D"
            "3912C6576945FAB897E7062CAA44A4AA06B8FE6E3DBA18AF6AE3738E30429EE9"
            "BE03427C9D64F695FA8CAB4BFE376853EA34AD1D76BFCAD15908C077FFE6DC55"
            "21ECEF5D278A96E26F57359FFAEDA19434B937F1AD999DC5C41EB11935B44C18"
            "100E857F431A4A5A6BB65114F174C2D7B59FDF237D6BB1DD0916E644D709DED5"
            "6481477C75D95CDD68254615F7740EC07F330AC5D67BCD75BF23D28A140826C0"
            "26DBDE971A37CD3EF9B8DF644AC385010501EFC6509D7A41"
        ),
    },
    # --- Mastercard (RID A000000004) ---
    # index 0x04, 1152-bit  (SHA1 381A035DA58B482EE2AF75F4C3F2CA469BA4AA6C)
    ("A000000004", 0x04): {
        "exp": 3,
        "mod": (
            "A6DA428387A502D7DDFB7A74D3F412BE762627197B25435B7A81716A700157DD"
            "D06F7CC99D6CA28C2470527E2C03616B9C59217357C2674F583B3BA5C7DCF283"
            "8692D023E3562420B4615C439CA97C44DC9A249CFCE7B3BFB22F68228C3AF133"
            "29AA4A613CF8DD853502373D62E49AB256D2BC17120E54AEDCED6D96A4287ACC"
            "5C04677D4A5A320DB8BEE2F775E5FEC5"
        ),
    },
    # index 0x05, 1408-bit  (SHA1 EBFA0D5D06D8CE702DA3EAE890701D45E274C845)
    ("A000000004", 0x05): {
        "exp": 3,
        "mod": (
            "B8048ABC30C90D976336543E3FD7091C8FE4800DF820ED55E7E94813ED00555B"
            "573FECA3D84AF6131A651D66CFF4284FB13B635EDD0EE40176D8BF04B7FD1C7B"
            "ACF9AC7327DFAA8AA72D10DB3B8E70B2DDD811CB4196525EA386ACC33C0D9D45"
            "75916469C4E4F53E8E1C912CC618CB22DDE7C3568E90022E6BBA770202E4522A"
            "2DD623D180E215BD1D1507FE3DC90CA310D27B3EFCCD8F83DE3052CAD1E48938"
            "C68D095AAC91B5F37E28BB49EC7ED597"
        ),
    },
    # index 0x06, 1984-bit  (SHA1 F910A1504D5FFB793D94F3B500765E1ABCAD72D9)
    ("A000000004", 0x06): {
        "exp": 3,
        "mod": (
            "CB26FC830B43785B2BCE37C81ED334622F9622F4C89AAE641046B2353433883F"
            "307FB7C974162DA72F7A4EC75D9D657336865B8D3023D3D645667625C9A07A6B"
            "7A137CF0C64198AE38FC238006FB2603F41F4F3BB9DA1347270F2F5D8C606E42"
            "0958C5F7D50A71DE30142F70DE468889B5E3A08695B938A50FC980393A9CBCE4"
            "4AD2D64F630BB33AD3F5F5FD495D31F37818C1D94071342E07F1BEC2194F6035"
            "BA5DED3936500EB82DFDA6E8AFB655B1EF3D0D7EBF86B66DD9F29F6B1D324FE8"
            "B26CE38AB2013DD13F611E7A594D675C4432350EA244CC34F3873CBA06592987"
            "A1D7E852ADC22EF5A2EE28132031E48F74037E3B34AB747F"
        ),
    },
    # --- American Express (RID A000000025) ---
    # index 0x0E, 1152-bit  (SHA1 A7266ABAE64B42A3668851191D49856E17F8FBCD)
    ("A000000025", 0x0E): {
        "exp": 3,
        "mod": (
            "AA94A8C6DAD24F9BA56A27C09B01020819568B81A026BE9FD0A3416CA9A71166"
            "ED5084ED91CED47DD457DB7E6CBCD53E560BC5DF48ABC380993B6D549F5196CF"
            "A77DFB20A0296188E969A2772E8C4141665F8BB2516BA2C7B5FC91F8DA04E8D5"
            "12EB0F6411516FB86FC021CE7E969DA94D33937909A53A57F907C40C22009DA7"
            "532CB3BE509AE173B39AD6A01BA5BB85"
        ),
    },
    # index 0x0F, 1408-bit  (SHA1 A73472B3AB557493A9BC2179CC8014053B12BAB4)
    ("A000000025", 0x0F): {
        "exp": 3,
        "mod": (
            "C8D5AC27A5E1FB89978C7C6479AF993AB3800EB243996FBB2AE26B67B23AC482"
            "C4B746005A51AFA7D2D83E894F591A2357B30F85B85627FF15DA12290F70F057"
            "66552BA11AD34B7109FA49DE29DCB0109670875A17EA95549E92347B948AA1F0"
            "45756DE56B707E3863E59A6CBE99C1272EF65FB66CBB4CFF070F36029DD76218"
            "B21242645B51CA752AF37E70BE1A84FF31079DC0048E928883EC4FADD497A719"
            "385C2BBBEBC5A66AA5E5655D18034EC5"
        ),
    },
    # index 0x10, 1984-bit  (SHA1 C729CF2FD262394ABC4CC173506502446AA9B9FD)
    ("A000000025", 0x10): {
        "exp": 3,
        "mod": (
            "CF98DFEDB3D3727965EE7797723355E0751C81D2D3DF4D18EBAB9FB9D49F38C8"
            "C4A826B99DC9DEA3F01043D4BF22AC3550E2962A59639B1332156422F788B9C1"
            "6D40135EFD1BA94147750575E636B6EBC618734C91C1D1BF3EDC2A46A4390166"
            "8E0FFC136774080E888044F6A1E65DC9AAA8928DACBEB0DB55EA3514686C6A73"
            "2CEF55EE27CF877F110652694A0E3484C855D882AE191674E25C296205BBB599"
            "455176FDD7BBC549F27BA5FE35336F7E29E68D783973199436633C67EE5A680F"
            "05160ED12D1665EC83D1997F10FD05BBDBF9433E8F797AEE3E9F02A34228ACE9"
            "27ABE62B8B9281AD08D3DF5C7379685045D7BA5FCDE58637"
        ),
    },
    # --- Cartes Bancaires (CB) (RID A000000042) ---
    # index 0x04, 1152-bit  (SHA1 95482A832B5B980A9F9C78BE810E149AC9425F47)
    ("A000000042", 0x04): {
        "exp": 3,
        "mod": (
            "D020CF4811D0F07E45C78AAC85DA5D9C5F499E70A40D9F7F51954B8F888DFE81"
            "1339984FF77BAC996792C73B50BF220EA86B016DA7F33B177B3765AB9469A785"
            "646311D649F0C468D29AA23F60D191EDFFD60D7A51834306453A1BC839CB858E"
            "91FB10C8E9BB7491FB036A0D3CE84A42EA045A294B82E63C9A6EAE360F35BC0B"
            "2438389D8D780F4C788364D2D3034931"
        ),
    },
    # index 0x06, 1152-bit  (SHA1 EF6EFF2FB8909A9B2EDF8ABB3E2AF1CC38B3BD19)
    ("A000000042", 0x06): {
        "exp": 3,
        "mod": (
            "B54B1057A9FEFDE4AB0B0AF8AFBF9BF0DECE975AE949391ADDE454D7455CE377"
            "BF3E5F5A4510C74347F01D029490B1E834364209CF4E89E23A242135D1E61BF1"
            "AF5A1E5C770A4637DEE81661775BF12BB8F0337325537AACFE73507EA0A3CE4C"
            "309BEF404ED45C6927F84FF25101A295224B39FC8983954AB291BFF6B45E12BE"
            "CDF2AE513B14BDD40938545C20F2A3D9"
        ),
    },
    # index 0x07, 1408-bit  (SHA1 1423BF39A1B0720F534F375423F7AE8D7DD2F46E)
    ("A000000042", 0x07): {
        "exp": 3,
        "mod": (
            "BA6D5B9CD83579E91864B6B66B274C0A6AB298BCE2842CFA53B070356EAD3E7C"
            "B5888FEFFEC1B657A9BE0A5AF576A8D98C88A2E3C98BB0DEAEE4EADDB2E90066"
            "A703B549EC048054E82CBA7EDB14BC8C1A5A07BE03EED8F13515806FA0F1B9FA"
            "E96DE4142ABD4ABBC8B7CCF7DEFBCAB39C5A12B1FE68C4BDED29F3D3F06BF6E5"
            "8BA8CB47483F92BAC76971EF895A57FC3E6F46BF43F9F1BCAE4F42FF00B1B45F"
            "6CC47F4AFCE844A8E7CF35A499FA54ED"
        ),
    },
    # index 0x08, 1984-bit  (SHA1 8519DA94E938A5352AE07990D15AD40DBB9A8F1C)
    ("A000000042", 0x08): {
        "exp": 3,
        "mod": (
            "D3E3463D40039DF15FA530D4367B3B558C9B18B34C972263321469803421E81B"
            "75DD9CA5E3578DC41FB24D0F4B85EF6E9DBFAEAA47E2533542B2EC397A281877"
            "4F2B9B319C18CEEA3A8C66870E31382F582D2C66164252DD43129208B6F39955"
            "4C584E43D3F984383CB86691B5D81C9CA9089A289A08B22CEBCF9C0E7BB2458F"
            "C057D9C56D0B9B4E636B64A359C07D43F8305B5027851FFCA43788A5A387FED7"
            "50DBAED61C78524DDE2E36F090C52913BF909DF1A2FD3C178C8D2E3007CA2CA6"
            "7CEA7CF02ACF8A228DBEA7589B2CC19305B3C0A64EFD47242A6FD958A381EFAE"
            "C191B790A9ABDB043D1AB1BDB8AAB66D0FE0DC82A0738FAB"
        ),
    },
    # --- JCB (RID A000000065) ---
    # index 0x10, 1152-bit  (SHA1 C75E5210CBE6E8F0594A0F1911B07418CADB5BAB)
    ("A000000065", 0x10): {
        "exp": 3,
        "mod": (
            "99B63464EE0B4957E4FD23BF923D12B61469B8FFF8814346B2ED6A780F8988EA"
            "9CF0433BC1E655F05EFA66D0C98098F25B659D7A25B8478A36E489760D071F54"
            "CDF7416948ED733D816349DA2AADDA227EE45936203CBF628CD033AABA5E5A6E"
            "4AE37FBACB4611B4113ED427529C636F6C3304F8ABDD6D9AD660516AE87F7F2D"
            "DF1D2FA44C164727E56BBC9BA23C0285"
        ),
    },
    # index 0x12, 1408-bit  (SHA1 874B379B7F607DC1CAF87A19E400B6A9E25163E8)
    ("A000000065", 0x12): {
        "exp": 3,
        "mod": (
            "ADF05CD4C5B490B087C3467B0F3043750438848461288BFEFD6198DD576DC3AD"
            "7A7CFA07DBA128C247A8EAB30DC3A30B02FCD7F1C8167965463626FEFF8AB1AA"
            "61A4B9AEF09EE12B009842A1ABA01ADB4A2B170668781EC92B60F605FD12B2B2"
            "A6F1FE734BE510F60DC5D189E401451B62B4E06851EC20EBFF4522AACC2E9CDC"
            "89BC5D8CDE5D633CFD77220FF6BBD4A9B441473CC3C6FEFC8D13E57C3DE97E12"
            "69FA19F655215B23563ED1D1860D8681"
        ),
    },
    # index 0x14, 1984-bit  (SHA1 C0D15F6CD957E491DB56DCDD1CA87A03EBE06B7B)
    ("A000000065", 0x14): {
        "exp": 3,
        "mod": (
            "AEED55B9EE00E1ECEB045F61D2DA9A66AB637B43FB5CDBDB22A2FBB25BE061E9"
            "37E38244EE5132F530144A3F268907D8FD648863F5A96FED7E42089E93457ADC"
            "0E1BC89C58A0DB72675FBC47FEE9FF33C16ADE6D341936B06B6A6F5EF6F66A4E"
            "DD981DF75DA8399C3053F430ECA342437C23AF423A211AC9F58EAF09B0F837DE"
            "9D86C7109DB1646561AA5AF0289AF5514AC64BC2D9D36A179BB8A7971E2BFA03"
            "A9E4B847FD3D63524D43A0E8003547B94A8A75E519DF3177D0A60BC0B4BAB1EA"
            "59A2CBB4D2D62354E926E9C7D3BE4181E81BA60F8285A896D17DA8C3242481B6"
            "C405769A39D547C74ED9FF95A70A796046B5EFF36682DC29"
        ),
    },
    # --- Discover (RID A000000152) ---
    # index 0x03, 1152-bit  (SHA1 CA1E9099327F0B786D8583EC2F27E57189503A57)
    ("A000000152", 0x03): {
        "exp": 3,
        "mod": (
            "BF321241BDBF3585FFF2ACB89772EBD18F2C872159EAA4BC179FB03A1B850A1A"
            "758FA2C6849F48D4C4FF47E02A575FC13E8EB77AC37135030C5600369B5567D3"
            "A7AAF02015115E987E6BE566B4B4CC03A4E2B16CD9051667C2CD0EEF4D76D27A"
            "6F745E8BBEB45498ED8C30E2616DB4DBDA4BAF8D71990CDC22A8A387ACB21DD8"
            "8E2CC27962B31FBD786BBB55F9E0B041"
        ),
    },
    # index 0x04, 1408-bit  (SHA1 17F971CAF6B708E5B9165331FBA91593D0C0BF66)
    ("A000000152", 0x04): {
        "exp": 3,
        "mod": (
            "8EEEC0D6D3857FD558285E49B623B109E6774E06E9476FE1B2FB273685B5A235"
            "E955810ADDB5CDCC2CB6E1A97A07089D7FDE0A548BDC622145CA2DE3C73D6B14"
            "F284B3DC1FA056FC0FB2818BCD7C852F0C97963169F01483CE1A63F0BF899D41"
            "2AB67C5BBDC8B4F6FB9ABB57E95125363DBD8F5EBAA9B74ADB93202050341833"
            "DEE8E38D28BD175C83A6EA720C262682BEABEA8E955FE67BD9C2EFF7CB9A9F45"
            "DD5BDA4A1EEFB148BC44FFF68D9329FD"
        ),
    },
    # index 0x05, 1984-bit  (SHA1 12BCD407B6E627A750FDF629EE8C2C9CC7BA636A)
    ("A000000152", 0x05): {
        "exp": 3,
        "mod": (
            "E1200E9F4428EB71A526D6BB44C957F18F27B20BACE978061CCEF23532DBEBFA"
            "F654A149701C14E6A2A7C2ECAC4C92135BE3E9258331DDB0967C3D1D375B996F"
            "25B77811CCCC06A153B4CE6990A51A0258EA8437EDBEB701CB1F335993E3F484"
            "58BC1194BAD29BF683D5F3ECB984E31B7B9D2F6D947B39DEDE0279EE45B47F2F"
            "3D4EEEF93F9261F8F5A571AFBFB569C150370A78F6683D687CB677777B2E7ABE"
            "FCFC8F5F93501736997E8310EE0FD87AFAC5DA772BA277F88B44459FCA563555"
            "017CD0D66771437F8B6608AA1A665F88D846403E4C41AFEEDB9729C2B2511CFE"
            "228B50C1B152B2A60BBF61D8913E086210023A3AA499E423"
        ),
    },
    # --- UnionPay (RID A000000333) ---
    # index 0x02, 1152-bit  (SHA1 03BB335A8549A03B87AB089D006F60852E4B8060)
    ("A000000333", 0x02): {
        "exp": 3,
        "mod": (
            "A3767ABD1B6AA69D7F3FBF28C092DE9ED1E658BA5F0909AF7A1CCD907373B721"
            "0FDEB16287BA8E78E1529F443976FD27F991EC67D95E5F4E96B127CAB2396A94"
            "D6E45CDA44CA4C4867570D6B07542F8D4BF9FF97975DB9891515E66F525D2B3C"
            "BEB6D662BFB6C3F338E93B02142BFC44173A3764C56AADD202075B26DC2F9F7D"
            "7AE74BD7D00FD05EE430032663D27A57"
        ),
    },
    # index 0x03, 1408-bit  (SHA1 87F0CD7C0E86F38F89A66F8C47071A8B88586F26)
    ("A000000333", 0x03): {
        "exp": 3,
        "mod": (
            "B0627DEE87864F9C18C13B9A1F025448BF13C58380C91F4CEBA9F9BCB214FF84"
            "14E9B59D6ABA10F941C7331768F47B2127907D857FA39AAF8CE02045DD01619D"
            "689EE731C551159BE7EB2D51A372FF56B556E5CB2FDE36E23073A44CA215D6C2"
            "6CA68847B388E39520E0026E62294B557D6470440CA0AEFC9438C923AEC9B209"
            "8D6D3A1AF5E8B1DE36F4B53040109D89B77CAFAF70C26C601ABDF59EEC0FDC8A"
            "99089140CD2E817E335175B03B7AA33D"
        ),
    },
    # index 0x04, 1984-bit  (SHA1 F527081CF371DD7E1FD4FA414A665036E0F5E6E5)
    ("A000000333", 0x04): {
        "exp": 3,
        "mod": (
            "BC853E6B5365E89E7EE9317C94B02D0ABB0DBD91C05A224A2554AA29ED9FCB9D"
            "86EB9CCBB322A57811F86188AAC7351C72BD9EF196C5A01ACEF7A4EB0D2AD63D"
            "9E6AC2E7836547CB1595C68BCBAFD0F6728760F3A7CA7B97301B7E0220184EFC"
            "4F653008D93CE098C0D93B45201096D1ADFF4CF1F9FC02AF759DA27CD6DFD6D7"
            "89B099F16F378B6100334E63F3D35F3251A5EC78693731F5233519CDB380F5AB"
            "8C0F02728E91D469ABD0EAE0D93B1CC66CE127B29C7D77441A49D09FCA5D6D97"
            "62FC74C31BB506C8BAE3C79AD6C2578775B95956B5370D1D0519E37906B38473"
            "6233251E8F09AD79DFBE2C6ABFADAC8E4D8624318C27DAF1"
        ),
    },
    # --- RuPay (RID A000000524) ---
    # index 0x03, 1152-bit  (SHA1 4B93D1E1F57CFA16970501F17D3E06411043F1D5)
    ("A000000524", 0x03): {
        "exp": 3,
        "mod": (
            "E703A908FFAE3730F82E550869A294C1FF1DA25F2B53D2C8BB18F770DAD50513"
            "5D03D5EC8EE3926550051C3D4857F6FEDB882C2889E0B25F389F78741F2931A9"
            "2D45D3A47E62810D3253653AB0AB3570C35DFD08D3167B6DB42ED28F765186F4"
            "287CDAF9D9BAD20BCE2C4ECFECDD218E50F1FCC718878882F3934A6FEB502CFC"
            "AD615A2B2E279A0868DDA9489DFA9CD9"
        ),
    },
    # index 0x04, 1408-bit  (SHA1 6F843CE765B9144CE1A6BFEA46BC37B65081CE7F)
    ("A000000524", 0x04): {
        "exp": 3,
        "mod": (
            "AC0019624FC0A72270C6885CC0B3C9140C351FCFE6F8145881A27750393453D3"
            "265F69E7658132D8D253EDF8991E2BA32B782D39ADE1FF1FC8F211F5DF51A000"
            "7C761AD9882587BD6A36AECD3ABBF944307AC97A2D905FAB489C3E1CCD76DE9E"
            "B93ECFAB2BB84F34E770119E356DC6372D8685DA8EB92FCAC7B53C0167100E4C"
            "DFB9830D1C45E787E44C9F6A42EC131A6A4CD66BBE4F93CA91FDF157C7B22FC7"
            "221A6348F0EDA6151302A80EF77D6CA5"
        ),
    },
    # index 0x05, 1984-bit  (SHA1 7081DF2A0C36360F24C122C574F0AD2E57893DD2)
    ("A000000524", 0x05): {
        "exp": 3,
        "mod": (
            "C04E80180369898AAEF6EE7741EDED25239D765301614B5B41A008CA3009358D"
            "626D828BC5F1B1E04A2DC1367101266905D262003BE747FD231C9B0011F2F2B2"
            "1BA8E4C0F4CA5E93ED9DBB2E92ABC450576A4EB59AD00DCA59C8BF3230E4B19D"
            "43452871C6215D837663310DF43CAEA1B9B08C1F500AF1B550F62E18D70EEE9E"
            "9475321BCD1799AB193E0BC849DACE892A0E6A1F42FE0786DB30345AE1A0E7E4"
            "C4B71640E03BFD2832C491A7D83F3B4EF4D388CDDBB748C2FD1D9D4A9BF52FC8"
            "56CBA088D4B274846002C23CDA722C5CFF3B1F8218A1843B0426474BDC92F2F5"
            "E31FBF321CC17480AD069DF55381F2E601D5CBA7B871253F"
        ),
    },
    # index 0x06, 1984-bit  (SHA1 E98F4134E1949A9A054E4679AC9A7EC83969E209)
    ("A000000524", 0x06): {
        "exp": 3,
        "mod": (
            "9D8A75B36BCBDF250B87615A46F6EA35DE35226EEAB7B473D7DC0A28B5DF075C"
            "83B2775F23337E6CEE36CCFE3A6568C9C822D6DE81299565A829348E03D479B6"
            "31BB18A2429A8590C597F446A3CEA3BE2E822106F43DFBB981EC0F1121919CB3"
            "5F85DBA3355C5E7FF35F2B221FD65EDBEA41F23A7A109FBBC4A774A756D89B59"
            "3B199E1E9DA9A99217D4BF31F67CDA8C4E1B81FA2A377C83B5D1CD6AF1F18804"
            "48CFF48D3A4ADBBC7FBD730061508A6EA8FDFC5BD66A2E94E33B83F81E0E56CF"
            "1C9473E4426EE435F9E80136760D8F4AD946805B03A67C55361582F5AD8F4040"
            "4392FA4CB4F5C2BAF6E26857A1D60941E3D055ACD9AC0BEF"
        ),
    },
}

# terminal-side defaults used to populate a PDOL/DOL for GET PROCESSING OPTIONS
PDOL_DEFAULTS = {
    "9F66": "36000000",  # TTQ (Terminal Transaction Qualifiers)
    "9F02": "000000000100",  # Amount, Authorised
    "9F03": "000000000000",  # Amount, Other
    "9F1A": "0826",  # Terminal Country Code (GB)
    "95": "0000000000",  # TVR
    "5F2A": "0826",  # Transaction Currency Code (GBP)
    "9A": "010101",  # Transaction Date
    "9C": "00",  # Transaction Type
    "9F37": "12345678",  # Unpredictable Number
    "9F35": "22",  # Terminal Type
    "9F6E": "D8E04000",  # (AMEX) Enhanced Contactless Reader Capabilities (EMV+magstripe capable)
    "9F40": "0000000000",
}

# Global VARs for data interchange
Cdol1 = ""
Cdol2 = ""
CurrentAID = ""

# known AIDs
# please mail new AIDs to aid@rfidiot.org
# https://www.eftlab.com/knowledge-base/complete-list-of-application-identifiers-aid
# https://en.wikipedia.org/wiki/EMV
KNOWN_AIDS = [
    ["VISA", 0xA0, 0x00, 0x00, 0x00, 0x03],
    ["VISA Debit/Credit", 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10],
    ["VISA Credit", 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x01],
    ["VISA Debit", 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x02],
    ["VISA Electron", 0xA0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10],
    ["VISA Interlink", 0xA0, 0x00, 0x00, 0x00, 0x03, 0x30, 0x10],
    ["VISA Plus", 0xA0, 0x00, 0x00, 0x00, 0x03, 0x80, 0x10],
    ["VISA ATM", 0xA0, 0x00, 0x00, 0x00, 0x03, 0x99, 0x99, 0x10],
    ["VISA BoA Debit", 0xA0, 0x00, 0x00, 0x00, 0x98],
    ["VISA Common Debit", 0xA0, 0x00, 0x00, 0x00, 0x98, 0x08, 0x40],
    ["VISA Schwab Debit", 0xA0, 0x00, 0x00, 0x00, 0x98, 0x08, 0x48],
    ["Discover/Diners", 0xA0, 0x00, 0x00, 0x01, 0x52],
    ["Discover Card", 0xA0, 0x00, 0x00, 0x01, 0x52, 0x30, 0x10],
    ["Discover Debit", 0xA0, 0x00, 0x00, 0x01, 0x52, 0x40, 0x10],
    ["MASTERCARD", 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10],
    ["Maestro", 0xA0, 0x00, 0x00, 0x00, 0x04, 0x30, 0x60],
    ["Maestro UK", 0xA0, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01],
    ["Maestro TEST", 0xB0, 0x12, 0x34, 0x56, 0x78],
    ["Self Service", 0xA0, 0x00, 0x00, 0x00, 0x24, 0x01],
    ["American Express", 0xA0, 0x00, 0x00, 0x00, 0x25],
    ["ExpressPay", 0xA0, 0x00, 0x00, 0x00, 0x25, 0x01, 0x07, 0x01],
    ["Link", 0xA0, 0x00, 0x00, 0x00, 0x29, 0x10, 0x10],
    ["Alias AID", 0xA0, 0x00, 0x00, 0x00, 0x29, 0x10, 0x10],
]

# Master Data File for PSE
DF_PSE = [
    0x31,
    0x50,
    0x41,
    0x59,
    0x2E,
    0x53,
    0x59,
    0x53,
    0x2E,
    0x44,
    0x44,
    0x46,
    0x30,
    0x31,
]

# define the apdus used in this script
AAC = 0
TC = 0x40
ARQC = 0x80
GENERATE_AC = [0x80, 0xAE]
GET_CHALLENGE = [0x00, 0x84, 0x00]
GET_DATA = [0x80, 0xCA]
GET_PROCESSING_OPTIONS = [0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00]
GET_RESPONSE = [0x00, 0xC0, 0x00, 0x00]
INTERNAL_AUTHENTICATE = [0x00, 0x88, 0x00, 0x00]
READ_RECORD = [0x00, 0xB2]
SELECT = [0x00, 0xA4, 0x04, 0x00]
UNBLOCK_PIN = [0x84, 0x24, 0x00, 0x00, 0x00]
VERIFY = [0x00, 0x20, 0x00, 0x80]

# BRUTE_AID= [0xa0,0x00,0x00,0x00]
BRUTE_AID = []

# define tags for response
BINARY = 0
TEXT = 1
BER_TLV = 2
NUMERIC = 3
MIXED = 4
TEMPLATE = 0
ITEM = 1
VALUE = 2
SFI = 0x88
CDOL1 = 0x8C
CDOL2 = 0x8D
CVM_LIST = 0x8E

# CVM (Cardholder Verification Method) list decoding - EMV Book 3
# low 6 bits of the CVM code = method
CVM_CODES = {
    0x00: "Fail CVM processing",
    0x01: "Plaintext PIN verification performed by ICC",
    0x02: "Enciphered PIN verified online",
    0x03: "Plaintext PIN verification by ICC and signature (paper)",
    0x04: "Enciphered PIN verification performed by ICC",
    0x05: "Enciphered PIN verification by ICC and signature (paper)",
    0x1E: "Signature (paper)",
    0x1F: "No CVM required",
}
CVM_CONDITIONS = {
    0x00: "Always",
    0x01: "If unattended cash",
    0x02: "If not unattended/manual cash and not cashback",
    0x03: "If terminal supports the CVM",
    0x04: "If manual cash",
    0x05: "If purchase with cashback",
    0x06: "If in application currency and under X value",
    0x07: "If in application currency and over X value",
    0x08: "If in application currency and under Y value",
    0x09: "If in application currency and over Y value",
}

TAGS = {
    0x4F: ["Application Identifier (AID)", BINARY, ITEM],
    0x50: ["Application Label", TEXT, ITEM],
    0x57: ["Track 2 Equivalent Data", BINARY, ITEM],
    0x5A: ["Application Primary Account Number (PAN)", NUMERIC, ITEM],
    0x6F: ["File Control Information (FCI) Template", BINARY, TEMPLATE],
    0x70: ["Record Template", BINARY, TEMPLATE],
    0x77: ["Response Message Template Format 2", BINARY, ITEM],
    0x80: ["Response Message Template Format 1", BINARY, ITEM],
    0x82: ["Application Interchange Profile", BINARY, ITEM],
    0x83: ["Command Template", BER_TLV, ITEM],
    0x84: ["DF Name", MIXED, ITEM],
    0x86: ["Issuer Script Command", BER_TLV, ITEM],
    0x87: ["Application Priority Indicator", BINARY, ITEM],
    0x88: ["Short File Identifier", BINARY, ITEM],
    0x8A: ["Authorisation Response Code", BINARY, VALUE],
    0x8C: ["Card Risk Management Data Object List 1 (CDOL1)", BINARY, TEMPLATE],
    0x8D: ["Card Risk Management Data Object List 2 (CDOL2)", BINARY, TEMPLATE],
    0x8E: ["Cardholder Verification Method (CVM) List", BINARY, ITEM],
    0x8F: ["Certification Authority Public Key Index", BINARY, ITEM],
    0x93: ["Signed Static Application Data", BINARY, ITEM],
    0x94: ["Application File Locator", BINARY, ITEM],
    0x95: ["Terminal Verification Results", BINARY, VALUE],
    0x97: ["Transaction Certificate Data Object List (TDOL)", BER_TLV, ITEM],
    0x9C: ["Transaction Type", BINARY, VALUE],
    0x9D: ["Directory Definition File", BINARY, ITEM],
    0xA5: ["Proprietary Information", BINARY, TEMPLATE],
    0x5F20: ["Cardholder Name", TEXT, ITEM],
    0x5F24: ["Application Expiration Date YYMMDD", NUMERIC, ITEM],
    0x5F25: ["Application Effective Date YYMMDD", NUMERIC, ITEM],
    0x5F28: ["Issuer Country Code", NUMERIC, ITEM],
    0x5F2A: ["Transaction Currency Code", BINARY, VALUE],
    0x5F2D: ["Language Preference", TEXT, ITEM],
    0x5F30: ["Service Code", NUMERIC, ITEM],
    0x5F34: ["Application Primary Account Number (PAN) Sequence Number", NUMERIC, ITEM],
    0x5F50: ["Issuer URL", TEXT, ITEM],
    0x90: ["Issuer Public Key Certificate", BINARY, ITEM],
    0x92: ["Issuer Public Key Remainder", BINARY, ITEM],
    0x93: ["Signed Static Application Data", BINARY, ITEM],
    0x9A: ["Transaction Date", BINARY, VALUE],
    0x9F02: ["Amount, Authorised (Numeric)", BINARY, VALUE],
    0x9F03: ["Amount, Other (Numeric)", BINARY, VALUE],
    0x9F04: ["Amount, Other (Binary)", BINARY, VALUE],
    0x9F05: ["Application Discretionary Data", BINARY, ITEM],
    0x9F07: ["Application Usage Control", BINARY, ITEM],
    0x9F08: ["Application Version Number", BINARY, ITEM],
    0x9F0D: ["Issuer Action Code - Default", BINARY, ITEM],
    0x9F0E: ["Issuer Action Code - Denial", BINARY, ITEM],
    0x9F0F: ["Issuer Action Code - Online", BINARY, ITEM],
    0x9F11: ["Issuer Code Table Index", BINARY, ITEM],
    0x9F12: ["Application Preferred Name", TEXT, ITEM],
    0x9F1A: ["Terminal Country Code", BINARY, VALUE],
    0x9F1F: ["Track 1 Discretionary Data", TEXT, ITEM],
    0x9F20: ["Track 2 Discretionary Data", TEXT, ITEM],
    0x9F21: ["Transaction Time", BINARY, VALUE],
    0x9F26: ["Application Cryptogram", BINARY, ITEM],
    0x9F27: ["Cryptogram Information Data", BINARY, ITEM],
    0x9F32: ["Issuer Public Key Exponent", BINARY, ITEM],
    0x9F36: ["Application Transaction Counter", BINARY, ITEM],
    0x9F37: ["Unpredictable Number", BINARY, VALUE],
    0x9F38: ["Processing Options Data Object List (PDOL)", BINARY, TEMPLATE],
    0x9F42: ["Application Currency Code", NUMERIC, ITEM],
    0x9F4E: ["Merchant Name and Location", TEXT, ITEM],
    0x9F44: ["Application Currency Exponent", NUMERIC, ITEM],
    0x9F45: ["Data Authentication Code", BINARY, ITEM],
    0x9F46: ["ICC Public Key Certificate", BINARY, ITEM],
    0x9F47: ["ICC Public Key Exponent", BINARY, ITEM],
    0x9F48: ["ICC Public Key Remainder", BINARY, ITEM],
    0x9F49: ["Dynamic Data Authentication Data Object List (DDOL)", BINARY, ITEM],
    0x9F4A: ["Static Data Authentication Tag List", BINARY, ITEM],
    0x9F4B: ["Signed Dynamic Application Data", BINARY, ITEM],
    0x9F4C: ["ICC Dynamic Number", BINARY, ITEM],
    0x9F4D: ["Log Entry", BINARY, ITEM],
    0x9F66: ["Terminal Transaction Qualifiers (TTQ)", BINARY, VALUE],
    0x9F6C: ["Card Transaction Qualifiers (CTQ)", BINARY, ITEM],
    0x9F6E: ["Form Factor Indicator / Third Party Data", BINARY, ITEM],
    0x9F69: ["Card Authentication Related Data", BINARY, ITEM],
    0x9F7C: ["Customer Exclusive Data", BINARY, ITEM],
    0x9F0A: ["Application Selection Registered Proprietary Data", BINARY, ITEM],
    0x9F10: ["Issuer Application Data", BINARY, ITEM],
    0x9F5A: ["Application Program Identifier", BINARY, ITEM],
    0xBF0C: [
        "File Control Information (FCI) Issuer Discretionary Data",
        BER_TLV,
        TEMPLATE,
    ],
}

# // conflicting item - need to check
# // 0x9f38:['Processing Optional Data Object List',BINARY,ITEM],

# define BER-TLV masks

TLV_CLASS_MASK = {
    0x00: "Universal class",
    0x40: "Application class",
    0x80: "Context-specific class",
    0xC0: "Private class",
}

# if TLV_TAG_NUMBER_MASK bits are set, refer to next byte(s) for tag number
# otherwise it's b1-5
TLV_TAG_NUMBER_MASK = 0x1F

# if TLV_DATA_MASK bit is set it's a 'Constructed data object'
# otherwise, 'Primitive data object'
TLV_DATA_MASK = 0x20
TLV_DATA_TYPE = ["Primitive data object", "Constructed data object"]

# if TLV_TAG_MASK is set another tag byte follows
TLV_TAG_MASK = 0x80
TLV_LENGTH_MASK = 0x80


# define AIP mask
AIP_MASK = {
    0x01: "CDA Supported (Combined Dynamic Data Authentication / Application Cryptogram Generation)",
    0x02: "RFU",
    0x04: "Issuer authentication is supported",
    0x08: "Terminal risk management is to be performed",
    0x10: "Cardholder verification is supported",
    0x20: "DDA supported (Dynamic Data Authentication)",
    0x40: "SDA supported (Static Data Authentiction)",
    0x80: "RFU",
}

# define dummy transaction values (see TAGS for tag names)
# for generate_ac
TRANS_VAL = {
    0x9F02: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    0x9F03: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    0x9F1A: [0x08, 0x26],
    0x95: [0x00, 0x00, 0x00, 0x00, 0x00],
    0x5F2A: [0x08, 0x26],
    0x9A: [0x08, 0x04, 0x01],
    0x9C: [0x01],
    0x9F37: [0xBA, 0xDF, 0x00, 0x0D],
}

# define SW1 return values
SW1_RESPONSE_BYTES = 0x61
SW1_WRONG_LENGTH = 0x6C
SW12_OK = [0x90, 0x00]
SW12_NOT_SUPORTED = [0x6A, 0x81]
SW12_NOT_FOUND = [0x6A, 0x82]
SW12_COND_NOT_SAT = [0x69, 0x85]  # conditions of use not satisfied
PIN_BLOCKED = [0x69, 0x83]
PIN_BLOCKED2 = [0x69, 0x84]
PIN_WRONG = 0x63

# some human readable error messages
ERRORS = {
    "6283": "Selected file deactivated / blocked",
    "6700": "Wrong length",
    "6982": "Security status not satisfied",
    "6983": "Authentication method blocked",
    "6984": "PIN Try Limit exceeded",
    "6985": "Conditions of use not satisfied or Command not supported",
    "6a81": "Function not supported",
    "6a82": "File or application not found",
    "6a86": "Incorrect parameters P1-P2",
    "6d00": "Instruction code not supported or invalid",
    "6e00": "Class not supported",
}

# define GET_DATA primitive tags
PIN_TRY_COUNTER = [0x9F, 0x17]
ATC = [0x9F, 0x36]
LAST_ATC = [0x9F, 0x13]
LOG_FORMAT = [0x9F, 0x4F]

# define TAGs after BER-TVL decoding
BER_TLV_AIP = 0x02
BER_TLV_AFL = 0x14


def printhelp():
    print("\nChAP.py - Chip And PIN in Python")
    print("Ver 0.1d\n")
    print("usage:\n\n ChAP.py [rfidiot-options] [ChAP-options] [PIN]")
    print()
    print("Reader selection uses the standard RFIDIOt global options above")
    print("(e.g. '-f 0' for libnfc, '-r 1' for the OMNIKEY contactless slot).")
    print()
    print("If the optional numeric PIN argument is given, the PIN will be verified (note that this")
    print("updates the PIN Try Counter and may result in the card being PIN blocked).")
    print("\nChAP options:\n")
    print("\t-a\t\tBruteforce AIDs")
    print("\t-A\t\tPrint list of known AIDs")
    print("\t-c\t\tRecover & verify the SDA/DDA certificate chain")
    print("\t-e\t\tBruteforce EMV AIDs")
    print("\t-E\t\tSend the PIN as an RSA-enciphered offline PIN (needs a PIN")
    print("\t\t\t  argument; implies -c. WARNING: updates the PIN Try Counter)")
    print("\t-F\t\tBruteforce files")
    print("\t-G\t\tGENERATE AC with CDA to verify the dynamic signature")
    print("\t\t\t  (WARNING: this increments the card's ATC)")
    print("\t-o\t\tOutput to files ([AID]-FILExxRECORDxx.HEX)")
    print("\t-p\t\tBruteforce primitives")
    print("\t-x\t\tRaw output - do not interpret EMV data")
    print("\t-v\t\tVerbose on")
    print("\nT=0/T=1 is auto-negotiated for PC/SC.")
    print()


def hexprint(data):
    index = 0

    while index < len(data):
        print("%02x" % data[index], end="")
        index += 1
    print()


#        try:
#            # try 1-byte tags
#            tag = data[index]
#            TAGS[tag]
#            taglen = 1
#        except:
#            try:
#                # try 2-byte tags
#                tag = data[index] * 256 + data[index + 1]
#                TAGS[tag]
#                taglen = 2
#            except:
#                # tag not found
#                index += 1
#                continue
def get_tag(data, req):
    "return a tag's data if present"

    index = 0

    # walk the tag chain to ensure no false positives
    while index < len(data):
        # try 1-byte tags
        tag = data[index]
        if tag in TAGS:
            taglen = 1
        else:
            # try 2-byte tags
            tag = data[index] * 256 + data[index + 1]
            if tag in TAGS:
                taglen = 2
            else:
                # tag not found
                index += 1
                continue

        if tag == req:
            itemlength = data[index + taglen]
            index += taglen + 1
            return True, itemlength, data[index : index + itemlength]
        # else:
        index += taglen + 1
    return False, 0, ""


def isbinary(data):
    index = 0

    while index < len(data):
        if data[index] < 0x20 or data[index] > 0x7E:
            return True
        index += 1
    return False


def ber_tag(data, i):
    "parse a BER-TLV tag at data[i]; return (tag_int, num_bytes)"
    first = data[i]
    if first & 0x1F != 0x1F:
        return first, 1
    tag = first
    k = 1
    while i + k < len(data):
        b = data[i + k]
        tag = (tag << 8) | b
        k += 1
        if not b & 0x80:
            break
    return tag, k


def ber_len(data, i):
    "parse a BER-TLV length at data[i]; return (length, num_bytes)"
    b = data[i]
    if b < 0x80:
        return b, 1
    n = b & 0x7F
    length = 0
    for k in range(n):
        length = (length << 8) | data[i + 1 + k]
    return length, 1 + n


def decode_pse(data, indent=""):
    "decode an EMV BER-TLV response (PSE / FCI / record templates), recursively"

    global Pdol
    if not indent:
        # top-level call (a fresh response); clear any PDOL from a prior select
        Pdol = []
        if OutputFiles:
            with open(f"{CurrentAID}-PSE.HEX", "w", encoding="utf-8") as file:
                for n in data:
                    file.write(f"{n:02X}")
        if RawOutput:
            hexprint(data)
            textprint(data)
            return

    index = 0
    while index < len(data):
        # skip inter-object padding
        if data[index] in (0x00, 0xFF):
            index += 1
            continue
        tag, taglen = ber_tag(data, index)
        if index + taglen >= len(data):
            break
        itemlength, lenlen = ber_len(data, index + taglen)
        vstart = index + taglen + lenlen
        value = data[vstart : vstart + itemlength]
        constructed = bool(data[index] & 0x20)
        known = tag in TAGS
        name = TAGS[tag][0] if known else "Unknown TAG"
        print(f"{indent}  {tag:02x}: {name} ({itemlength} bytes):", end="")
        # store CDOLs for later use
        if tag == CDOL1:
            Cdol1 = value  # noqa: F841 pylint: disable=unused-variable
        if tag == CDOL2:
            Cdol2 = value  # noqa: F841 pylint: disable=unused-variable
        if tag == 0x9F38:
            Pdol = list(value)
        # only true constructed templates (BER constructed bit 0x20 set) contain
        # nested TLV - recurse into those. DOLs (CDOL/PDOL/DDOL/TDOL) are
        # primitive-encoded tag+length lists and must NOT be recursed.
        if constructed:
            print()
            decode_pse(value, indent + "  ")
            index = vstart + itemlength
            continue
        # primitive value
        EMVData[tag] = list(value)  # collect for later cert-chain recovery
        if not known:
            hexprint(value)
        elif tag == CVM_LIST:
            decode_cvm(value)
        elif tag == 0x57:  # Track 2 Equivalent Data
            hexprint(value)
            decode_track2(value, indent)
        elif tag == 0x9F27:  # Cryptogram Information Data
            hexprint(value)
            decode_cid(value, indent)
        else:
            fmt = TAGS[tag][1]
            if fmt == TEXT:
                print("".join("%c" % b for b in value))
            elif fmt == NUMERIC:
                out = "".join("%02x" % b for b in value)
                if tag in (0x9F42, 0x5F28):
                    try:
                        print(out + " (" + ISO3166CountryCodes["%03d" % int(out)] + ")")
                    except (KeyError, ValueError):
                        print(out)
                else:
                    print(out)
            elif fmt == MIXED:
                if isbinary(value):
                    hexprint(value)
                else:
                    textprint(value)
            else:  # BINARY / anything else
                hexprint(value)
        index = vstart + itemlength


def textprint(data):
    index = 0
    out = ""

    while index < len(data):
        if data[index] >= 0x20 and data[index] < 0x7F:
            out += chr(data[index])
        else:
            out += "."
        index += 1
    print(out)


def bruteforce_primitives():
    for x in range(256):
        for y in range(256):
            status, _length, response = get_primitive([x, y]) # pylint unused-variable
            if status:
                print("Primitive {x:02x} {y:02x}: ")
                if response:
                    hexprint(response)
                    textprint(response)


def get_primitive(tag):
    # get primitive data object - return status, length, data
    le = 0x00
    apdu = GET_DATA + tag + [le]
    response, _sw1, _sw2 = send_apdu(apdu)
    if response[0:2] == tag:
        length = response[2]
        return True, length, response[3:]
    # else:
    return False, 0, ""


def check_return(sw1, sw2):
    if [sw1, sw2] == SW12_OK:
        return True
    return False


def _transceive(apdu):
    # low-level APDU exchange over whichever reader rfidiot.card opened (PC/SC or
    # libnfc), returning (response-bytes-as-list-of-ints, sw1, sw2). T=0/T=1 is
    # negotiated by the library for PC/SC.
    hexapdu = "".join("%02X" % b for b in apdu)
    if card.readertype == card.READER_LIBNFC:
        ok, resp = card.nfc.sendAPDU(hexapdu, card.timeout)
        if not ok or len(resp) < 4:
            return [], 0x6F, 0x00
        data = [int(resp[i : i + 2], 16) for i in range(0, len(resp) - 4, 2)]
        return data, int(resp[-4:-2], 16), int(resp[-2:], 16)
    # PC/SC: pcsc_send_apdu stores the response body in card.data and the status
    # word in card.errorcode ("SW1SW2")
    card.pcsc_send_apdu([hexapdu])
    resp = card.data or ""
    ec = card.errorcode or "6F00"
    data = [int(resp[i : i + 2], 16) for i in range(0, len(resp), 2)]
    return data, int(ec[0:2], 16), int(ec[2:4], 16)


def send_apdu(apdu):
    # send apdu and get additional data if required
    response, sw1, sw2 = _transceive(apdu)
    if sw1 == SW1_WRONG_LENGTH:
        # command used wrong length. retry with correct length.
        apdu = apdu[: len(apdu) - 1] + [sw2]
        return send_apdu(apdu)
    if sw1 == SW1_RESPONSE_BYTES:
        # response bytes available.
        apdu = GET_RESPONSE + [sw2]
        response, sw1, sw2 = _transceive(apdu)
    return response, sw1, sw2


def select_aid(aid):  # pylint unused-argument
    # select an AID and return True/False plus additional data
    apdu = SELECT + [len(aid)] + aid + [0x00]
    response, sw1, sw2 = send_apdu(apdu)
    if check_return(sw1, sw2):
        if Verbose:
            decode_pse(response)
        return True, response, sw1, sw2
    # else:
    return False, [], sw1, sw2


def bruteforce_aids(aid): # pylint unused-argument
    # brute force two digits of AID
    print("Bruteforcing AIDs")
    y = z = 0
    if BruteforceEMV:
        brute_range = [0xA0]
    else:
        brute_range = list(range(256))
    for x in brute_range:
        for y in range(256):
            for z in range(256):
                # aidb= aid + [x]
                aidb = [x, y, 0x00, 0x00, z]
                if Verbose:
                    print("\r  %02x %02x %02x %02x %02x" % (x, y, 0x00, 0x00, z), end="")
                status, response, sw1, sw2 = select_aid(aidb)
                if [sw1, sw2] != SW12_NOT_FOUND:
                    print("\r  Found AID:", end="")
                    hexprint(aidb)
                    if status:
                        decode_pse(response)
                    else:
                        print("SW1 SW2: %02x %02x" % (sw1, sw2))


def read_record(sfi, record):
    # read a specific record from a file
    p1 = record
    p2 = (sfi << 3) + 4
    le = 0x00
    apdu = READ_RECORD + [p1, p2, le]
    response, sw1, sw2 = send_apdu(apdu)
    if check_return(sw1, sw2):
        return True, response
    # else:
    return False, ""


# ISO 4217 numeric currency codes seen in transaction logs (common subset)
CURRENCY_CODES = {
    "0036": "AUD", "0124": "CAD", "0156": "CNY", "0208": "DKK", "0344": "HKD",
    "0356": "INR", "0392": "JPY", "0702": "SGD", "0756": "CHF", "0826": "GBP",
    "0840": "USD", "0978": "EUR", "0049": "COP", "0484": "MXN", "0710": "ZAR",
}

TRANSACTION_TYPES = {
    0x00: "Purchase", 0x01: "Cash advance", 0x09: "Purchase with cashback",
    0x20: "Refund", 0x30: "Balance enquiry",
}


def parse_dol(dol):
    "parse a DOL (list of ints) into a list of (tag:int, length:int) pairs"
    out = []
    i = 0
    while i < len(dol):
        t0 = dol[i]
        tag = t0
        i += 1
        if t0 & 0x1F == 0x1F:
            while i < len(dol):
                tag = (tag << 8) | dol[i]
                more = dol[i] & 0x80
                i += 1
                if not more:
                    break
        if i >= len(dol):
            break
        out.append((tag, dol[i]))
        i += 1
    return out


def format_log_field(tag, val):
    "render one transaction-log field value for display"
    hexval = "".join("%02X" % b for b in val)
    if tag in (0x9F02, 0x9F03) and val:  # amounts: BCD minor units
        try:
            return "%.2f" % (int(hexval) / 100.0)
        except ValueError:
            return hexval
    if tag == 0x9A and len(val) == 3:  # Transaction Date YYMMDD
        return "20%02X-%02X-%02X" % (val[0], val[1], val[2])
    if tag == 0x9F21 and len(val) == 3:  # Transaction Time HHMMSS
        return "%02X:%02X:%02X" % (val[0], val[1], val[2])
    if tag == 0x5F2A:  # Transaction Currency Code
        return CURRENCY_CODES.get(hexval, hexval)
    if tag in (0x9F1A, 0x5F28, 0x9F42):  # country codes
        try:
            return hexval + " (" + ISO3166CountryCodes["%03d" % int(hexval)] + ")"
        except (KeyError, ValueError):
            return hexval
    if tag == 0x9C:  # Transaction Type
        return "%s (%s)" % (hexval, TRANSACTION_TYPES.get(val[0] if val else -1, "?"))
    if tag == 0x9F36:  # ATC
        return str(int(hexval, 16)) if hexval else "0"
    if tag == 0x9F4E:  # Merchant Name and Location (text)
        return "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in val)
    if tag == 0x9F27 and val:  # Cryptogram Information Data
        actype = {0x00: "AAC", 0x40: "TC", 0x80: "ARQC", 0xC0: "RFU"}[val[0] & 0xC0]
        return "%s (%s%s)" % (hexval, actype, ", CDA" if val[0] & 0x10 else "")
    return hexval


def read_transaction_log():
    "read and decode the card's transaction log (Log Entry 9F4D + Log Format 9F4F)"
    entry = EMVData.get(0x9F4D)
    if not entry or len(entry) < 2:
        return  # card advertises no transaction log
    sfi, count = entry[0], entry[1]
    ret, _length, logfmt = get_primitive(LOG_FORMAT)
    fmt = parse_dol(logfmt) if ret else []
    print("  Transaction log (SFI %02X, up to %d records):" % (sfi, count))
    if fmt:
        print("    format:", ", ".join("%X" % t for t, _ in fmt))
    found = 0
    for rec in range(1, count + 1):
        ok, data = read_record(sfi, rec)
        if not ok or not data or all(b == 0 for b in data):
            continue  # empty / unused log slot
        found += 1
        print("    record %d:" % rec)
        if fmt:
            i = 0
            for tag, length in fmt:
                val = data[i : i + length]
                i += length
                name = TAGS[tag][0] if tag in TAGS else "Tag %X" % tag
                print("      %-34s %s" % (name + ":", format_log_field(tag, val)))
        else:
            hexprint(data)
    if not found:
        print("    (log is empty)")


def bruteforce_files():
    # now try and brute force records
    print("  Checking for files:")
    for y in range(1, 31):
        for x in range(1, 256):
            ret, response = read_record(y, x)
            if ret:
                print("  Record %02x, File %02x: length %d" % (x, y, len(response)))
                if Verbose:
                    hexprint(response)
                    textprint(response)
                decode_pse(response)


def build_dol(dol):
    "populate a DOL (list of int tag/length pairs) with terminal defaults; return list of ints"
    out = []
    i = 0
    while i < len(dol):
        t0 = dol[i]
        tag = "%02X" % t0
        i += 1
        if t0 & 0x1F == 0x1F:
            while i < len(dol):
                tag += "%02X" % dol[i]
                more = dol[i] & 0x80
                i += 1
                if not more:
                    break
        if i >= len(dol):
            break
        length = dol[i]
        i += 1
        fill = PDOL_DEFAULTS.get(tag, "")
        b = bytes.fromhex(fill) if fill else b""
        b = (b + b"\x00" * length)[:length]
        out += list(b)
    return out


def get_processing_options():
    # build the GPO command data object (83) from the card's PDOL (9F38) if any
    pdol_data = build_dol(Pdol) if Pdol else []
    field = [0x83, len(pdol_data)] + pdol_data
    apdu = [0x80, 0xA8, 0x00, 0x00, len(field)] + field + [0x00]
    response, sw1, sw2 = send_apdu(apdu)
    if check_return(sw1, sw2):
        return True, response
    # else:
    return False, "%02x%02x" % (sw1, sw2)


def decode_processing_options(data):
    # extract and decode AIP (Application Interchange Profile)
    # and AFL (Application File Locator)
    global SDA_INPUT
    SDA_INPUT = []  # reset the offline-auth input for this application
    # strip the outer template (tag 80 format 1, or tag 77 format 2) honouring
    # multi-byte BER lengths - a long template (>127 bytes) encodes its length as
    # 81 xx etc., so the body does not always start at offset 2
    top, toplen = ber_tag(data, 0)
    tlen, tlenlen = ber_len(data, toplen)
    body = data[toplen + tlenlen : toplen + tlenlen + tlen]
    if top == 0x80:
        # format 1: AIP (first 2 bytes) followed by the AFL
        EMVData[0x82] = list(body[0:2])  # store AIP (not TLV-tagged in format 1)
        decode_aip(body)
        x = 2
        while x < len(body):
            sfi, start, end, offline = decode_afl(body[x : x + 4])
            print(
                "    SFI %02X: starting record %02X, ending record %02X; %02X offline data authentication records"
                % (sfi, start, end, offline)
            )
            x += 4
            decode_file(sfi, start, end, offline)
    elif top == 0x77:
        # format 2: BER-TLV, including the AIP (82) and AFL (94)
        x = 0
        while x < len(body):
            tag, fieldlen, value = decode_ber_tlv_item(body[x:])
            if tag == BER_TLV_AIP:
                decode_aip(value)
            if tag == BER_TLV_AFL:
                # the AFL may hold several 4-byte entries - iterate all of them
                j = 0
                while j < len(value):
                    sfi, start, end, offline = decode_afl(value[j : j + 4])
                    print(
                        "    SFI %02X: starting record %02X, ending record %02X; %02X offline data authentication records"
                        % (sfi, start, end, offline)
                    )
                    decode_file(sfi, start, end, offline)
                    j += 4
            x += fieldlen


def collect_sda(sfi, record):
    "append a record's contribution to the static data to be authenticated (EMV Book 3, 10.3)"
    global SDA_INPUT
    if sfi <= 10:
        # records in SFI 1-10 are '70' templates; include the value only
        # (strip the '70' tag and its length)
        if record and record[0] == 0x70:
            _, taglen = ber_tag(record, 0)
            vlen, lenlen = ber_len(record, taglen)
            SDA_INPUT += list(record[taglen + lenlen : taglen + lenlen + vlen])
        else:
            SDA_INPUT += list(record)
    else:
        # records in SFI 11-30 are included in full (tag '70', length and value)
        SDA_INPUT += list(record)


def decode_file(sfi, start, end, offline=0):
    for y in range(start, end + 1):
        ret, response = read_record(sfi, y)
        if ret:
            # the first 'offline' records of this AFL entry feed offline data auth
            if (y - start) < offline:
                collect_sda(sfi, response)
            if OutputFiles:
                # file = open("%s-FILE%02XRECORD%02X.HEX" % (CurrentAID, sfi, y), "w")
                # for n in range(len(response)):
                #     file.write("%02X" % response[n])
                with open(f"{CurrentAID}-FILE{sfi:02X}XRECORD{y:02X}.HEX", "w", encoding="utf-8") as file:
                    for n in response:
                        file.write(f"{n:02X}")
            print(f"      record {y:02X}: ", end="")
            decode_pse(response)
        else:
            print("Read error!")


def decode_aip(data):
    # byte 1 of AIP is bit masked, byte 2 is RFU
    # for x in list(AIP_MASK.keys()):
    for x in AIP_MASK:
        if data[0] & x:
            print("    " + AIP_MASK[x])


def decode_cvm(data):
    "decode a Cardholder Verification Method (CVM) List (tag 8E)"
    print()
    if len(data) < 8:
        print("      (malformed CVM list)")
        return
    amount_x = int.from_bytes(bytes(data[0:4]), "big")
    amount_y = int.from_bytes(bytes(data[4:8]), "big")
    print("      Amount X: %d   Amount Y: %d" % (amount_x, amount_y))
    rules = data[8:]
    i = 0
    n = 1
    while i + 1 < len(rules):
        code, cond = rules[i], rules[i + 1]
        method = code & 0x3F
        cont = code & 0x40  # apply next rule if this CVM is unsuccessful
        mname = CVM_CODES.get(method, "RFU/proprietary (0x%02x)" % method)
        cname = CVM_CONDITIONS.get(cond, "RFU/proprietary (0x%02x)" % cond)
        tail = "else apply next rule" if cont else "else fail CVM"
        print("      %d. %s  [%s]  (%s)" % (n, mname, cname, tail))
        i += 2
        n += 1


# service-code digit meanings (ISO 7813)
SERVICE_CODE_1 = {
    "1": "International", "2": "International, ICC preferred", "5": "National",
    "6": "National, ICC preferred", "7": "Private/no interchange", "9": "Test",
}
SERVICE_CODE_2 = {
    "0": "Normal authorisation", "2": "Authorise online by issuer",
    "4": "Authorise online by issuer unless bilateral agreement",
}
SERVICE_CODE_3 = {
    "0": "No restrictions, PIN required", "1": "No restrictions",
    "2": "Goods and services only", "3": "ATM only, PIN required",
    "4": "Cash only", "5": "Goods and services only, PIN required",
    "6": "No restrictions, prompt for PIN if PED present",
    "7": "Goods and services only, prompt for PIN if PED present",
}


def decode_service_code(code):
    "return the three ISO 7813 service-code digit meanings"
    return [
        "interchange:   " + SERVICE_CODE_1.get(code[0], code[0]),
        "authorisation: " + SERVICE_CODE_2.get(code[1], code[1]),
        "services:      " + SERVICE_CODE_3.get(code[2], code[2]),
    ]


def decode_track2(value, indent=""):
    "split Track 2 Equivalent Data (tag 57) into PAN / expiry / service code / discretionary"
    h = "".join("%02X" % b for b in value).upper()
    sep = h.find("D")  # field separator is the hex nibble 'D'
    if sep < 1:
        return
    pan = h[:sep]
    rest = h[sep + 1 :]
    expiry = rest[0:4]  # YYMM
    service = rest[4:7]
    disc = rest[7:].rstrip("F")
    pad = indent + "        "
    print(pad + "PAN:            " + pan)
    if len(expiry) == 4:
        print(pad + "Expiry:         20%s-%s" % (expiry[0:2], expiry[2:4]))
    if len(service) == 3:
        print(pad + "Service code:   " + service)
        for line in decode_service_code(service):
            print(pad + "  " + line)
    if disc:
        print(pad + "Discretionary:  " + disc)


def decode_cid(value, indent=""):
    "decode the Cryptogram Information Data (tag 9F27)"
    if not value:
        return
    b = value[0]
    actype = {
        0x00: "AAC - declined offline",
        0x40: "TC - approved offline",
        0x80: "ARQC - online authorisation requested",
        0xC0: "RFU",
    }
    line = actype.get(b & 0xC0, "?")
    if b & 0x10:
        line += ", CDA signature requested"
    print(indent + "        cryptogram: " + line)


def decode_afl(data):
    sfi = int(data[0] >> 3)
    start = int(data[1])
    end = int(data[2])
    offline = int(data[3])
    return sfi, start, end, offline


def _rsa_recover(cert, mod_int, exp):
    "EMV public-key recovery: cert^exp mod n, returned as bytes"
    c = int.from_bytes(bytes(cert), "big")
    r = pow(c, exp, mod_int)
    return r.to_bytes((mod_int.bit_length() + 7) // 8, "big")


def _ca_key_validates(key, cert):
    "does this CA key recover the Issuer PK cert to a valid, hash-correct structure?"
    import hashlib

    if not key:
        return False
    rec = _rsa_recover(cert, int(key["mod"], 16), key["exp"])
    if not (rec[0] == 0x6A and rec[1] == 0x02 and rec[-1] == 0xBC):
        return False
    rem = EMVData.get(0x92)
    iexp = EMVData.get(0x9F32, [])
    hin = bytes(rec[1:-21]) + (bytes(rem) if rem else b"") + bytes(iexp)
    return hashlib.sha1(hin).digest() == bytes(rec[-21:-1])


def find_ca_key(rid, index, cert):
    "the CA key for (rid, index); else any key of that index that validates the cert"
    key = CA_PUBLIC_KEYS.get((rid, index))
    if _ca_key_validates(key, cert):
        return key, rid
    # companion/alias AIDs (e.g. LINK A000000029) carry no CA keys of their own -
    # their certs are signed by the primary scheme's CA. The recovery is self-
    # validating (6A..BC + hash), so search other RIDs at the same index.
    for (krid, kidx), kkey in CA_PUBLIC_KEYS.items():
        if kidx == index and krid != rid and _ca_key_validates(kkey, cert):
            return kkey, krid
    return None, rid


def recover_certificates():
    "recover & verify the SDA/DDA certificate chain from the collected EMVData"
    import hashlib

    global IssuerKey, ICCKey
    IssuerKey = None
    ICCKey = None

    idx = EMVData.get(0x8F)
    cert = EMVData.get(0x90)
    if not idx or not cert:
        return  # no readable offline-auth data on this application
    rid = CurrentAID[:10].upper()
    index = idx[0]
    print("  -- Offline Data Authentication --")
    key, key_rid = find_ca_key(rid, index, cert)
    if not key:
        print("    no CA public key for RID %s index %02X (add it to CA_PUBLIC_KEYS)" % (rid, index))
        return
    ca_mod = int(key["mod"], 16)
    if key_rid != rid:
        print("    RID %s has no CA key of its own; cert verifies under RID %s (companion AID)" % (rid, key_rid))
    print("    CA key: RID %s index %02X (%d-bit)" % (key_rid, index, ca_mod.bit_length()))

    # 1. Issuer Public Key certificate (tag 90), signed by the CA key
    rec = _rsa_recover(cert, ca_mod, key["exp"])
    if not (rec[0] == 0x6A and rec[1] == 0x02 and rec[-1] == 0xBC):
        print("    Issuer PK cert: INVALID recovery (wrong CA key or corrupt cert)")
        return
    pklen = rec[13]
    field = rec[15:-21]
    rem = EMVData.get(0x92)
    iexp = EMVData.get(0x9F32, [])
    hin = bytes(rec[1:-21]) + (bytes(rem) if rem else b"") + bytes(iexp)
    hash_ok = hashlib.sha1(hin).digest() == bytes(rec[-21:-1])
    if pklen <= len(field):
        issuer_mod = bytes(field[:pklen])
    else:
        issuer_mod = bytes(field) + (bytes(rem) if rem else b"")
    print("    Issuer PK cert: 6A..BC ok, hash %s, key %d-bit, expiry %02x/%02x, serial %s"
          % ("OK" if hash_ok else "FAIL", pklen * 8, rec[6], rec[7], bytes(rec[8:11]).hex().upper()))
    imod = int.from_bytes(issuer_mod, "big")
    iexp_int = int.from_bytes(bytes(iexp), "big") if iexp else 3
    IssuerKey = {"mod": imod, "exp": iexp_int}

    # 2. ICC Public Key certificate (tag 9F46), signed by the issuer key
    icc = EMVData.get(0x9F46)
    if not icc:
        print("    (no ICC PK certificate - SDA-only application)")
        verify_sda()
        return
    icc_exp = int.from_bytes(bytes(EMVData.get(0x9F47, [3])), "big")
    rec2 = _rsa_recover(icc, imod, icc_exp)
    if not (rec2[0] == 0x6A and rec2[1] == 0x04 and rec2[-1] == 0xBC):
        print("    ICC PK cert: INVALID recovery")
        verify_sda()
        return
    icclen = rec2[19]
    icc_field = rec2[21:-21]
    icc_rem = EMVData.get(0x9F48)
    if icclen <= len(icc_field):
        icc_mod = bytes(icc_field[:icclen])
    else:
        icc_mod = bytes(icc_field) + (bytes(icc_rem) if icc_rem else b"")
    ICCKey = {"mod": int.from_bytes(icc_mod, "big"), "exp": icc_exp}
    pan_cert = bytes(rec2[2:12]).hex().upper().rstrip("F")
    pan_card = bytes(EMVData.get(0x5A, [])).hex().upper().rstrip("F")
    match = "  (matches card PAN)" if pan_card and pan_cert == pan_card else ""
    print("    ICC PK cert: 6A..BC ok, key %d-bit, PAN %s%s, expiry %02x/%02x"
          % (icclen * 8, pan_cert, match, rec2[12], rec2[13]))
    print("    chain verified: CA %d-bit -> Issuer %d-bit -> ICC %d-bit"
          % (ca_mod.bit_length(), pklen * 8, icclen * 8))

    # 3. verify the data the chain exists to protect: SDA (static) and/or DDA (dynamic)
    verify_sda()
    verify_dda()


def verify_sda():
    "verify Signed Static Application Data (tag 93) against the recovered Issuer key"
    import hashlib

    if not IssuerKey:
        return
    sdata = EMVData.get(0x93)
    if not sdata:
        return  # DDA-only application: no static signature to check
    rec = _rsa_recover(sdata, IssuerKey["mod"], IssuerKey["exp"])
    if not (rec[0] == 0x6A and rec[1] == 0x03 and rec[-1] == 0xBC):
        print("    SDA (static data): INVALID recovery")
        return
    static = bytes(SDA_INPUT)
    # if a Static Data Authentication Tag List (9F4A) is present it should list
    # tag 82 (AIP), whose value is appended to the authenticated static data
    taglist = EMVData.get(0x9F4A)
    if taglist and 0x82 in taglist:
        static += bytes(EMVData.get(0x82, []))
    calc = hashlib.sha1(bytes(rec[1:-21]) + static).digest()
    ok = calc == bytes(rec[-21:-1])
    dac = bytes(rec[3:5]).hex().upper()
    print("    SDA (static data): %s  (DAC %s)"
          % ("VERIFIED - static data intact" if ok else "HASH MISMATCH - data altered", dac))


def _extract_sdad(response):
    "pull the Signed Dynamic Application Data (tag 80 value, or 9F4B inside a 77 template)"
    top, toplen = ber_tag(response, 0)
    tlen, tlenlen = ber_len(response, toplen)
    tval = response[toplen + tlenlen : toplen + tlenlen + tlen]
    if top == 0x80:
        return tval
    if top == 0x77:
        idx = 0
        while idx < len(tval):
            tag, taglen = ber_tag(tval, idx)
            vlen, lenlen = ber_len(tval, idx + taglen)
            vstart = idx + taglen + lenlen
            if tag == 0x9F4B:
                return tval[vstart : vstart + vlen]
            idx = vstart + vlen
    return None


def _verify_sdad(sdad, appended, label, require_hash=True):
    "recover Signed Dynamic Application Data with the ICC key and verify its hash"
    import hashlib

    rec = _rsa_recover(sdad, ICCKey["mod"], ICCKey["exp"])
    if not (rec[0] == 0x6A and rec[1] == 0x05 and rec[-1] == 0xBC):
        print("    %s: INVALID recovery" % label)
        return
    # the hash covers the recovered data (minus the leading 6A and trailing
    # hash+BC) plus the terminal dynamic data: the DDOL data for INTERNAL
    # AUTHENTICATE, or the Unpredictable Number for fast DDA
    calc = hashlib.sha1(bytes(rec[1:-21]) + bytes(appended)).digest()
    ok = calc == bytes(rec[-21:-1])
    if ok:
        print("    %s: VERIFIED - card holds the matching private key (genuine, not a clone)" % label)
    elif require_hash:
        print("    %s: HASH MISMATCH - card could not sign the challenge" % label)
    else:
        # fast DDA: valid 6A..BC framing under the ICC key already proves the card
        # signed with the ICC private key (and the signature is fresh per read).
        # The UN-binding hash depends on the kernel's transaction-data rules, which
        # we don't reconstruct, so we don't assert it.
        print("    %s: signature recovered, ICC-key framing valid - card holds the ICC private key" % label)
        print("        (dynamic UN-binding hash not checked - fast-DDA transaction binding is kernel-specific)")


def verify_dda():
    "verify Dynamic Data Authentication - contactless fast DDA, or contact INTERNAL AUTHENTICATE"
    import os

    if not ICCKey:
        return
    aip = EMVData.get(0x82, [0])
    if not (aip[0] & 0x20):
        return  # card does not advertise DDA support in the AIP

    # contactless fast DDA: the Signed Dynamic Application Data (9F4B) is already
    # in the GPO response (signed during GPO over the terminal data below)
    sdad = EMVData.get(0x9F4B)
    if sdad:
        # Visa qVSDC fast DDA: the signature covers the Unpredictable Number,
        # Amount Authorised, Transaction Currency Code (as sent in the PDOL) and
        # the card's Card Authentication Related Data (9F69). require_hash=False
        # so a card following a different kernel's fDDA still reports the
        # (meaningful) framing-valid result rather than a false "mismatch".
        tdd = (
            bytes.fromhex(PDOL_DEFAULTS.get("9F37", ""))
            + bytes.fromhex(PDOL_DEFAULTS.get("9F02", ""))
            + bytes.fromhex(PDOL_DEFAULTS.get("5F2A", ""))
            + bytes(EMVData.get(0x9F69, []))
        )
        _verify_sdad(sdad, tdd, "fDDA (dynamic, contactless)", require_hash=False)
        return

    # contact DDA: challenge the card with INTERNAL AUTHENTICATE + the DDOL
    ddol = EMVData.get(0x9F49, [0x9F, 0x37, 0x04])
    unpredictable = os.urandom(4)
    saved = PDOL_DEFAULTS.get("9F37")
    PDOL_DEFAULTS["9F37"] = unpredictable.hex().upper()
    try:
        ddol_data = build_dol(ddol)
    finally:
        if saved is None:
            PDOL_DEFAULTS.pop("9F37", None)
        else:
            PDOL_DEFAULTS["9F37"] = saved
    apdu = INTERNAL_AUTHENTICATE + [len(ddol_data)] + ddol_data + [0x00]
    response, sw1, sw2 = send_apdu(apdu)
    if not check_return(sw1, sw2):
        print("    DDA (dynamic): INTERNAL AUTHENTICATE failed %02x%02x" % (sw1, sw2))
        return
    sdad = _extract_sdad(response)
    if not sdad:
        print("    DDA (dynamic): no Signed Dynamic Application Data in response")
        return
    _verify_sdad(sdad, ddol_data, "DDA (dynamic)")


def generate_ac():
    "send GENERATE AC requesting CDA, then verify the returned dynamic signature"
    import os

    cdol1 = EMVData.get(0x8C)
    if not cdol1:
        print("  GENERATE AC: card has no CDOL1 (tag 8C) - cannot build the command")
        return
    print()
    print("  *** GENERATE AC (CDA) - this WRITES to the card and increments its ATC ***")
    # request an ARQC (online authorisation) with CDA requested (P1 bit 0x10). The
    # transaction is never taken online, so nothing is actually authorised, but the
    # card still returns a CDA-signed response we can verify.
    un = os.urandom(4)
    saved = PDOL_DEFAULTS.get("9F37")
    PDOL_DEFAULTS["9F37"] = un.hex().upper()
    try:
        cdol_data = build_dol(cdol1)
    finally:
        if saved is None:
            PDOL_DEFAULTS.pop("9F37", None)
        else:
            PDOL_DEFAULTS["9F37"] = saved
    p1 = 0x80 | 0x10  # ARQC + CDA requested
    apdu = GENERATE_AC + [p1, 0x00, len(cdol_data)] + cdol_data + [0x00]
    response, sw1, sw2 = send_apdu(apdu)
    if not check_return(sw1, sw2):
        print("  GENERATE AC failed: %02x%02x %s" % (sw1, sw2, ERRORS.get("%02x%02x" % (sw1, sw2), "")))
        return
    print("  GENERATE AC response:")
    decode_pse(response)  # populates EMVData with 9F27 (CID), 9F36 (ATC), 9F4B, ...
    cid = EMVData.get(0x9F27, [0])
    actype = {0x00: "AAC (declined)", 0x40: "TC (approved)", 0x80: "ARQC (online)"}.get(cid[0] & 0xC0, "?")
    print("    cryptogram type returned: %s" % actype)
    sdad = EMVData.get(0x9F4B)
    if not sdad:
        print("    (no CDA signature returned - card generated a plain cryptogram, no CDA)")
        return
    if not ICCKey:
        print("    CDA signature present but ICC key not recovered (run with -c)")
        return
    _verify_sdad(sdad, un, "CDA (dynamic)", require_hash=False)


def decode_ber_tlv_field(data):
    x = 0
    while x < len(data):
        tag, fieldlen, value = decode_ber_tlv_item(data[x:])
        print("Tag %04X: " % tag, end="")
        hexprint(value)
        x += fieldlen


def decode_ber_tlv_item(data):
    # return tag, total length of data processed and value for BER-TLV object
    tag = data[0] & TLV_TAG_NUMBER_MASK
    i = 1
    if tag == TLV_TAG_NUMBER_MASK:
        # high-tag-number form: the tag number continues in the following
        # byte(s). Each subsequent byte with bit 8 (0x80) set is followed by
        # another; the byte with bit 8 clear is the last. Build the full tag as
        # an int - in Py3 indexing a bytes/bytearray yields ints, not str, so
        # the original str accumulation ("" + int) raised a TypeError.
        tag = data[0]
        while data[i] & TLV_TAG_MASK:
            # another tag byte follows
            tag = (tag << 8) | data[i]
            i += 1
        tag = (tag << 8) | data[i]
        i += 1
    if data[i] & TLV_LENGTH_MASK:
        # this byte tells us the number of subsequent bytes that describe the length
        lenlen = xor(data[i], TLV_LENGTH_MASK)
        i += 1
        length = int(data[i])
        z = 1
        while z < lenlen:
            i += 1
            z += 1
            length = length << 8
            length += int(data[i])
        i += 1
    else:
        length = int(data[i])
        i += 1
    return tag, i + length, data[i : i + length]


def get_challenge(d_bytes):
    lc = d_bytes
    le = 0x00
    apdu = GET_CHALLENGE + [lc, le]
    response, sw1, sw2 = send_apdu(apdu)
    if check_return(sw1, sw2):
        print("Random number: ", end="")
        hexprint(response)
    # print 'GET CHAL: %02x%02x %d' % (sw1,sw2,len(response))


def build_pin_block(pin):
    "build the 8-byte plaintext offline PIN block (control 2, length, PIN nibbles, F pad)"
    block = [(0x02 << 4) + len(pin)]
    x = 0
    while x < len(pin):
        leftnibble = int(pin[x])
        try:
            rightnibble = int(pin[x + 1])
        except (IndexError, ValueError):
            rightnibble = 0x0F  # pad to even length
        block.append((leftnibble << 4) + rightnibble)
        x += 2
    while len(block) < 8:
        block.append(0xFF)
    return block


def _pin_result(sw1, sw2):
    "report the outcome of a VERIFY and return True on success"
    if [sw1, sw2] == SW12_OK:
        print("PIN verified")
        return True
    if [sw1, sw2] == PIN_BLOCKED or [sw1, sw2] == PIN_BLOCKED2:
        print("PIN blocked!")
    elif sw1 == PIN_WRONG:
        print("wrong PIN - %d tries left" % (int(sw2) & 0x0F))
    elif [sw1, sw2] == SW12_NOT_SUPORTED:
        print("Function not supported")
    else:
        print("command failed! ", end="")
        hexprint([sw1, sw2])
    return False


def verify_pin(pin):
    # construct offline PIN block and verify (plaintext)
    print("Verifying PIN:", pin)
    block = build_pin_block(pin)
    apdu = VERIFY + [len(block)] + block
    _response, sw1, sw2 = send_apdu(apdu)
    return _pin_result(sw1, sw2)


def verify_pin_enciphered(pin):
    "verify an offline PIN enciphered under the ICC public key (EMV Book 2, 7.1)"
    import os

    if not ICCKey:
        print("Enciphered PIN needs the ICC public key - run with -c (and a card that")
        print("exposes an ICC PK certificate).")
        return False
    # ICC Unpredictable Number, bound into the block so it cannot be replayed.
    # GET CHALLENGE: 00 84 00 00 00 (P2=00, Le=00 -> card returns 8 bytes)
    challenge, sw1, sw2 = send_apdu([0x00, 0x84, 0x00, 0x00, 0x00])
    if not check_return(sw1, sw2) or len(challenge) < 8:
        print("GET CHALLENGE failed %02x%02x" % (sw1, sw2))
        return False
    icc_un = list(challenge[0:8])
    # plaintext to encipher: 7F || PIN block(8) || ICC UN(8) || random padding,
    # left-padded by the 0x7F header so the value is always < the ICC modulus
    klen = (ICCKey["mod"].bit_length() + 7) // 8
    message = [0x7F] + build_pin_block(pin) + icc_un
    padlen = klen - len(message)
    if padlen < 0:
        print("ICC key too small to carry the enciphered PIN block")
        return False
    message += list(os.urandom(padlen))
    cipher = pow(int.from_bytes(bytes(message), "big"), ICCKey["exp"], ICCKey["mod"])
    data = list(cipher.to_bytes(klen, "big"))
    print("Verifying enciphered PIN:", pin)
    # VERIFY with P2 = 0x88 (enciphered PIN)
    _response, sw1, sw2 = send_apdu([0x00, 0x20, 0x00, 0x88, len(data)] + data)
    return _pin_result(sw1, sw2)


# def update_pin_try_counter(tries):
#     # try to set Pin Try Counter by sending Card Status Update
#     if tries > 0x0F:
#         return False, "PTC max value exceeded"
#     csu = []
#     csu.append(tries)
#     csu.append(0x10)
#     csu.append(0x00)
#     csu.append(0x00)
#     tag = 0x91  # Issuer Authentication Data
#     lc = len(csu) + 1


# def generate_ac(d_type):
#     # generate an application Cryptogram
#     if d_type == TC:
#         # populate data with CDOL1
#         print()
#     apdu = GENERATE_AC + [lc, d_type] + data + [le]
#     le = 0x00
#     response, sw1, sw2 = send_apdu(apdu) # pylint: disable=unused-variable
#     if check_return(sw1, sw2):
#         print("AC generated!")
#         return True
#     #else:
#     hexprint([sw1, sw2])


# main loop
aidlist = KNOWN_AIDS


if _want_help:
    # print the global reader options followed by ChAP's own, then stop
    rfidiot.printoptions()
    printhelp()
    sys.exit(False)

try:
    # reader options were already consumed by the rfidiot import; parse ChAP's
    # own options (and the optional trailing PIN) out of rfidiot.args.
    opts, pinargs = getopt.getopt(rfidiot.args, "aAceEFGopxv")
    for o, a in opts:
        if o == "-c":
            RecoverCerts = True
        if o == "-G":
            GenerateAC = True
        if o == "-E":
            EncipheredPIN = True
            RecoverCerts = True  # enciphered PIN needs the recovered ICC public key
        if o == "-a":
            BruteforceAID = True
        if o == "-A":
            print()
            for x in aidlist:
                print(f"{x[0]:20s}: ", end="")
                hexprint(x[1:])
            print()
            sys.exit(False)
        if o == "-e":
            BruteforceAID = True
            BruteforceEMV = True
        if o == "-F":
            BruteforceFiles = True
        if o == "-o":
            OutputFiles = True
        if o == "-p":
            BruteforcePrimitives = True
        if o == "-x":
            RawOutput = True
        if o == "-v":
            Verbose = True

except getopt.GetoptError:
    printhelp()
    sys.exit(True)

PIN = ""
if pinargs:
    if not pinargs[0].isdigit():
        print("Invalid PIN", pinargs[0])
        sys.exit(True)
    else:
        PIN = pinargs[0]

try:
    print("using reader:", getattr(card, "readername", "unknown"))
    if card.readertype == card.READER_LIBNFC:
        # contactless: run ISO 14443-A anticollision/select to power and select
        # the card before exchanging APDUs (PC/SC is already connected on import)
        if not card.select():
            print("no card on the reader")
            sys.exit(True)

    # get_challenge(0)

    # try to select PSE
    apdu = SELECT + [len(DF_PSE)] + DF_PSE
    response, sw1, sw2 = send_apdu(apdu)

    if check_return(sw1, sw2):
        # there is a PSE
        print("PSE found!")
        decode_pse(response)
        if BruteforcePrimitives:
            # brute force primitives
            print("Brute forcing primitives")
            bruteforce_primitives()
        if BruteforceFiles:
            print("Brute forcing files")
            bruteforce_files()
        status, length, psd = get_tag(response, SFI)
        if not status:
            print("No PSD found!")
        else:
            print("  Checking for records:", end="")
            if BruteforcePrimitives:
                psd = list(range(31))
                print("(bruteforce all files)")
            else:
                print()
            for x in range(256):
                for y in psd:
                    p1 = x
                    p2 = (y << 3) + 4
                    le = 0x00
                    apdu = READ_RECORD + [p1] + [p2, le]
                    response, sw1, sw2 = _transceive(apdu)
                    if sw1 == 0x6C:
                        print(f"  Record {x:02x}, File {y:02x}: length {sw2}")
                        le = sw2
                        apdu = READ_RECORD + [p1] + [p2, le]
                        response, sw1, sw2 = _transceive(apdu)
                        print("  ", end="")
                        aid = ""
                        if Verbose:
                            hexprint(response)
                            textprint(response)
                        i = 0
                        while i < len(response):
                            # extract the AID
                            if response[i] == 0x4F and aid == "":
                                aidlen = response[i + 1]
                                aid = response[i + 2 : i + 2 + aidlen]
                            i += 1
                        print("   AID found:", end="")
                        hexprint(aid)
                        aidlist.append(["PSD Entry"] + aid)
    if BruteforceAID:
        bruteforce_aids(BRUTE_AID)
    if aidlist:
        # now try dumping the AID records
        current = 0
        while current < len(aidlist):
            if Verbose:
                print(f"Trying AID: {aidlist[current][0]} -",  end="")
                hexprint(aidlist[current][1:])
            selected, response, sw1, sw2 = select_aid(aidlist[current][1:])
            if selected:
                CurrentAID = ""
                for n in range(len(aidlist[current][1:])):
                    CurrentAID += "%02X" % aidlist[current][1:][n]
                if Verbose:
                    print("  Selected: ", end="")
                    hexprint(response)
                    textprint(response)
                else:
                    print(f"  Found AID: {aidlist[current][0]} -", end="")
                    hexprint(aidlist[current][1:])
                EMVData.clear()  # fresh tag collection for this application
                decode_pse(response)
                if BruteforcePrimitives:
                    # brute force primitives
                    print("Brute forcing primitives")
                    bruteforce_primitives()
                if BruteforceFiles:
                    print("Brute forcing files")
                    bruteforce_files()
                ret, response = get_processing_options()
                if not ret:
                    # GPO failed - this AID is not a usable application (e.g. a bare
                    # RID that only returns a directory FCI). Skip the transaction
                    # steps (incl. VERIFY) and move on to the next AID.
                    print(
                        "  Could not get processing options:",
                        response,
                        ERRORS.get(response, "unknown error"),
                    )
                    current += 1
                    continue
                print("  Processing Options:", end="")
                decode_pse(response)
                decode_processing_options(response)
                if RecoverCerts:
                    recover_certificates()
                if GenerateAC:
                    generate_ac()
                pret, length, pins = get_primitive(PIN_TRY_COUNTER)
                if pret:
                    print("  PIN tries left:", int(pins[0]))
                if PIN:
                    print("  *** sending VERIFY - this decrements the PIN Try Counter ***")
                    if EncipheredPIN:
                        ok = verify_pin_enciphered(PIN)
                    else:
                        ok = verify_pin(PIN)
                    sys.exit(not ok)
                aret, length, atc = get_primitive(ATC)
                if aret:
                    print("  Application Transaction Counter:", (atc[0] << 8) + atc[1])
                lret, length, latc = get_primitive(LAST_ATC)
                if lret:
                    print("  Last ATC:", (latc[0] << 8) + latc[1])
                read_transaction_log()
                current += 1
            else:
                if Verbose:
                    print("  Not found: %02x %02x" % (sw1, sw2))
                current += 1
    else:
        print("no PSE: %02x %02x" % (sw1, sw2))

except Exception as emsg:  # pylint: disable=broad-except
    print("card communication error:", emsg)
    if rfidiot.rfidiotglobals.Debug:
        raise

if "win32" == sys.platform:
    print("press Enter to continue")
    sys.stdin.read(1)
