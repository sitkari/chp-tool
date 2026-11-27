#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""chp.py — unpacker/packer for device firmware containers (.chp).

Understands containers from a whole family of devices. The image
header in the 0x800 area (version/subversion/checksum) is not present in
every file, so it is detected automatically; the remaining files are
parsed as a plain image without a header.


The .chp container (verified against official files):
    byte 0            = 8 - pad, where pad = 8 - (len(XML) % 8)  (pad = 1..8)
    bytes 1..         = XML encrypted in 8-byte blocks,
                        a tail shorter than 8 bytes is copied as is

XML (cp1251) with Russian tag names, translated here as
File / Program / Area:
    <File name="..." size="<len payload>" crc="<crc8 payload>">
        ...
        <Program version="2.75" description="Subversion 34" ...>
            <Area address="2048" size="131072" offset="2048">...</Area>
        </Program> ...
        <HEX>
        :100800002A38010013012200431AFF006EEF2AF010
        ...
        </HEX>
    </File>

Image (what is stored in HEX) — an address space from 0x00000 to 0x1FFFF,
data starts at 0x800. Image header:

    0x800  word  w0          -> end of the checksum area W = 0x10000 + w0
    0x802  word  0x0001
    0x804  word  version (275)
    0x806  word  subversion (34)
    0x808  word  crc — compensator: (0xF0F1 - sum16LE[0x800,W)) & 0xFFFF
    0x80A  byte 0xFF, word 0x00FF
    0x80C  GOTO 0x54DC       ; application entry point
    0x810  GOTO 0x6190       ; interrupt handler

Invariants: sum16LE[0x800,W) == 0xF0F1, sum16LE[0x800,W+2) == 0x0000.

Examples:
    python chp.py info    "firmware.chp"
    python chp.py unpack  "firmware.chp" -o work
    python chp.py pack    "firmware.chp" -b work/base.bin -o new.chp --sub 38
    python chp.py set     "firmware.chp" -o new.chp --word 0x5924=9E83 --sub 37
    python chp.py diff    a.chp b.chp
    python chp.py verify  new.chp
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys

# --------------------------------------------------------------------------- #
#  container cipher
# --------------------------------------------------------------------------- #

KEYHEX = ('1939052419401004196812221971121819911993199619'
          '991234567887654321')

SBOX_HEX = (
        'efe1e8eee6ebe3e4e9e7e2edece0e5ea4f41484e464b43444947424d4c40454adfd1'
    'd8ded6dbd3d4d9d7d2dddcd0d5da1f11181e161b13141917121d1c10151a2f21282e'
    '262b23242927222d2c20252afff1f8fef6fbf3f4f9f7f2fdfcf0f5fabfb1b8beb6bb'
    'b3b4b9b7b2bdbcb0b5ba8f81888e868b83848987828d8c80858a3f31383e363b3334'
    '3937323d3c30353aafa1a8aea6aba3a4a9a7a2adaca0a5aa6f61686e666b63646967'
    '626d6c60656acfc1c8cec6cbc3c4c9c7c2cdccc0c5ca5f51585e565b53545957525d'
    '5c50555a9f91989e969b93949997929d9c90959a0f01080e060b03040907020d0c00'
    '050a7f71787e767b73747977727d7c70757aa7adaea3a0a6a9aaa1a2a8a5abaca4af'
    '070d0e030006090a010208050b0c040f979d9e939096999a919298959b9c949fe7ed'
    'eee3e0e6e9eae1e2e8e5ebece4ef676d6e636066696a616268656b6c646f373d3e33'
    '3036393a313238353b3c343ff7fdfef3f0f6f9faf1f2f8f5fbfcf4ff575d5e535056'
    '595a515258555b5c545f171d1e131016191a111218151b1c141fd7ddded3d0d6d9da'
    'd1d2d8d5dbdcd4dfc7cdcec3c0c6c9cac1c2c8c5cbccc4cf777d7e737076797a7172'
    '78757b7c747fb7bdbeb3b0b6b9bab1b2b8b5bbbcb4bf474d4e434046494a41424845'
    '4b4c444f272d2e232026292a212228252b2c242f878d8e838086898a818288858b8c'
    '848f2c212a2f29222628202d23242e27252bccc1cacfc9c2c6c8c0cdc3c4cec7c5cb'
    '4c414a4f49424648404d43444e47454b1c111a1f19121618101d13141e17151b7c71'
    '7a7f79727678707d73747e77757baca1aaafa9a2a6a8a0ada3a4aea7a5abbcb1babf'
    'b9b2b6b8b0bdb3b4beb7b5bb6c616a6f69626668606d63646e67656b8c818a8f8982'
    '8688808d83848e87858b5c515a5f59525658505d53545e57555b3c313a3f39323638'
    '303d33343e37353bfcf1fafff9f2f6f8f0fdf3f4fef7f5fbdcd1dadfd9d2d6d8d0dd'
    'd3d4ded7d5db0c010a0f09020608000d03040e07050bece1eaefe9e2e6e8e0ede3e4'
    'eee7e5eb9c919a9f99929698909d93949e97959b4d424844464f4b414a49434e4540'
    '4c47bdb2b8b4b6bfbbb1bab9b3beb5b0bcb72d222824262f2b212a29232e25202c27'
    'ede2e8e4e6efebe1eae9e3eee5e0ece7fdf2f8f4f6fffbf1faf9f3fef5f0fcf70d02'
    '0804060f0b010a09030e05000c078d828884868f8b818a89838e85808c87ddd2d8d4'
    'd6dfdbd1dad9d3ded5d0dcd73d323834363f3b313a39333e35303c37cdc2c8c4c6cf'
    'cbc1cac9c3cec5c0ccc79d929894969f9b919a99939e95909c977d727874767f7b71'
    '7a79737e75707c775d525854565f5b515a59535e55505c57ada2a8a4a6afaba1aaa9'
    'a3aea5a0aca76d626864666f6b616a69636e65606c671d121814161f1b111a19131e'
    '15101c17'
)

_CRC_TBL = bytes.fromhex(
    '005ebce2613fdd83c29c7e20a3fd1f419dc3217ffca2401e5f01e3bd3e6082dc'
    '237d9fc1421cfea0e1bf5d0380de3c62bee0025cdf81633d7c22c09e1d43a1'
    'ff4618faa427799bc584da3866e5bb5907db856739bae406581947a5fb7826c4'
    '9a653bd987045ab8e6a7f91b45c6987a24f8a6441a99c7257b3a6486d85b05'
    'e7b98cd2306eedb3510f4e10f2ac2f7193cd114fadf3702ecc92d38d6f31b2'
    'ec0e50aff1134dce90722c6d33d18f0c52b0ee326c8ed0530defb1f0ae4c1291'
    'cf2d73ca947628abf517490856b4ea6937d58b5709ebb536688ad495cb2977f4'
    'aa4816e9b7550b88d6346a2b7597c94a14f6a8742ac896154ba9f7b6fc0a54d7'
    '896b35'
)

_S: list[bytes] | None = None


def _sbox() -> list[bytes]:
    global _S
    if _S is None:
        raw = bytes.fromhex(SBOX_HEX)
        if len(raw) != 1024:
            raise SystemExit('built-in SBOX is corrupted (%d bytes)' % len(raw))
        _S = [raw[i * 256:(i + 1) * 256] for i in range(4)]
    return _S


def _rol32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _f(x: int) -> int:
    s = _sbox()
    return _rol32((s[0][(x >> 24) & 0xFF] << 24) |
                  (s[1][(x >> 16) & 0xFF] << 16) |
                  (s[2][(x >> 8) & 0xFF] << 8) |
                  s[3][x & 0xFF], 11)


def _crypt_block(block: bytes, decrypt: bool) -> bytes:
    key = struct.unpack('<8I', bytes.fromhex(KEYHEX))
    x, y = struct.unpack('<II', block)
    seq = (list(range(8)) + list(range(7, -1, -1)) * 3) if decrypt \
        else (list(range(8)) * 3 + list(range(7, -1, -1)))
    for i, k in enumerate(seq):
        if i % 2 == 0:
            y ^= _f((x + key[k]) & 0xFFFFFFFF)
        else:
            x ^= _f((y + key[k]) & 0xFFFFFFFF)
    return struct.pack('<II', y, x)


def crypt(body: bytes, decrypt: bool) -> bytes:
    out = bytearray()
    n = len(body) // 8 * 8
    for i in range(0, n, 8):
        out += _crypt_block(body[i:i + 8], decrypt)
    out += body[n:]
    return bytes(out)


def crc8(data: bytes) -> int:
    c = 0
    for b in data:
        c = _CRC_TBL[c ^ b]
    return c


# --------------------------------------------------------------------------- #
#  XML: tags, attributes, HEX
# --------------------------------------------------------------------------- #

OPEN_TAG = re.compile(rb'<\xd4\xe0\xe9\xeb[^>]*>')      # <File ...>
CLOSE_TAG = b'</\xd4\xe0\xe9\xeb>'
RE_SIZE = rb'\xf0\xe0\xe7\xec\xe5\xf0="(\d+)"'          # size="N"
RE_CRC = rb'\xea\xf1="(\d+)"'                           # crc="N"
RE_NAME = rb'\xe8\xec\xff="([^"]*)"'                    # name="..."
RE_VER = rb'\xe2\xe5\xf0\xf1\xe8\xff="([^"]*)"'         # version="..."
RE_SUB = rb'(\xcf\xee\xe4\xe2\xe5\xf0\xf1\xe8\xff )(\d+)'   # "Subversion 34"
RE_AREA = re.compile(rb'<\xce\xe1\xeb\xe0\xf1\xf2\xfc([^>]*)>')  # <Area ...>
RE_PROG = re.compile(rb'<\xcf\xf0\xee\xe3\xf0\xe0\xec\xec\xe0[^>]*>')  # <Program ...>
RE_DESC = rb'\xee\xef\xe8\xf1\xe0\xed\xe8\xe5="([^"]*)"'             # description="..."

DEFAULT_SIZE = 0x20000
SUM_TARGET = 0xF0F1
CK = 0x808
TAIL = 0x0F0F


def _hex_lines(xml: bytes):
    """HEX lines: (start offset in XML, end, bytes of the line)."""
    hx = xml.find(b'<HEX>')
    if hx < 0:
        return
    hx += 5
    hc = xml.find(b'</HEX>', hx)
    if hc < 0:
        hc = len(xml)
    pos = hx
    while pos < hc:
        while pos < hc and xml[pos] in (9, 10, 13, 32):
            pos += 1
        start = pos
        while pos < hc and xml[pos] not in (10, 13):
            pos += 1
        if pos > start:
            yield start, pos, bytes(xml[start:pos])
        if pos < hc:
            pos += 1


def _hex_record(line: bytes):
    """Parse a single Intel HEX record -> (address, type, data) or None."""
    if len(line) < 11 or line[0:1] != b':':
        return None
    try:
        n = int(line[1:3], 16)
        addr = int(line[3:7], 16)
        typ = int(line[7:9], 16)
        d = bytes.fromhex(line[9:9 + 2 * n].decode('ascii'))
    except (ValueError, UnicodeDecodeError):
        return None
    if len(d) != n:
        return None
    return addr, typ, d


def hex_segments(xml: bytes) -> list[tuple[int, int]]:
    """Contiguous address ranges covered by type 0 records."""
    segs: list[tuple[int, int]] = []
    base = 0
    for _s, _e, line in _hex_lines(xml):
        r = _hex_record(line)
        if not r:
            continue
        addr, typ, d = r
        if typ == 0:
            a, b = base + addr, base + addr + len(d) - 1
            segs.append((a, b))
        elif typ == 4 and len(d) >= 2:
            base = ((d[0] << 8) | d[1]) << 16
        elif typ == 2 and len(d) >= 2:
            base = ((d[0] << 8) | d[1]) << 4
    out: list[tuple[int, int]] = []
    for a, b in sorted(segs):
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def image_span(xml: bytes) -> tuple[int, int]:
    """(lo, hi) of the main area: the group of records with the largest volume.

    Configuration/EEPROM/ID live in separate groups far beyond the code
    (0x200000, 0x300000, 0xF00000, 0x4000xxxx) and are not part of the image.
    """
    segs = hex_segments(xml)
    if not segs:
        return 0, -1
    groups: list[list[tuple[int, int]]] = []
    for a, b in segs:
        if groups and a - groups[-1][-1][1] <= 0x10000:
            groups[-1].append((a, b))
        else:
            groups.append([(a, b)])
    g = max(groups, key=lambda gg: sum(b - a + 1 for a, b in gg))
    return g[0][0], g[-1][1]


def image_size(xml: bytes) -> int:
    _lo, hi = image_span(xml)
    return hi + 1 if hi >= 0 else 0


def parse_hex(xml: bytes):
    """map: image address -> (position in XML, ASCII offset)"""
    cov: dict[int, tuple[int, int]] = {}
    base = 0
    for start, _end, line in _hex_lines(xml):
        r = _hex_record(line)
        if not r:
            continue
        addr, typ, d = r
        if typ == 0:
            for k in range(len(d)):
                cov[base + addr + k] = (start, 9 + 2 * k)
        elif typ == 4 and len(d) >= 2:
            base = ((d[0] << 8) | d[1]) << 16
        elif typ == 2 and len(d) >= 2:
            base = ((d[0] << 8) | d[1]) << 4
    return cov


def area_size(xml: bytes) -> int:
    """Declared size of the first <Area> (informational, not the image size)."""
    m = RE_AREA.search(xml)
    if m:
        m2 = re.search(rb'\xf0\xe0\xe7\xec\xe5\xf0="(\d+)"', m.group(1))
        if m2:
            return int(m2.group(1))
    return DEFAULT_SIZE


def decode_hex(xml: bytes, size: int | None = None) -> bytes:
    if size is None:
        size = image_size(xml)
    img = bytearray(b'\xFF') * size
    base = 0
    for _s, _e, line in _hex_lines(xml):
        r = _hex_record(line)
        if not r:
            continue
        addr, typ, d = r
        if typ == 0:
            a = base + addr
            if a >= size:
                continue
            n = min(len(d), size - a)
            img[a:a + n] = d[:n]
        elif typ == 4 and len(d) >= 2:
            base = ((d[0] << 8) | d[1]) << 16
        elif typ == 2 and len(d) >= 2:
            base = ((d[0] << 8) | d[1]) << 4
    return bytes(img)


def hex_text(xml: bytes) -> str:
    hx = xml.find(b'<HEX>') + 5
    hc = xml.find(b'</HEX>', hx)
    t = xml[hx:hc].replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    return t.decode('ascii', 'replace').strip() + '\n'


# --------------------------------------------------------------------------- #
#  image: invariants, compensator
# --------------------------------------------------------------------------- #

def word(img: bytes, a: int) -> int:
    return img[a] | (img[a + 1] << 8)


def wsum(d: bytes, lo: int, hi: int) -> int:
    t = 0
    for i in range(lo, hi - 1, 2):
        t += d[i] | (d[i + 1] << 8)
    return t & 0xFFFF


def image_kind(img: bytes) -> str:
    """'header' — image with a header at 0x800, otherwise 'generic'."""
    if len(img) < 0x80C:
        return 'generic'
    if img[0x802:0x804] != b'\x01\x00' or img[0x80A:0x80C] != b'\xFF\x00':
        return 'generic'
    W = 0x10000 + word(img, 0x800)
    return 'header' if 0x800 < W <= len(img) - 2 else 'generic'


def xml_meta(xml: bytes) -> dict:
    """Version/description from the <Program ...> tag."""
    m = RE_PROG.search(xml)
    tag = m.group(0) if m else b''
    ver = re.search(RE_VER, tag)
    desc = re.search(RE_DESC, tag)
    sub = re.search(RE_SUB, tag)
    return {
        'xml_version': ver.group(1).decode('ascii', 'replace') if ver else None,
        'xml_description': human(desc.group(1)) if desc else None,
        'xml_subversion': int(sub.group(2)) if sub else None,
    }


def image_info(img: bytes) -> dict:
    info = {
        'kind': image_kind(img),
        'size': len(img),
        'w0': None,
        'W': None,
        'version': None,
        'subversion': None,
        'ck': None,
        'header': img[0x800:0x80C].hex(' ') if len(img) >= 0x80C else '',
        'sum': None,
        'sum_plus2': None,
        'tail': None,
        'sum_ok': False,
        'sum2_ok': False,
        'tail_ok': False,
    }
    if info['kind'] != 'header':
        info['used'] = sum(1 for b in img if b != 0xFF)
        return info
    w0 = word(img, 0x800)
    W = 0x10000 + w0
    info['w0'] = w0
    info['W'] = W
    info['version'] = word(img, 0x804)
    info['subversion'] = word(img, 0x806)
    info['ck'] = word(img, CK)
    info['sum'] = wsum(img, 0x800, W)
    info['sum_plus2'] = wsum(img, 0x800, W + 2)
    info['tail'] = word(img, W)
    # universal invariant: the sum over [0x800, W+2) is zero
    info['sum_ok'] = info['sum_plus2'] == 0
    info['sum2_ok'] = info['sum_plus2'] == 0
    info['tail_ok'] = info['tail'] == TAIL
    return info


def fix_ck(img: bytes) -> tuple[bytes, int]:
    img = bytearray(img)
    W = 0x10000 + word(img, 0x800)
    if not (0x800 < W <= len(img) - 2):
        raise SystemExit('W=0x%X is outside the image — nothing to fix the crc with' % W)
    img[CK:CK + 2] = b'\x00\x00'
    ck = (-wsum(img, 0x800, W + 2)) & 0xFFFF
    img[CK:CK + 2] = ck.to_bytes(2, 'little')
    return bytes(img), ck



# --------------------------------------------------------------------------- #
#  container
# --------------------------------------------------------------------------- #

def human(b: bytes) -> str:
    return b.decode('cp1251', 'replace')


class Container:
    def __init__(self, path: str):
        self.path = path
        self.raw = open(path, 'rb').read()
        if len(self.raw) < 16:
            raise SystemExit('%s: file is too small' % path)
        self.byte0 = self.raw[0]
        self.pt = crypt(self.raw[1:], True)
        self.xml = self.pt.rstrip(b'\x00')
        self.pad = len(self.pt) - len(self.xml)
        m = OPEN_TAG.match(self.xml)
        if not m:
            raise SystemExit('%s: no <File> tag (not a .chp?)' % path)
        self.tag = m.group(0)
        self.payload = self.xml[m.end():self.xml.rfind(CLOSE_TAG)]
        mn = re.search(RE_NAME, self.tag)
        self.name = mn.group(1) if mn else b''
        self.size_attr = int(re.search(RE_SIZE, self.tag).group(1))
        self.kc_attr = int(re.search(RE_CRC, self.tag).group(1))
        self.area = area_size(self.xml)
        self.image = decode_hex(self.xml)
        self.kind = image_kind(self.image)
        self.span = image_span(self.xml)
        self.meta = xml_meta(self.xml)

    # ---- checks ----
    def check(self) -> list[str]:
        bad = []
        if len(self.pt) % 8:
            bad.append('decrypted text length is not a multiple of 8')
        expect_pad = 8 - (len(self.xml) % 8)
        if self.pad != expect_pad:
            bad.append('padding %d, expected %d' % (self.pad, expect_pad))
        if self.byte0 != 8 - expect_pad:
            bad.append('byte0=%d, expected %d' % (self.byte0, 8 - expect_pad))
        if self.size_attr != len(self.payload):
            bad.append('size="%d", actual %d' % (self.size_attr, len(self.payload)))
        if self.kc_attr != crc8(self.payload):
            bad.append('crc="%d", crc8=%d' % (self.kc_attr, crc8(self.payload)))
        return bad

    def info(self) -> dict:
        ii = image_info(self.image)
        d = {
            'file': self.path,
            'file_size': len(self.raw),
            'name_attr': human(self.name),
            'size_attr': self.size_attr,
            'kc_attr': self.kc_attr,
            'kc_crc8': crc8(self.payload),
            'byte0': self.byte0,
            'pad': self.pad,
            'area_size': self.area,
            'kind': self.kind,
            'image_lo': self.span[0],
            'image_hi': self.span[1],
            'image_size': len(self.image),
            'image_sha256': hashlib.sha256(self.image).hexdigest(),
            'file_sha256': hashlib.sha256(self.raw).hexdigest(),
            'header': ii['header'],
            'version': ii['version'],
            'subversion': ii['subversion'],
            'ck': ii['ck'],
            'W': ii['W'],
            'sum': ii.get('sum'),
            'sum_plus2': ii.get('sum_plus2'),
            'tail': ii.get('tail'),
            'sum_ok': ii['sum_ok'],
            'sum2_ok': ii['sum2_ok'],
            'tail_ok': ii['tail_ok'],
            'problems': self.check(),
        }
        d.update(self.meta)
        return d

    def save(self, out: str, xml: bytes, expect: bytes | None = None) -> None:
        xml = bytes(xml)
        pad = 8 - (len(xml) % 8)
        byte0 = 8 - pad
        pt = xml + b'\x00' * pad
        raw = bytes([byte0]) + crypt(pt, False)
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        open(out, 'wb').write(raw)
        chk = Container(out)
        if chk.xml != xml:
            raise SystemExit('self-check: XML after assembly did not match')
        if chk.check():
            raise SystemExit('self-check: ' + '; '.join(chk.check()))
        if expect is not None and chk.image != expect:
            raise SystemExit('self-check: image after assembly did not match')


# --------------------------------------------------------------------------- #
#  assembly
# --------------------------------------------------------------------------- #

def encode_diff(xml: bytes, base: bytes, new: bytes) -> tuple[bytes, list[tuple[int, int, int]]]:
    if len(base) != len(new):
        raise SystemExit('image size %d != %d' % (len(new), len(base)))
    cov = parse_hex(xml)
    diffs = [(a, base[a], new[a]) for a in range(len(new)) if new[a] != base[a]]
    miss = [a for a, _, _ in diffs if a not in cov]
    if miss:
        raise SystemExit('addresses not covered by HEX: ' +
                         ' '.join('%05X' % a for a in miss[:10]))
    xml = bytearray(xml)
    for a, _o, n in diffs:
        p, off = cov[a]
        xml[p + off:p + off + 2] = b'%02X' % n
    xml = bytes(xml)
    if decode_hex(xml) != new:
        raise SystemExit('HEX after the edit did not match the image')
    return xml, diffs


def _set_text(xml: bytes, rx: bytes, value: bytes, what: str,
              group: int = 1) -> bytes:
    ms = list(re.finditer(rx, xml))
    if not ms:
        print('  ! %s: not found, left as is' % what, file=sys.stderr)
        return xml
    if len(ms) != 1:
        raise SystemExit('%s: found %d occurrences' % (what, len(ms)))
    m = ms[0]
    return xml[:m.start(group)] + value + xml[m.end(group):]


def _set_prog_text(xml: bytes, rx: bytes, value: bytes, what: str,
                   group: int = 1) -> bytes:
    """Edit an attribute only inside the <Program ...> tag.

    The XML may contain several version="..." attributes (in <File> and in
    <Program>), so the search is strictly inside the program tag.
    """
    m = RE_PROG.search(xml)
    if not m:
        print('  ! %s: no <Program> tag, left as is' % what,
              file=sys.stderr)
        return xml
    tag = m.group(0)
    ms = list(re.finditer(rx, tag))
    if not ms:
        print('  ! %s: not found, left as is' % what, file=sys.stderr)
        return xml
    if len(ms) != 1:
        raise SystemExit('%s: found %d occurrences' % (what, len(ms)))
    h = ms[0]
    tag = tag[:h.start(group)] + value + tag[h.end(group):]
    return xml[:m.start()] + tag + xml[m.end():]


def _rebuild_tag(xml: bytes) -> bytes:
    m = OPEN_TAG.match(xml)
    tag = m.group(0)
    payload = xml[m.end():xml.rfind(CLOSE_TAG)]
    tag = re.sub(RE_SIZE, b'\xf0\xe0\xe7\xec\xe5\xf0="' +
                 str(len(payload)).encode() + b'"', tag)
    tag = re.sub(RE_CRC, b'\xea\xf1="' + str(crc8(payload)).encode() + b'"', tag)
    return tag + xml[m.end():]


def rebuild(base: Container, img: bytes, out: str, *,
            name: bytes | None = None, sub: int | None = None,
            ver: str | None = None, fixck: bool = True,
            quiet: bool = False) -> dict:
    img = bytearray(img)
    if len(img) != len(base.image):
        raise SystemExit('image must be %d bytes, got %d'
                         % (len(base.image), len(img)))

    has_header = image_kind(bytes(img)) == 'header'

    if sub is not None:
        if not has_header:
            raise SystemExit('image has no 0x800 header — --sub is not applicable')
        img[0x806:0x808] = int(sub).to_bytes(2, 'little')
    if ver is not None:
        if not has_header:
            raise SystemExit('image has no 0x800 header — --ver is not applicable')
        # "2.75" -> 275
        try:
            v = int(ver.replace('.', ''))
        except ValueError:
            raise SystemExit('version must look like 2.75')
        if not 0 < v < 1000:
            raise SystemExit('version out of range: %s' % ver)
        img[0x804:0x806] = v.to_bytes(2, 'little')

    img = bytes(img)
    if fixck and has_header:
        img, ck = fix_ck(img)
    else:
        ck = word(img, CK) if has_header else None

    xml, diffs = encode_diff(base.xml, base.image, img)

    if name is not None:
        xml = _set_text(xml, RE_NAME, name, 'name')
    if sub is not None:
        xml = _set_prog_text(xml, RE_SUB, str(int(sub)).encode(),
                             'description "Subversion N"', 2)
    if ver is not None:
        xml = _set_prog_text(xml, RE_VER, ver.encode(), 'version', 1)

    xml = _rebuild_tag(xml)
    base.save(out, xml, expect=img)

    info = image_info(img)
    if not quiet:
        print('=== %s' % out)
        for a, o, n in diffs:
            print('  %05X: %02X -> %02X' % (a, o, n))
        if not diffs:
            print('  (image unchanged)')
        if info['kind'] == 'header':
            print('  version/subversion: %d / %d'
                  % (info['version'], info['subversion']))
            print('  crc              : %04X' % info['ck'])
            print('  sum/sum+2        : %04X (%s) / %04X (%s)' % (
                info.get('sum', -1), 'ok' if info['sum_ok'] else 'BAD',
                info.get('sum_plus2', -1), 'ok' if info['sum2_ok'] else 'BAD'))
            print('  tail @%05X      : %04X%s' % (
                info['W'], info.get('tail', -1),
                '' if info['tail_ok'] else '  (not 0F0F, official files have this too)'))
        else:
            print('  image            : %d bytes, no 0x800 header' % len(img))
        print('  file             : %d bytes, sha256 %s'
              % (os.path.getsize(out),
                 hashlib.sha256(open(out, 'rb').read()).hexdigest()))

    res = {'out': out, 'diffs': diffs, 'ck': ck}
    res.update(info)
    return res


# --------------------------------------------------------------------------- #
#  commands
# --------------------------------------------------------------------------- #

def parse_addr(s: str) -> int:
    s = s.strip()
    if s.lower().startswith('0x'):
        return int(s, 16)
    if s.lower().endswith('h'):
        return int(s[:-1], 16)
    return int(s, 0)


def cmd_info(a) -> None:
    c = Container(a.file)
    d = c.info()
    if a.json:
        print(json.dumps(d, ensure_ascii=False, indent=2))
        return
    print('file        : %s' % d['file'])
    print('  inside    : %s' % d['name_attr'])
    print('  size      : %d bytes in file, attribute %d' % (d['file_size'], d['size_attr']))
    print('  crc       : %d (crc8 %d)' % (d['kc_attr'], d['kc_crc8']))
    print('  container : byte0=%d pad=%d' % (d['byte0'], d['pad']))
    print('  area      : %d bytes (0x%X)' % (d['area_size'], d['area_size']))
    print('  XML       : version %s, subversion %s'
          % (d.get('xml_version') or '-',
             d['xml_subversion'] if d.get('xml_subversion') is not None else '-'))
    print('image       : %d bytes (0x%X..0x%X), kind %s'
          % (d['image_size'], d['image_lo'], d['image_hi'], d['kind']))
    if d['kind'] == 'header':
        print('  header    : %s' % d['header'])
        print('  version   : %d (%.2f), subversion %d'
              % (d['version'], d['version'] / 100.0, d['subversion']))
        print('  W         : 0x%05X' % d['W'])
        print('  sum       : %s / sum+2 %s / tail %s'
              % ('ok' if d['sum_ok'] else 'BAD',
                 'ok' if d['sum2_ok'] else 'BAD',
                 'ok' if d['tail_ok'] else 'not 0F0F'))
    print('  sha256    : %s' % d['image_sha256'])
    if d['problems']:
        print('ERRORS:')
        for p in d['problems']:
            print('  - %s' % p)
    else:
        print('container  : ok')


def _expand(paths: list[str]) -> list[str]:
    """Expand directories into a list of .chp files."""
    out: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            out += [os.path.join(p, n) for n in sorted(os.listdir(p))
                    if n.lower().endswith('.chp')]
        else:
            out.append(p)
    return out


def cmd_verify(a) -> None:
    files = _expand(a.files)
    if not files:
        raise SystemExit('no .chp files found')
    bad = 0
    for path in files:
        print('%s' % path)
        try:
            c = Container(path)
        except (SystemExit, Exception) as e:
            print('  ERROR     : %s' % e)
            bad += 1
            continue
        probs = list(c.check())
        info = image_info(c.image)
        if info['kind'] == 'header':
            if not info['sum_ok']:
                probs.append('image sum is not 0')
            if not info['sum2_ok']:
                probs.append('sum+2 is not 0')
            print('  container : %s' % ('ok' if not c.check() else
                                        '; '.join(c.check())))
            print('  image    : %d bytes, version %d/%d, crc %04X, '
                  'sum %04X (%s), sum+2 %04X (%s)'
                  % (len(c.image), info['version'], info['subversion'],
                     info['ck'], info.get('sum', -1),
                     'ok' if info['sum_ok'] else 'BAD',
                     info.get('sum_plus2', -1),
                     'ok' if info['sum2_ok'] else 'BAD'))
        else:
            if info['size'] == 0:
                probs.append('HEX without data')
            print('  container : %s' % ('ok' if not c.check() else
                                        '; '.join(c.check())))
            print('  image    : %d bytes (0x%X..0x%X), no 0x800 header, '
                  'used %d'
                  % (len(c.image), c.span[0], c.span[1],
                     sum(1 for b in c.image if b != 0xFF)))
        if probs:
            print('  PROBLEMS  : %s' % '; '.join(probs))
            bad += 1
        else:
            print('  result    : ok')
    print('---')
    print('checked %d, problems %d' % (len(files), bad))
    if bad:
        raise SystemExit('%d file(s) with problems' % bad)


def cmd_unpack(a) -> None:
    c = Container(a.file)
    os.makedirs(a.out, exist_ok=True)
    stem = os.path.splitext(os.path.basename(a.file))[0]
    p_bin = os.path.join(a.out, stem + '.bin')
    p_xml = os.path.join(a.out, stem + '.xml')
    p_hex = os.path.join(a.out, stem + '.hex')
    p_json = os.path.join(a.out, stem + '.json')

    open(p_bin, 'wb').write(c.image)
    open(p_xml, 'w', encoding='utf-8', newline='\n').write(
        c.xml.decode('cp1251', 'replace').replace('\r\n', '\n'))
    open(p_hex, 'w', encoding='ascii', newline='\n').write(hex_text(c.xml))

    d = c.info()
    d['files'] = {'bin': p_bin, 'xml': p_xml, 'hex': p_hex}
    open(p_json, 'w', encoding='utf-8', newline='\n').write(
        json.dumps(d, ensure_ascii=False, indent=2) + '\n')

    print('unpacked: %s' % a.out)
    print('  %-40s %d bytes' % (os.path.basename(p_bin), len(c.image)))
    print('  %-40s %d bytes' % (os.path.basename(p_xml), len(c.xml)))
    print('  %-40s %d lines' % (os.path.basename(p_hex), hex_text(c.xml).count('\n')))
    print('  %-40s metadata' % os.path.basename(p_json))
    if d['kind'] == 'header':
        print('  version %d / subversion %d, crc %04X, W=0x%05X'
              % (d['version'], d['subversion'], d['ck'], d['W']))
    else:
        print('  image %d bytes without a 0x800 header (generic kind)' % len(c.image))
    if d['problems']:
        print('  WARNING: ' + '; '.join(d['problems']))


def cmd_pack(a) -> None:
    base = Container(a.file)
    img = open(a.bin, 'rb').read()
    name = a.name.encode('cp1251') if a.name else default_name(a, base, a.out)
    rebuild(base, img, a.out, name=name, sub=a.sub, ver=a.ver,
            fixck=not a.no_fixck)


def cmd_set(a) -> None:
    base = Container(a.file)
    img = bytearray(base.image)
    edits = []
    for spec in a.byte or []:
        k, v = spec.split('=')
        addr = parse_addr(k)
        val = int(v, 16) if not v.lower().startswith('0x') else int(v, 16)
        if not 0 <= val <= 0xFF:
            raise SystemExit('byte out of range: %s' % spec)
        edits.append((addr, img[addr], val, 1))
        img[addr] = val
    for spec in a.word or []:
        k, v = spec.split('=')
        addr = parse_addr(k)
        val = int(v, 16)
        if not 0 <= val <= 0xFFFF:
            raise SystemExit('word out of range: %s' % spec)
        cur = word(img, addr)
        edits.append((addr, cur, val, 2))
        img[addr:addr + 2] = val.to_bytes(2, 'little')
    name = a.name.encode('cp1251') if a.name else default_name(a, base, a.out)
    print('edits:')
    for addr, o, n, size in edits:
        if size == 1:
            print('  %05X: %02X -> %02X' % (addr, o, n))
        else:
            print('  %05X: %04X -> %04X' % (addr, o, n))
    rebuild(base, bytes(img), a.out, name=name, sub=a.sub, ver=a.ver,
            fixck=not a.no_fixck)


def default_name(a, base: Container, out: str) -> bytes | None:
    stem = os.path.splitext(os.path.basename(out))[0]
    new = stem.encode('cp1251')
    if new == base.name:
        return None
    if len(new) != len(base.name):
        print('  ! name "%s" (%d bytes) does not fit instead of "%s" '
              '(%d bytes) — old one kept'
              % (stem, len(new), human(base.name), len(base.name)),
              file=sys.stderr)
        return None
    return new


def cmd_diff(a) -> None:
    ca = Container(a.a)
    cb = Container(a.b)
    if len(ca.image) != len(cb.image):
        raise SystemExit('different image sizes: %d / %d'
                         % (len(ca.image), len(cb.image)))
    diffs = [(i, ca.image[i], cb.image[i])
             for i in range(len(ca.image)) if ca.image[i] != cb.image[i]]
    print('%s  ->  %s' % (a.a, a.b))
    print('  bytes differing: %d' % len(diffs))
    for i, x, y in diffs:
        print('  %05X: %02X -> %02X' % (i, x, y))
    ia, ib = image_info(ca.image), image_info(cb.image)
    if ia['kind'] == 'header' and ib['kind'] == 'header':
        print('  version/subversion: %d/%d -> %d/%d'
              % (ia['version'], ia['subversion'], ib['version'], ib['subversion']))
        print('  crc              : %04X -> %04X' % (ia['ck'], ib['ck']))
    else:
        print('  kind             : %s -> %s' % (ia['kind'], ib['kind']))


def cmd_image(a) -> None:
    img = open(a.bin, 'rb').read()
    d = image_info(img)
    print('image    : %s (%d bytes)' % (a.bin, len(img)))
    if d['kind'] == 'header':
        print('  header    : %s' % d['header'])
        print('  W         : 0x%05X' % d['W'])
        print('  version   : %d (%.2f), subversion %d'
              % (d['version'], d['version'] / 100.0, d['subversion']))
        print('  sum       : %s, sum+2 %s, tail %04X'
              % ('ok' if d['sum_ok'] else 'BAD',
                 'ok' if d['sum2_ok'] else 'BAD', d.get('tail', -1)))
    else:
        print('  kind      : no 0x800 header (generic)')
        print('  used      : %d bytes' % d.get('used', 0))
    print('  sha256    : %s' % hashlib.sha256(img).hexdigest())


def cmd_fixck(a) -> None:
    img = open(a.bin, 'rb').read()
    new, ck = fix_ck(img)
    if a.out:
        open(a.out, 'wb').write(new)
        print('%s -> %s  crc %04X -> %04X' % (a.bin, a.out, word(img, CK), ck))
    else:
        open(a.bin, 'wb').write(new)
        print('%s  crc %04X -> %04X' % (a.bin, word(img, CK), ck))


# --------------------------------------------------------------------------- #

def main(argv=None) -> None:
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    try:
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

    p = argparse.ArgumentParser(
        prog='chp.py',
        description='unpack/assemble .chp firmware containers')
    sub = p.add_subparsers(dest='cmd', required=True)

    s = sub.add_parser('info', help='show the container and the image')
    s.add_argument('file')
    s.add_argument('--json', action='store_true')
    s.set_defaults(func=cmd_info)

    s = sub.add_parser('verify', help='verify one or more .chp files')
    s.add_argument('files', nargs='+')
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser('unpack', help='split into .bin/.xml/.hex/.json')
    s.add_argument('file')
    s.add_argument('-o', '--out', default=None,
                   help='directory (default: next to the file)')
    s.set_defaults(func=cmd_unpack)

    s = sub.add_parser('pack', help='build a .chp from a modified .bin')
    s.add_argument('file')
    s.add_argument('-b', '--bin', required=True)
    s.add_argument('-o', '--out', required=True)
    s.add_argument('--sub', type=int, help='subversion (0x806)')
    s.add_argument('--ver', help='version, e.g. 2.75 (0x804)')
    s.add_argument('--name', help='internal name (default = output name)')
    s.add_argument('--no-fixck', action='store_true',
                   help='do not recompute the crc at 0x808')
    s.set_defaults(func=cmd_pack)

    s = sub.add_parser('set', help='edit bytes/words in place + rebuild')
    s.add_argument('file')
    s.add_argument('-o', '--out', required=True)
    s.add_argument('--byte', action='append', metavar='ADDR=BYTE',
                   help='e.g. 0x5518=A0')
    s.add_argument('--word', action='append', metavar='ADDR=WORD',
                   help='e.g. 0x5924=9E83')
    s.add_argument('--sub', type=int)
    s.add_argument('--ver')
    s.add_argument('--name')
    s.add_argument('--no-fixck', action='store_true')
    s.set_defaults(func=cmd_set)

    s = sub.add_parser('diff', help='compare two .chp files')
    s.add_argument('a')
    s.add_argument('b')
    s.set_defaults(func=cmd_diff)

    s = sub.add_parser('image', help='summarize a .bin')
    s.add_argument('bin')
    s.set_defaults(func=cmd_image)

    s = sub.add_parser('fixck', help='recompute the crc in a .bin')
    s.add_argument('bin')
    s.add_argument('-o', '--out')
    s.set_defaults(func=cmd_fixck)

    a = p.parse_args(argv)
    if getattr(a, 'out', None) is None and a.cmd == 'unpack':
        a.out = os.path.splitext(os.path.abspath(a.file))[0] + '_unpacked'
    a.func(a)


if __name__ == '__main__':
    main()
