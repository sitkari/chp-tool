# chp-tool

Unpacker/packer for `.chp` firmware containers.

## Command line

| command | what it does |
|---|---|
| `info FILE.chp` | header, checksum, sizes, version/subversion, `W`, invariants |
| `unpack FILE.chp [-o DIR]` | writes `*.bin`, `*.xml`, `*.hex`, `*.json` |
| `pack FILE.chp -b NEW.bin -o OUT.chp` | builds a container from a modified image |
| `set FILE.chp -o OUT.chp --byte A=V --word A=V` | edits bytes/words in place and builds |
| `diff A.chp B.chp` | lists differences between two images |
| `verify FILE.chp...` | checks the container and invariants (files or directories) |
| `image FILE.bin` | summary of a raw image |
| `fixck FILE.bin [-o OUT.bin]` | recompute the `0x808` checksum |

Common build options: `--sub N`, `--ver x.xx`, `--name "..."`, `--no-fixck`.

### Examples

**See what is inside**

```bat
python chp.py info "xxx.chp"
python chp.py unpack "xxx.chp" -o work
```

**Patch bytes directly from the container**

```bat
python chp.py set "xxx.chp" -o "xxx.chp" ^
    --word 0x5924=9E83 --word 0x5926=0000 --sub 37 --name "xxx.chp"
```

`--word` writes little-endian (`0x5924=9E83` -> bytes `83 9E`).
`--byte` writes a single byte (`0x5518=A0`).

**Edit in a hex editor**

```bat
python chp.py unpack "xxx.chp" -o work
rem ... edit work\xxx.bin ...
python chp.py pack "xxx.chp" -b "work\xxx.bin" ^
    -o "xxx.chp" --sub 38
```

## Format (brief)

```
file   = [byte0] + encrypt(XML + pad)
         pad   = 8 - (len(XML) % 8)      # 1..8 zero bytes
         byte0 = 8 - pad                 # validated by the vendor tool

XML    = <File name="..." size="len(payload)" crc="crc8(payload)">
             <Device type="16" versions="0.11">
                 <Program version="2.75" description="Subversion 34" ...>
                     <Area address="2048" size="131072" offset="2048">
             <HEX> :10 0800 00 ... </HEX>
         </File>                             # cp1251, Russian tag names
```

The cipher is a block cipher over 8-byte blocks; the key and S-boxes are
embedded in `chp.py`. `crc` is CRC-8 (table-driven) over the whole payload
between the root open and close tags.

Image header:

| address | value |
|---|---|
| `0x800` | `w0`, end of the checksummed area `W = 0x10000 + w0` |
| `0x802` | `0x0001` |
| `0x804` | version (275 = 2.75) |
| `0x806` | subversion (34) |
| `0x808` | checksum: `(0xF0F1 - sum16LE[0x800,W)) & 0xFFFF` |
| `0x80A` | `FF 00` |
| `0x80C` | `GOTO` - application entry |
| `0x810` | `GOTO` - interrupt handler |

Invariants checked by `verify`:

```
sum16LE[0x800, W)  == 0xF0F1
sum16LE[0x800, W+2) == 0x0000
word[W] == 0x0F0F        # differs in some official builds - reported as a warning
```


## Important

This project is not affiliated with any device manufacturer. Device names and
formats are mentioned only for compatibility. Firmware files, dumps and other
vendor materials are not part of the repository and are not distributed. Use
the tool only with your own devices and at your own risk. Before publishing,
check the license/EULA of your software and the laws of your country.
