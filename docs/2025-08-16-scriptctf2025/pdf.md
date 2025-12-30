# pdf

There is a hint in the pdf:

```
maybe look between stream and endstream
```

The stream is compressed:

```
<< /Length 48 /Filter /FlateDecode >>
stream
x<9c>+N.Ê,(q^Nq«.HI<8b>/6/26É5<8d>7(3.<8a>7/74OÎ<88>7-^A<89>^U×^B^@G^B^NÔ
endstream
endobj
```

Use <https://gist.github.com/averagesecurityguy/ba8d9ed3c59c1deffbd1390dafa5a3c2> to decompress all streams:

```python

#!/usr/bin/env python3
# This script is designed to do one thing and one thing only. It will find each
# of the FlateDecode streams in a PDF document using a regular expression,
# unzip them, and print out the unzipped data. You can do the same in any
# programming language you choose.
#
# This is NOT a generic PDF decoder, if you need a generic PDF decoder, please
# take a look at pdf-parser by Didier Stevens, which is included in Kali linux.
# https://tools.kali.org/forensics/pdf-parser.
#
# Any requests to decode a PDF will be ignored.
import re
import zlib

pdf = open("some_doc.pdf", "rb").read()
stream = re.compile(rb'.*?FlateDecode.*?stream(.*?)endstream', re.S)

for s in stream.findall(pdf):
    s = s.strip(b'\r\n')
    try:
        print(zlib.decompress(s))
        print("")
    except:
        pass
```

Get flag:

```
b'scriptCTF{pdf_s7r34m5_0v3r_7w17ch_5tr34ms}'

b"q\nq\n0 0 275.258 174.837 re\nW n\n/P BMC \nEMC \n/P BMC \nQ\nBT\n0 g\n/T1_0 12 Tf\n0 Tc 0 Tw 0 Ts 100 Tz 0 Tr 0 162.835 Td\n(thx for comming)Tj\n/C0_0 12 Tf\n1 0 0 1 85.356 162.8346 Tm\n<0000>Tj\n/T1_0 12 Tf\n-85.356 -11.998 Td\n(but no flag here :\\))Tj\nET\nEMC \nq\n0 0 275.258 174.837 re\nW n\n/P BMC \nEMC \n/P BMC \nEMC \n/P BMC \nEMC \n/P BMC \nEMC \n/P BMC \nEMC \n/P BMC \nEMC \n/P BMC \nEMC \n/P BMC \nEMC \n/P BMC \nEMC \n/P BMC \nQ\nBT\n0.996 g\n0 42.837 Td\n(scriptCTF{this_is_def_the_flag_trust)Tj\n0 -12 Td\n(} i told u there's not flag here)Tj\nET\nEMC \nQ\n"

b'\x01\x00\x04\x02\x00\x01\x01\x01\x0eTLJDPL+Symbol\x00\x01\x01\x012\xf8\x1b\xf8\x1c\x8b\x0c\x1e\xf8\x1d\x01\xf8\x17\x04\xf8\x1e\x0c\x15\xfbH\xfb\xb9\xfa\xd6\xfa\x86\x05\x1d\x00\x00\xa7\xf4\r\x8c\x0c"\xf7q\x0f\xf7t\x11\xf7r\x0c%\xf7z\x0c$\x00\x05\x01\x01\x06\x0ei\x81\x87AdobeIdentityCopyright (c) 1985, 1987, 1989, 1990, 1997 Adobe Systems Incorporated. All rights reserved./OrigFontType /Type1 defSymbol\x00\x00\x00\x00\x00\x00\x01\x01\x01\x02\x0e\x00\x01\x01\x01\t\xf8\x1f\x0c&\x9b\xf7\x87\x12x\x9e\xf95\x9a\xfb]\x98\x06\xe7\n\xe0\x0b\xf7\x8e\x14'

b'\x80'

b'/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo\n<< /Registry (Adobe)\n/Ordering (UCS) /Supplement 0 >> def\n/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n1 beginbfchar\n<0000> <0020>\nendbfchar\nendcmap CMapName currentdict /CMap defineresource pop end end\n'

b'/ADBE_FillSign BMC \nq\n0 TL/Fm0 Do\nQ\nEMC \n'
```