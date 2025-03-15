# white

[library.m0unt41n.ch/challenges/white](https://library.m0unt41n.ch/challenges/white) ![](../../resources/misc.svg) ![](../../resources/medium.svg) 

# TL;DR

We get a 255x255 black&white (1-bit) image.

# Analysis

Some usual things to try:
[aperisolve.com](https://www.aperisolve.com),
[StegOnline](https://georgeom.net/StegOnline/upload),
[pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html),
did not reveal anything suspicious.
[PNG file chunk inspector](https://www.nayuki.io/page/png-file-chunk-inspector)
only reinforced that view - there is nothing in metadata whatsoever.
The `NoRelect` string is correctly deflated.

My next bet was that maybe there is something appended to the compressed data in
`IDAT` chunks. I haven't found a simple decoder, but looking at the chunk
inspector (above) made it clear that each chunk has two bytes of data, right
after the `IDAT` tag. So, we can extract the compressed stream:

```python
png = open("white.png", "rb").read(65536)
raw = b''
for i in range(len(png)-4):
  try:
    if png[i:i+4].decode('ascii') == "IDAT":
      raw += png[i+4:i+6]
  except UnicodeDecodeError:
    pass
```
... and decompress it:
```python
import zlib
dec = zlib.decompressobj().decompress(raw)
```

The `dec` bytes look as expected: rows of bit pixels, each using 33 bytes,
starting with `0x00`, then 31x `0xFF` and then... I noticed that last byte
of each line is either `0xFE` or`0xFF`. Which makes sense - image width is
255, so, that hides information in the column after the last one! Let's
collect these bits and turn them into chars:

```python
bits = flag = ''
for i in range(32, len(dec), 33):
  bits += str(dec[i] & 1)
  if len(bits)==8:
    flag += chr(int(bits, 2))
    bits = ''
print(flag)
```

---

## `shc2023{y0u_guy5_ar3_da_b35t}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
