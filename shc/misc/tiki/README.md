# tiki

[library.m0unt41n.ch/challenges/tiki](https://library.m0unt41n.ch/challenges/tiki) ![](../../resources/misc.svg) ![](../../resources/easy.svg) 

# TL;DR

A ZIP archive hidden in a PNG image.

Few simple checks:

```bash
$ pngcheck challenge.png
challenge.png  additional data after IEND chunk
ERROR: challenge.png
```

That usually means a file appended to the image adata. What file?

```bash
$ binwalk challenge.png 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1024 x 1024, 8-bit/color RGB, non-interlaced
283           0x11B           Zlib compressed data, best compression
846187        0xCE96B         StuffIt Deluxe Segment (data): f%
1437348       0x15EEA4        Zip archive data, encrypted at least v1.0 to extract, compressed size: 40, uncompressed size: 28, name: flag.txt
1437548       0x15EF6C        End of Zip archive, footer length: 22
```

A ZIP, containing `flag.txt`, nice &#128578;

```bash
$ binwalk -o 1437348 -e challenge.png 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
1437348       0x15EEA4        Zip archive data, encrypted at least v1.0 to extract, compressed size: 40, uncompressed size: 28, name: flag.txt
1437548       0x15EF6C        End of Zip archive, footer length: 22

unzip _challenge.png.extracted/15EEA4.zip 
Archive:  _challenge.png.extracted/15EEA4.zip
[_challenge.png.extracted/15EEA4.zip] flag.txt password: ^C
```

Where could that password be?

```bash
$ exiftool challenge.png 
(...)
Description                     : m4it4i
```

That works for ZIP extraction &#128578;

---

## `stairctf{tr0p1c4l_surpr1s3}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
