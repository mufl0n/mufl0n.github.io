# blue-revenge

[library.m0unt41n.ch/challenges/blue-revenge](https://library.m0unt41n.ch/challenges/blue-revenge) ![](../../resources/misc.svg) ![](../../resources/hard.svg) 

# TL;DR

We get a PNG file and challenge description that is first verse of
[Blue (Da Ba Dee)](https://genius.com/Eiffel-65-blue-da-ba-dee-lyrics)
by Eiffel 65.

![](blue_revenge.png "")

The flag is behind few layers of stego and rev &#128578;

# Inspecting the file

[AperiSolve](https://www.aperisolve.com/5282a2546269e99a99beaccbcaee8692) did not yield much.
Displaying the file with ImageMagick works, but with following errors:

```
display: IDAT: Too much image data `blue_revenge.png' @ warning/png.c/MagickPNGWarningHandler/1526.
display: blUe: CRC error `blue_revenge.png' @ warning/png.c/MagickPNGWarningHandler/1526.
display: blUe: CRC error `blue_revenge.png' @ warning/png.c/MagickPNGWarningHandler/1526.
display: blUe: CRC error `blue_revenge.png' @ warning/png.c/MagickPNGWarningHandler/1526.
display: blUe: CRC error `blue_revenge.png' @ warning/png.c/MagickPNGWarningHandler/1526.
display: blUe: CRC error `blue_revenge.png' @ warning/png.c/MagickPNGWarningHandler/1526.
display: blUe: CRC error `blue_revenge.png' @ warning/png.c/MagickPNGWarningHandler/1526.
display: blUe: CRC error `blue_revenge.png' @ warning/png.c/MagickPNGWarningHandler/1526.
display: blUe: CRC error `blue_revenge.png' @ warning/png.c/MagickPNGWarningHandler/1526.
```

`Too much image data` seems like a good hint, the CRC errors a bit less so.

Let's dissect the file.
Following two good PNG inspector tools were helpful:

*   [rameshvarun.github.io/binary-inspector/png](https://rameshvarun.github.io/binary-inspector/png)
*   [nayuki.io/page/png-file-chunk-inspector](https://www.nayuki.io/page/png-file-chunk-inspector)


```
0000  89 50 4e 47 0d 0a 1a 0a                         |.PNG....        | PNG signature
0000                          00 00 00 0d             |        ....    | Chunk len: 13
```
```
                                          49 48 44 52 |            IHDR| Chunk type: IHDR
0010  00 00 01 2c                                     |...,            | Width: 300
0010              00 00 00 c8                         |    ....        | Height: 200
0010                          02                      |        .       | Bit depth: 2 bits per pixel
0010                             03                   |         .      | Color type: 3 (palette)
0010                                00                |          .     | Compression method: 0 (DEFLATE)
0010                                   00             |           .    | Filter method: 0 (Adaptive)
0010                                      00          |            .   | Interlace method: 0 (None)
0010                                         2f b1 34 |             /.4| CRC: 2FB134C6 (OK)
0020  c6                                              |.               |   (cont'd)
```
```
0020     00 00 00 09                                  | ....           | Chunk len: 9
0020                 50 4c 54 45                      |     PLTE       | Chunk type: PLTE
0020                             2c 00 f7 ff 20 85 ff |         ,... ..| Data: 2c00f7ff2085ffffff
0030  ff ff                                           |..              |   (cont'd)
0030        b9 43 78 f3                               |  .Cx.          | CRC: B94378F3 (OK)
```
```
0030                    00 00 03 f9                   |      ....      | Chunk len: 1017
0030                                49 44 41 54       |          IDAT  | Chunk type: IDAT
0030                                            78 01 |              x.| Data:
0040  ed 96 4b 8e dc 30 0c 44 09 af 02 9d c4 d0 29 8d |..K..0.D......).|   (cont'd)
0050  2c e7 14 44 af 0c 9d 32 af 28 77 bb c7 e3 01 82 |,..D...2.(w.....| Decompressed data length: 22 800 bytes
0060  01 b2 09 4a ed 38 96 44 3e 51 45 7d 26 c2 c5 0a |...J.8.D>QE}&...| Pass 0: 300 × 200, 15 200 bytes
0070  58 01 2b 60 05 ac 80 15 b0 02 56 c0 0a 58 01 2b |X.+`......V..X.+| Decompressed data too long !!!
0080  60 05 ac 80 15 b0 02 56 c0 0a 58 01 2b 60 05 ac |`......V..X.+`..|
0090  80 15 b0 02 56 c0 0a 58 01 2b 60 05 ac 80 15 b0 |....V..X.+`.....|
00a0  02 56 c0 0a 58 01 2b 60 05 ac 80 15 b0 02 56 c0 |.V..X.+`......V.|
00b0  0a 58 01 2b 60 05 ac 80 15 b0 02 56 c0 0a 58 01 |.X.+`......V..X.|
00c0  2b 60 05 ac 80 15 b0 02 56 c0 0a 58 01 2b 60 05 |+`......V..X.+`.|
00d0  ac 80 15 b0 02 56 c0 0a 58 01 2b 60 05 ac 80 15 |.....V..X.+`....|
00e0  b0 02 56 e0 ab 02 6d 44 e4 92 b1 2f 23 c6 88 35 |..V...mD.../#..5|
00f0  f8 4a cc a8 46 cf f9 bd c7 ae 96 3d c6 a6 a7 a9 |.J..F......=....|
0100  16 bd de 51 c6 aa 53 3a 9d a9 5f 1b db 18 db 8b |...Q..S:.._.....|
0110  45 35 c6 93 55 0e 8c 3a 59 93 82 b1 fc 97 7a eb |E5..U..:Y.....z.|
0120  0b 56 db 78 c3 ea bf b7 bd e5 8b 45 95 d6 d1 92 |.V.x.......E....|
0130  de bd 6c b0 c4 91 67 b2 66 63 54 17 36 2a c7 2c |..l...g.fcT.6*.,|
0140  96 83 f2 62 f1 71 b2 ba 2c d7 e5 60 d5 8c 9f 11 |...b.q..,..`....|
0150  35 75 51 18 63 85 d5 53 76 7b 71 d7 21 fa 32 54 |5uQ.c..Sv{q.!.2T|
0160  ed 23 89 ab 31 53 2a 59 ed 15 17 2c e6 81 37 66 |.#..1S*Y...,..7f|
0170  51 c3 dc b1 da d6 a1 2c e5 5f ac c7 af 14 31 af |Q......,._....1.|
0180  2c d1 96 8d 61 94 ac 2a 4a 9f 46 c8 e8 cb f6 50 |,...a..*J.F....P|
0190  1e 37 44 51 a4 5b 52 a5 fd b1 67 6f 37 ac 15 57 |.7DQ.[R...go7..W|
01a0  06 de 00 1c ac 48 0a 1e b0 9a 92 c8 a3 c9 c2 0a |.....H..........|
01b0  71 69 87 45 f5 88 2b 73 6a 8f 3f 66 cc 4e f3 cb |qi.E..+sj.?f.N..|
01c0  2f ac d6 94 32 e5 71 91 33 81 2b 83 fc 52 55 f4 |/...2.q.3.+..RU.|
01d0  1a a8 f6 38 59 8d f4 ad 9a 9f e2 63 06 94 39 2c |...8Y......c..9,|
01e0  3e b0 e4 13 27 8b ea c9 ea c5 22 27 4f ed b1 a7 |>...'....."'O...|
01f0  57 2c 96 ee 95 45 fa e2 33 4b 24 fd 34 06 93 f9 |W,...E..3K$.4...|
0200  9c c7 f6 21 0a ac 73 79 8d 0f 99 62 c7 fe 58 df |...!..sy...b..X.|
0210  e2 c2 97 ea c9 c2 83 28 58 04 58 66 30 2c f6 44 |.......(X.Xf0,.D|
0220  86 19 ef a3 20 39 cf 64 91 2f b8 20 d4 b8 29 7d |.... 9.d./. ..)}|
0230  93 35 db f9 a6 fd 9d 45 50 32 7b a2 d4 dd 95 be |.5.....EP2{.....|
0240  64 9c f9 21 d6 d0 c2 e1 7d b0 50 bd 62 6c b4 d4 |d..!....}.P.bl..|
0250  d3 c9 6b 65 03 33 88 67 5c da b1 c5 3a ce 09 2d |..ke.3.g\...:..-|
0260  54 0e 09 d6 74 4c 16 0e af 73 82 48 78 c4 62 ab |T...tL...s.Hx.b.|
0270  e2 55 db e3 09 fb 9b ff a5 d0 b5 bc da 6e fa ae |.U...........n..|
0280  b6 ef f5 97 df 5b e3 5d db 5b f7 b7 9f 77 7e cc |.....[.].[...w~.|
0290  f5 47 e5 96 f5 23 92 9d fe 9d 02 f3 b2 63 97 b0 |.G...#.......c..|
02a0  45 58 f1 9c 16 3a c5 b5 85 f7 39 28 55 16 ba 0e |EX...:....9(U...|
02b0  96 1e bc db 38 bb ae 51 69 df b1 f3 8b c5 f7 d0 |....8..Qi.......|
02c0  45 99 6a 01 aa 1e 9c d9 9b b5 3d 39 48 c5 dd b4 |E.j.......=9H...|
02d0  83 6e cb 68 1b ed 3a 45 d9 e7 9c d4 5c 94 18 d7 |.n.h..:E....\...|
02e0  99 33 59 f3 30 a0 2b d8 b9 cb c6 f3 2d 6b 2f 8f |.3Y.0.+.....-k/.|
02f0  c9 22 3a 46 9d 73 c3 f9 60 69 72 0a 1c 16 5d 7a |.":F.s..`ir...]z|
0300  ee 56 af 0e bc e4 08 04 51 71 e9 a3 58 d2 85 1b |.V......Qq..X...|
0310  a0 66 84 33 2c 2c 97 8f 83 c5 a1 28 f9 2e 05 0b |.f.3,,.....(....|
0320  fc e9 e3 1e 64 8e 93 95 38 57 1e de 59 84 a9 3b |....d...8W..Y..;|
0330  a1 e2 c2 1e 83 0b 4a a3 11 11 46 5c 22 b0 10 62 |......J...F\"..b|
0340  d7 2d 17 2b 13 e4 20 c6 be ee f3 99 47 cc 7a d6 |.-.+.. .....G.z.|
0350  03 0b e1 2a 45 27 11 d6 b4 fb c4 62 be cc 68 b2 |...*E'.....b..h.|
0360  2a 96 69 b3 36 72 aa 87 18 57 d2 f5 95 d5 ea 50 |*.i.6r...W.....P|
0370  55 34 33 2e 02 ab bf 21 02 20 71 ad 9a 17 7a c9 |U43....!. q...z.|
0380  bf 01 20 9b 9a 6c a7 eb 52 88 4b ab 92 5f b1 d0 |.. ..l..R.K.._..|
0390  6b 5f f9 52 b0 07 2b 0f 16 5d 09 ab ec 61 dd 6b |k_.R..+..]...a.k|
03a0  3f a7 23 d7 d2 7e ef a9 8b b2 06 20 2e 9e 19 17 |?.#..~..... ....|
03b0  2d 35 a9 0c 2d e6 c0 f8 66 8e 98 d3 57 ac 50 5c |-5..-...f...W.P\|
03c0  dc 6c 44 f9 64 11 4a af e7 60 55 5c 48 89 d7 95 |.lD.d.J..`U\H...|
03d0  d5 f9 03 a2 6b b9 c3 4a b6 08 a1 b5 ec 45 d4 1c |....k..J.....E..|
03e0  b3 40 75 09 d6 02 e4 0f 44 0d 06 8b 44 5f e4 62 |.@u.....D...D_.b|
03f0  1d 21 0d 2b 43 ac 41 82 b8 a3 4a 78 da c5 aa b5 |.!.+C.A...Jx....|
0400  da b0 21 34 54 af d5 cb a2 83 75 b3 be da 23 39 |..!4T.....u...#9|
0410  27 14 14 7a 73 ad b3 4b 58 0d 24 fe 21 16 29 c3 |'..zs..KX.$.!.).|
0420  47 44 f4 19 fc 03 a1 07 96 aa 2e 56 c0 0a fc ff |GD.........V....|
0430  0a fc 01 fe 2a 33 73                            |....*3s         |
0430                       25 b3 fe 50                |       %..P     | CRC: 25B3FE50 (OK)
```
```
0430                                   00 00 00 1b    |           .... | Chunk length: 27
0430                                               62 |               b| Chunk type: blUe
0440  6c 55 65                                        |lUe             | 
0440           59 6f 20 6c 69 73 74 65 6e 20 75 70 20 |   Yo listen up | Data: "Yo listen up here's a story"
0450  68 65 72 65 27 73 20 61 20 73 74 6f 72 79       |here's a story  |
0450                                            e8 fa |              ..| CRC: E8FA34F7 (BAD: 5B7AC22D)
0460  34 f7                                           |4.              |
```
```
0460        00 00 00 2d                               |  ...-          | Chunk length: 56
0460                    62 6c 55 65                   |      blUe      | Chunk type: blUe
0460                                41 62 6f 75 74 20 |          About | Data: "About a little guy that lives in a blue world"
0470  61 20 6c 69 74 74 6c 65 20 67 75 79 20 74 68 61 |a little guy tha|
0480  74 20 6c 69 76 65 73 20 69 6e 20 61 20 62 6c 75 |t lives in a blu|
0490  65 20 77 6f 72 6c 64                            |e world         |
0490                       b0 2a c1 7e                |       .*.~     | CRC: B02AC17E (BAD: 984C80A2)
```
```
0490                                   00 00 00 3d    |           ...= | Chunk length: 61
0490                                               62 |               b| Chunk type: blUe
04a0  6c 55 65                                        |lUe             |
04a0           41 6e 64 20 61 6c 6c 20 64 61 79 20 61 |   And all day a| Data: "And all day and all night and everything he sees Is just blue"
04b0  6e 64 20 61 6c 6c 20 6e 69 67 68 74 20 61 6e 64 |nd all night and|
04c0  20 65 76 65 72 79 74 68 69 6e 67 20 68 65 20 73 | everything he s|
04d0  65 65 73 20 49 73 20 6a 75 73 74 20 62 6c 75 65 |ees Is just blue|
04e0  69 e7 08 31                                     |i..1            | CRC: 69E70831 (BAD: E723D2B6)
```
```
04e0              00 00 00 1b                         |    ....        | Chunk length: 27
04e0                          62 6c 55 65             |        blUe    | Chunk type: blUe
04e0                                      4c 69 6b 65 |            Like| Data: "Like him inside and outside"
04f0  20 68 69 6d 20 69 6e 73 69 64 65 20 61 6e 64 20 | him inside and |
0500  6f 75 74 73 69 64 65                            |outside         |
0500                       a7 28 6f ad                |       .(o.     | CRC: A7286FAD (BAD: 6E406947)
```
```
0500                                   00 00 00 28    |           ...( | Chunk length: 40
0500                                               62 |               b| Chunk type: blUe
0510  6c 55 65                                        |lUe             |
0510           42 6c 75 65 20 68 69 73 20 68 6f 75 73 |   Blue his hous| Data: "Blue his house with a blue little window"
0520  65 20 77 69 74 68 20 61 20 62 6c 75 65 20 6c 69 |e with a blue li|
0530  74 74 6c 65 20 77 69 6e 64 6f 77                |ttle window     |
0530                                   04 9b db c2    |           .... | CRC: 049BDBC2 (BAD: AC4573B2)
```
```
0530                                               00 |               .| Chunk length: 19
0540  00 00 13                                        |...             |
0540           62 6c 55 65                            |   blUe         | Chunk type: blUe
0540                       41 6e 64 20 61 20 62 6c 75 |       And a blu| Data: "And a blue Corvette"
0550  65 20 43 6f 72 76 65 74 74 65                   |e Corvette      |
0550                                97 53 ab 8e       |          .S..  | CRC: 9753AB8E (BAD: F65F1678)
```
```
0550                                            00 00 |              ..| Chunk length: 30
0560  00 1e                                           |..              |
0560        62 6c 55 65                               |  blUe          | Chunk type: blUe
0560                    41 6e 64 20 65 76 65 72 79 74 |      And everyt| Data: "And everything is blue for him"
0570  68 69 6e 67 20 69 73 20 62 6c 75 65 20 66 6f 72 |hing is blue for|
0580  20 68 69 6d                                     | him            |
0580              4d 52 dd ca                         |    MR..        | CRC: 4D52DDCA (BAD: 70FD2FB1)
```
```
0580                          00 00 00 20             |        ...     | Chunk length: 32
0580                                      62 6c 55 65 |            blUe| Chunk type: blUe
0590  41 6e 64 20 68 69 6d 73 65 6c 66 20 61 6e 64 20 |And himself and | Data: "And himself and everybody around"
05a0  65 76 65 72 79 62 6f 64 79 20 61 72 6f 75 6e 64 |everybody around|
05b0  4d 8e 11 6f                                     |M..o            | CRC: 4D8E116F (BAD: F5F93C49)
```
```
05b0              00 00 00 00                         |    ....        | Chunk length: 0
05b0                          49 45 4e 44             |        IEND    | Chunk type: IEND
05b0                                      ae 42 60 82 |            .B`.| CRC: AE426082 (OK)
```

# Summary

*   A 300x200, 2-bit image with 3-element palette
*   Eight additional `blUe` chunks, with incorrect CRCs. Note that the capitalization of
    the chunk name determines the flags:
    *   `XXXX`: *Critical* (0), *Public* (0), *Reserved* (0), *Unsafe to copy* (0)
    *   `blUe`: *Ancillary* (1), *Private* (1), *Reserved* (0), *Safe to copy* (1)
*   Decompressed data is 22800 bytes while it should be 15200.
    *   Or more like 15000 probably (`300 * 200 / 4`). Not sure why the tool says 15200.

# Decompressing the data

Deflated data in Hex is:

```
78 01 ed 96 4b 8e dc 30 0c 44 09 af 02 9d c4 d0 29 8d 2c e7 14 44 af 0c 9d 32 af 28 77 bb c7 e3
01 82 01 b2 09 4a ed 38 96 44 3e 51 45 7d 26 c2 c5 0a 58 01 2b 60 05 ac 80 15 b0 02 56 c0 0a 58
01 2b 60 05 ac 80 15 b0 02 56 c0 0a 58 01 2b 60 05 ac 80 15 b0 02 56 c0 0a 58 01 2b 60 05 ac 80
15 b0 02 56 c0 0a 58 01 2b 60 05 ac 80 15 b0 02 56 c0 0a 58 01 2b 60 05 ac 80 15 b0 02 56 c0 0a
58 01 2b 60 05 ac 80 15 b0 02 56 c0 0a 58 01 2b 60 05 ac 80 15 b0 02 56 c0 0a 58 01 2b 60 05 ac
80 15 b0 02 56 e0 ab 02 6d 44 e4 92 b1 2f 23 c6 88 35 f8 4a cc a8 46 cf f9 bd c7 ae 96 3d c6 a6
a7 a9 16 bd de 51 c6 aa 53 3a 9d a9 5f 1b db 18 db 8b 45 35 c6 93 55 0e 8c 3a 59 93 82 b1 fc 97
7a eb 0b 56 db 78 c3 ea bf b7 bd e5 8b 45 95 d6 d1 92 de bd 6c b0 c4 91 67 b2 66 63 54 17 36 2a
c7 2c 96 83 f2 62 f1 71 b2 ba 2c d7 e5 60 d5 8c 9f 11 35 75 51 18 63 85 d5 53 76 7b 71 d7 21 fa
32 54 ed 23 89 ab 31 53 2a 59 ed 15 17 2c e6 81 37 66 51 c3 dc b1 da d6 a1 2c e5 5f ac c7 af 14
31 af 2c d1 96 8d 61 94 ac 2a 4a 9f 46 c8 e8 cb f6 50 1e 37 44 51 a4 5b 52 a5 fd b1 67 6f 37 ac
15 57 06 de 00 1c ac 48 0a 1e b0 9a 92 c8 a3 c9 c2 0a 71 69 87 45 f5 88 2b 73 6a 8f 3f 66 cc 4e
f3 cb 2f ac d6 94 32 e5 71 91 33 81 2b 83 fc 52 55 f4 1a a8 f6 38 59 8d f4 ad 9a 9f e2 63 06 94
39 2c 3e b0 e4 13 27 8b ea c9 ea c5 22 27 4f ed b1 a7 57 2c 96 ee 95 45 fa e2 33 4b 24 fd 34 06
93 f9 9c c7 f6 21 0a ac 73 79 8d 0f 99 62 c7 fe 58 df e2 c2 97 ea c9 c2 83 28 58 04 58 66 30 2c
f6 44 86 19 ef a3 20 39 cf 64 91 2f b8 20 d4 b8 29 7d 93 35 db f9 a6 fd 9d 45 50 32 7b a2 d4 dd
95 be 64 9c f9 21 d6 d0 c2 e1 7d b0 50 bd 62 6c b4 d4 d3 c9 6b 65 03 33 88 67 5c da b1 c5 3a ce
09 2d 54 0e 09 d6 74 4c 16 0e af 73 82 48 78 c4 62 ab e2 55 db e3 09 fb 9b ff a5 d0 b5 bc da 6e
fa ae b6 ef f5 97 df 5b e3 5d db 5b f7 b7 9f 77 7e cc f5 47 e5 96 f5 23 92 9d fe 9d 02 f3 b2 63
97 b0 45 58 f1 9c 16 3a c5 b5 85 f7 39 28 55 16 ba 0e 96 1e bc db 38 bb ae 51 69 df b1 f3 8b c5
f7 d0 45 99 6a 01 aa 1e 9c d9 9b b5 3d 39 48 c5 dd b4 83 6e cb 68 1b ed 3a 45 d9 e7 9c d4 5c 94
18 d7 99 33 59 f3 30 a0 2b d8 b9 cb c6 f3 2d 6b 2f 8f c9 22 3a 46 9d 73 c3 f9 60 69 72 0a 1c 16
5d 7a ee 56 af 0e bc e4 08 04 51 71 e9 a3 58 d2 85 1b a0 66 84 33 2c 2c 97 8f 83 c5 a1 28 f9 2e
05 0b fc e9 e3 1e 64 8e 93 95 38 57 1e de 59 84 a9 3b a1 e2 c2 1e 83 0b 4a a3 11 11 46 5c 22 b0
10 62 d7 2d 17 2b 13 e4 20 c6 be ee f3 99 47 cc 7a d6 03 0b e1 2a 45 27 11 d6 b4 fb c4 62 be cc
68 b2 2a 96 69 b3 36 72 aa 87 18 57 d2 f5 95 d5 ea 50 55 34 33 2e 02 ab bf 21 02 20 71 ad 9a 17
7a c9 bf 01 20 9b 9a 6c a7 eb 52 88 4b ab 92 5f b1 d0 6b 5f f9 52 b0 07 2b 0f 16 5d 09 ab ec 61
dd 6b 3f a7 23 d7 d2 7e ef a9 8b b2 06 20 2e 9e 19 17 2d 35 a9 0c 2d e6 c0 f8 66 8e 98 d3 57 ac
50 5c dc 6c 44 f9 64 11 4a af e7 60 55 5c 48 89 d7 95 d5 f9 03 a2 6b b9 c3 4a b6 08 a1 b5 ec 45
d4 1c b3 40 75 09 d6 02 e4 0f 44 0d 06 8b 44 5f e4 62 1d 21 0d 2b 43 ac 41 82 b8 a3 4a 78 da c5
aa b5 da b0 21 34 54 af d5 cb a2 83 75 b3 be da 23 39 27 14 14 7a 73 ad b3 4b 58 0d 24 fe 21 16
29 c3 47 44 f4 19 fc 03 a1 07 96 aa 2e 56 c0 0a fc ff 0a fc 01 fe 2a 33 73
```

CyberChef can [deal with that](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')Zlib_Inflate(0,0,'Adaptive',false,false)To_Hex('Space',0)&input=NzggMDEgZWQgOTYgNGIgOGUgZGMgMzAgMGMgNDQgMDkgYWYgMDIgOWQgYzQgZDAgMjkgOGQgMmMgZTcgMTQgNDQgYWYgMGMgOWQgMzIgYWYgMjggNzcgYmIgYzcgZTMKMDEgODIgMDEgYjIgMDkgNGEgZWQgMzggOTYgNDQgM2UgNTEgNDUgN2QgMjYgYzIgYzUgMGEgNTggMDEgMmIgNjAgMDUgYWMgODAgMTUgYjAgMDIgNTYgYzAgMGEgNTgKMDEgMmIgNjAgMDUgYWMgODAgMTUgYjAgMDIgNTYgYzAgMGEgNTggMDEgMmIgNjAgMDUgYWMgODAgMTUgYjAgMDIgNTYgYzAgMGEgNTggMDEgMmIgNjAgMDUgYWMgODAKMTUgYjAgMDIgNTYgYzAgMGEgNTggMDEgMmIgNjAgMDUgYWMgODAgMTUgYjAgMDIgNTYgYzAgMGEgNTggMDEgMmIgNjAgMDUgYWMgODAgMTUgYjAgMDIgNTYgYzAgMGEKNTggMDEgMmIgNjAgMDUgYWMgODAgMTUgYjAgMDIgNTYgYzAgMGEgNTggMDEgMmIgNjAgMDUgYWMgODAgMTUgYjAgMDIgNTYgYzAgMGEgNTggMDEgMmIgNjAgMDUgYWMKODAgMTUgYjAgMDIgNTYgZTAgYWIgMDIgNmQgNDQgZTQgOTIgYjEgMmYgMjMgYzYgODggMzUgZjggNGEgY2MgYTggNDYgY2YgZjkgYmQgYzcgYWUgOTYgM2QgYzYgYTYKYTcgYTkgMTYgYmQgZGUgNTEgYzYgYWEgNTMgM2EgOWQgYTkgNWYgMWIgZGIgMTggZGIgOGIgNDUgMzUgYzYgOTMgNTUgMGUgOGMgM2EgNTkgOTMgODIgYjEgZmMgOTcKN2EgZWIgMGIgNTYgZGIgNzggYzMgZWEgYmYgYjcgYmQgZTUgOGIgNDUgOTUgZDYgZDEgOTIgZGUgYmQgNmMgYjAgYzQgOTEgNjcgYjIgNjYgNjMgNTQgMTcgMzYgMmEKYzcgMmMgOTYgODMgZjIgNjIgZjEgNzEgYjIgYmEgMmMgZDcgZTUgNjAgZDUgOGMgOWYgMTEgMzUgNzUgNTEgMTggNjMgODUgZDUgNTMgNzYgN2IgNzEgZDcgMjEgZmEKMzIgNTQgZWQgMjMgODkgYWIgMzEgNTMgMmEgNTkgZWQgMTUgMTcgMmMgZTYgODEgMzcgNjYgNTEgYzMgZGMgYjEgZGEgZDYgYTEgMmMgZTUgNWYgYWMgYzcgYWYgMTQKMzEgYWYgMmMgZDEgOTYgOGQgNjEgOTQgYWMgMmEgNGEgOWYgNDYgYzggZTggY2IgZjYgNTAgMWUgMzcgNDQgNTEgYTQgNWIgNTIgYTUgZmQgYjEgNjcgNmYgMzcgYWMKMTUgNTcgMDYgZGUgMDAgMWMgYWMgNDggMGEgMWUgYjAgOWEgOTIgYzggYTMgYzkgYzIgMGEgNzEgNjkgODcgNDUgZjUgODggMmIgNzMgNmEgOGYgM2YgNjYgY2MgNGUKZjMgY2IgMmYgYWMgZDYgOTQgMzIgZTUgNzEgOTEgMzMgODEgMmIgODMgZmMgNTIgNTUgZjQgMWEgYTggZjYgMzggNTkgOGQgZjQgYWQgOWEgOWYgZTIgNjMgMDYgOTQKMzkgMmMgM2UgYjAgZTQgMTMgMjcgOGIgZWEgYzkgZWEgYzUgMjIgMjcgNGYgZWQgYjEgYTcgNTcgMmMgOTYgZWUgOTUgNDUgZmEgZTIgMzMgNGIgMjQgZmQgMzQgMDYKOTMgZjkgOWMgYzcgZjYgMjEgMGEgYWMgNzMgNzkgOGQgMGYgOTkgNjIgYzcgZmUgNTggZGYgZTIgYzIgOTcgZWEgYzkgYzIgODMgMjggNTggMDQgNTggNjYgMzAgMmMKZjYgNDQgODYgMTkgZWYgYTMgMjAgMzkgY2YgNjQgOTEgMmYgYjggMjAgZDQgYjggMjkgN2QgOTMgMzUgZGIgZjkgYTYgZmQgOWQgNDUgNTAgMzIgN2IgYTIgZDQgZGQKOTUgYmUgNjQgOWMgZjkgMjEgZDYgZDAgYzIgZTEgN2QgYjAgNTAgYmQgNjIgNmMgYjQgZDQgZDMgYzkgNmIgNjUgMDMgMzMgODggNjcgNWMgZGEgYjEgYzUgM2EgY2UKMDkgMmQgNTQgMGUgMDkgZDYgNzQgNGMgMTYgMGUgYWYgNzMgODIgNDggNzggYzQgNjIgYWIgZTIgNTUgZGIgZTMgMDkgZmIgOWIgZmYgYTUgZDAgYjUgYmMgZGEgNmUKZmEgYWUgYjYgZWYgZjUgOTcgZGYgNWIgZTMgNWQgZGIgNWIgZjcgYjcgOWYgNzcgN2UgY2MgZjUgNDcgZTUgOTYgZjUgMjMgOTIgOWQgZmUgOWQgMDIgZjMgYjIgNjMKOTcgYjAgNDUgNTggZjEgOWMgMTYgM2EgYzUgYjUgODUgZjcgMzkgMjggNTUgMTYgYmEgMGUgOTYgMWUgYmMgZGIgMzggYmIgYWUgNTEgNjkgZGYgYjEgZjMgOGIgYzUKZjcgZDAgNDUgOTkgNmEgMDEgYWEgMWUgOWMgZDkgOWIgYjUgM2QgMzkgNDggYzUgZGQgYjQgODMgNmUgY2IgNjggMWIgZWQgM2EgNDUgZDkgZTcgOWMgZDQgNWMgOTQKMTggZDcgOTkgMzMgNTkgZjMgMzAgYTAgMmIgZDggYjkgY2IgYzYgZjMgMmQgNmIgMmYgOGYgYzkgMjIgM2EgNDYgOWQgNzMgYzMgZjkgNjAgNjkgNzIgMGEgMWMgMTYKNWQgN2EgZWUgNTYgYWYgMGUgYmMgZTQgMDggMDQgNTEgNzEgZTkgYTMgNTggZDIgODUgMWIgYTAgNjYgODQgMzMgMmMgMmMgOTcgOGYgODMgYzUgYTEgMjggZjkgMmUKMDUgMGIgZmMgZTkgZTMgMWUgNjQgOGUgOTMgOTUgMzggNTcgMWUgZGUgNTkgODQgYTkgM2IgYTEgZTIgYzIgMWUgODMgMGIgNGEgYTMgMTEgMTEgNDYgNWMgMjIgYjAKMTAgNjIgZDcgMmQgMTcgMmIgMTMgZTQgMjAgYzYgYmUgZWUgZjMgOTkgNDcgY2MgN2EgZDYgMDMgMGIgZTEgMmEgNDUgMjcgMTEgZDYgYjQgZmIgYzQgNjIgYmUgY2MKNjggYjIgMmEgOTYgNjkgYjMgMzYgNzIgYWEgODcgMTggNTcgZDIgZjUgOTUgZDUgZWEgNTAgNTUgMzQgMzMgMmUgMDIgYWIgYmYgMjEgMDIgMjAgNzEgYWQgOWEgMTcKN2EgYzkgYmYgMDEgMjAgOWIgOWEgNmMgYTcgZWIgNTIgODggNGIgYWIgOTIgNWYgYjEgZDAgNmIgNWYgZjkgNTIgYjAgMDcgMmIgMGYgMTYgNWQgMDkgYWIgZWMgNjEKZGQgNmIgM2YgYTcgMjMgZDcgZDIgN2UgZWYgYTkgOGIgYjIgMDYgMjAgMmUgOWUgMTkgMTcgMmQgMzUgYTkgMGMgMmQgZTYgYzAgZjggNjYgOGUgOTggZDMgNTcgYWMKNTAgNWMgZGMgNmMgNDQgZjkgNjQgMTEgNGEgYWYgZTcgNjAgNTUgNWMgNDggODkgZDcgOTUgZDUgZjkgMDMgYTIgNmIgYjkgYzMgNGEgYjYgMDggYTEgYjUgZWMgNDUKZDQgMWMgYjMgNDAgNzUgMDkgZDYgMDIgZTQgMGYgNDQgMGQgMDYgOGIgNDQgNWYgZTQgNjIgMWQgMjEgMGQgMmIgNDMgYWMgNDEgODIgYjggYTMgNGEgNzggZGEgYzUKYWEgYjUgZGEgYjAgMjEgMzQgNTQgYWYgZDUgY2IgYTIgODMgNzUgYjMgYmUgZGEgMjMgMzkgMjcgMTQgMTQgN2EgNzMgYWQgYjMgNGIgNTggMGQgMjQgZmUgMjEgMTYKMjkgYzMgNDcgNDQgZjQgMTkgZmMgMDMgYTEgMDcgOTYgYWEgMmUgNTYgYzAgMGEgZmMgZmYgMGEgZmMgMDEgZmUgMmEgMzMgNzM). The result seem to be roughly:

*   15000 zeros, as expected for 300 x 200 x (2 bits).
*   7800 bytes that seem to have some data. 7800 = 26 * 300, so, maybe 26 additional lines?

# Decoding the second image

... Almost &#128578; Taking these 7800 bytes and playing around with CyberChef's "Generate Image",
[we get an image](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')Zlib_Inflate(0,0,'Adaptive',false,false)Drop_bytes(0,15048,false)Generate_Image('Bits',1,608)&input=NzggMDEgZWQgOTYgNGIgOGUgZGMgMzAgMGMgNDQgMDkgYWYgMDIgOWQgYzQgZDAgMjkgOGQgMmMgZTcgMTQgNDQgYWYgMGMgOWQgMzIgYWYgMjggNzcgYmIgYzcgZTMKMDEgODIgMDEgYjIgMDkgNGEgZWQgMzggOTYgNDQgM2UgNTEgNDUgN2QgMjYgYzIgYzUgMGEgNTggMDEgMmIgNjAgMDUgYWMgODAgMTUgYjAgMDIgNTYgYzAgMGEgNTgKMDEgMmIgNjAgMDUgYWMgODAgMTUgYjAgMDIgNTYgYzAgMGEgNTggMDEgMmIgNjAgMDUgYWMgODAgMTUgYjAgMDIgNTYgYzAgMGEgNTggMDEgMmIgNjAgMDUgYWMgODAKMTUgYjAgMDIgNTYgYzAgMGEgNTggMDEgMmIgNjAgMDUgYWMgODAgMTUgYjAgMDIgNTYgYzAgMGEgNTggMDEgMmIgNjAgMDUgYWMgODAgMTUgYjAgMDIgNTYgYzAgMGEKNTggMDEgMmIgNjAgMDUgYWMgODAgMTUgYjAgMDIgNTYgYzAgMGEgNTggMDEgMmIgNjAgMDUgYWMgODAgMTUgYjAgMDIgNTYgYzAgMGEgNTggMDEgMmIgNjAgMDUgYWMKODAgMTUgYjAgMDIgNTYgZTAgYWIgMDIgNmQgNDQgZTQgOTIgYjEgMmYgMjMgYzYgODggMzUgZjggNGEgY2MgYTggNDYgY2YgZjkgYmQgYzcgYWUgOTYgM2QgYzYgYTYKYTcgYTkgMTYgYmQgZGUgNTEgYzYgYWEgNTMgM2EgOWQgYTkgNWYgMWIgZGIgMTggZGIgOGIgNDUgMzUgYzYgOTMgNTUgMGUgOGMgM2EgNTkgOTMgODIgYjEgZmMgOTcKN2EgZWIgMGIgNTYgZGIgNzggYzMgZWEgYmYgYjcgYmQgZTUgOGIgNDUgOTUgZDYgZDEgOTIgZGUgYmQgNmMgYjAgYzQgOTEgNjcgYjIgNjYgNjMgNTQgMTcgMzYgMmEKYzcgMmMgOTYgODMgZjIgNjIgZjEgNzEgYjIgYmEgMmMgZDcgZTUgNjAgZDUgOGMgOWYgMTEgMzUgNzUgNTEgMTggNjMgODUgZDUgNTMgNzYgN2IgNzEgZDcgMjEgZmEKMzIgNTQgZWQgMjMgODkgYWIgMzEgNTMgMmEgNTkgZWQgMTUgMTcgMmMgZTYgODEgMzcgNjYgNTEgYzMgZGMgYjEgZGEgZDYgYTEgMmMgZTUgNWYgYWMgYzcgYWYgMTQKMzEgYWYgMmMgZDEgOTYgOGQgNjEgOTQgYWMgMmEgNGEgOWYgNDYgYzggZTggY2IgZjYgNTAgMWUgMzcgNDQgNTEgYTQgNWIgNTIgYTUgZmQgYjEgNjcgNmYgMzcgYWMKMTUgNTcgMDYgZGUgMDAgMWMgYWMgNDggMGEgMWUgYjAgOWEgOTIgYzggYTMgYzkgYzIgMGEgNzEgNjkgODcgNDUgZjUgODggMmIgNzMgNmEgOGYgM2YgNjYgY2MgNGUKZjMgY2IgMmYgYWMgZDYgOTQgMzIgZTUgNzEgOTEgMzMgODEgMmIgODMgZmMgNTIgNTUgZjQgMWEgYTggZjYgMzggNTkgOGQgZjQgYWQgOWEgOWYgZTIgNjMgMDYgOTQKMzkgMmMgM2UgYjAgZTQgMTMgMjcgOGIgZWEgYzkgZWEgYzUgMjIgMjcgNGYgZWQgYjEgYTcgNTcgMmMgOTYgZWUgOTUgNDUgZmEgZTIgMzMgNGIgMjQgZmQgMzQgMDYKOTMgZjkgOWMgYzcgZjYgMjEgMGEgYWMgNzMgNzkgOGQgMGYgOTkgNjIgYzcgZmUgNTggZGYgZTIgYzIgOTcgZWEgYzkgYzIgODMgMjggNTggMDQgNTggNjYgMzAgMmMKZjYgNDQgODYgMTkgZWYgYTMgMjAgMzkgY2YgNjQgOTEgMmYgYjggMjAgZDQgYjggMjkgN2QgOTMgMzUgZGIgZjkgYTYgZmQgOWQgNDUgNTAgMzIgN2IgYTIgZDQgZGQKOTUgYmUgNjQgOWMgZjkgMjEgZDYgZDAgYzIgZTEgN2QgYjAgNTAgYmQgNjIgNmMgYjQgZDQgZDMgYzkgNmIgNjUgMDMgMzMgODggNjcgNWMgZGEgYjEgYzUgM2EgY2UKMDkgMmQgNTQgMGUgMDkgZDYgNzQgNGMgMTYgMGUgYWYgNzMgODIgNDggNzggYzQgNjIgYWIgZTIgNTUgZGIgZTMgMDkgZmIgOWIgZmYgYTUgZDAgYjUgYmMgZGEgNmUKZmEgYWUgYjYgZWYgZjUgOTcgZGYgNWIgZTMgNWQgZGIgNWIgZjcgYjcgOWYgNzcgN2UgY2MgZjUgNDcgZTUgOTYgZjUgMjMgOTIgOWQgZmUgOWQgMDIgZjMgYjIgNjMKOTcgYjAgNDUgNTggZjEgOWMgMTYgM2EgYzUgYjUgODUgZjcgMzkgMjggNTUgMTYgYmEgMGUgOTYgMWUgYmMgZGIgMzggYmIgYWUgNTEgNjkgZGYgYjEgZjMgOGIgYzUKZjcgZDAgNDUgOTkgNmEgMDEgYWEgMWUgOWMgZDkgOWIgYjUgM2QgMzkgNDggYzUgZGQgYjQgODMgNmUgY2IgNjggMWIgZWQgM2EgNDUgZDkgZTcgOWMgZDQgNWMgOTQKMTggZDcgOTkgMzMgNTkgZjMgMzAgYTAgMmIgZDggYjkgY2IgYzYgZjMgMmQgNmIgMmYgOGYgYzkgMjIgM2EgNDYgOWQgNzMgYzMgZjkgNjAgNjkgNzIgMGEgMWMgMTYKNWQgN2EgZWUgNTYgYWYgMGUgYmMgZTQgMDggMDQgNTEgNzEgZTkgYTMgNTggZDIgODUgMWIgYTAgNjYgODQgMzMgMmMgMmMgOTcgOGYgODMgYzUgYTEgMjggZjkgMmUKMDUgMGIgZmMgZTkgZTMgMWUgNjQgOGUgOTMgOTUgMzggNTcgMWUgZGUgNTkgODQgYTkgM2IgYTEgZTIgYzIgMWUgODMgMGIgNGEgYTMgMTEgMTEgNDYgNWMgMjIgYjAKMTAgNjIgZDcgMmQgMTcgMmIgMTMgZTQgMjAgYzYgYmUgZWUgZjMgOTkgNDcgY2MgN2EgZDYgMDMgMGIgZTEgMmEgNDUgMjcgMTEgZDYgYjQgZmIgYzQgNjIgYmUgY2MKNjggYjIgMmEgOTYgNjkgYjMgMzYgNzIgYWEgODcgMTggNTcgZDIgZjUgOTUgZDUgZWEgNTAgNTUgMzQgMzMgMmUgMDIgYWIgYmYgMjEgMDIgMjAgNzEgYWQgOWEgMTcKN2EgYzkgYmYgMDEgMjAgOWIgOWEgNmMgYTcgZWIgNTIgODggNGIgYWIgOTIgNWYgYjEgZDAgNmIgNWYgZjkgNTIgYjAgMDcgMmIgMGYgMTYgNWQgMDkgYWIgZWMgNjEKZGQgNmIgM2YgYTcgMjMgZDcgZDIgN2UgZWYgYTkgOGIgYjIgMDYgMjAgMmUgOWUgMTkgMTcgMmQgMzUgYTkgMGMgMmQgZTYgYzAgZjggNjYgOGUgOTggZDMgNTcgYWMKNTAgNWMgZGMgNmMgNDQgZjkgNjQgMTEgNGEgYWYgZTcgNjAgNTUgNWMgNDggODkgZDcgOTUgZDUgZjkgMDMgYTIgNmIgYjkgYzMgNGEgYjYgMDggYTEgYjUgZWMgNDUKZDQgMWMgYjMgNDAgNzUgMDkgZDYgMDIgZTQgMGYgNDQgMGQgMDYgOGIgNDQgNWYgZTQgNjIgMWQgMjEgMGQgMmIgNDMgYWMgNDEgODIgYjggYTMgNGEgNzggZGEgYzUKYWEgYjUgZGEgYjAgMjEgMzQgNTQgYWYgZDUgY2IgYTIgODMgNzUgYjMgYmUgZGEgMjMgMzkgMjcgMTQgMTQgN2EgNzMgYWQgYjMgNGIgNTggMGQgMjQgZmUgMjEgMTYKMjkgYzMgNDcgNDQgZjQgMTkgZmMgMDMgYTEgMDcgOTYgYWEgMmUgNTYgYzAgMGEgZmMgZmYgMGEgZmMgMDEgZmUgMmEgMzMgNzM)
of a Base64-encoded string:

![](encoded.png "")

More specifically:

*   I used `Mode: Bits` (unfortunately CC doesn't have N-bits-per-pixel mode)
*   I skipped the initial 15000 bytes of zeros using `Drop bytes`
*   I played around with `Pixels per row` until something started to align at `608` (which is really `304` at 2bpp)
*   Finally, for better alignment, added extra `48` to `Drop bytes` (that makes it exactly 608x102 2-bit image at
    the end of binary stream.)

# Decoding the flag    

So, the Base64 string is:
```
wOiV6BhUc6fMqK+0ll1y2c/-
u9xMJONGaYtzCF84SSVs=
```

That decodes to:
```
c0 e8 95 e8 18 54 73 a7 cc a8 af b4 96 5d 72 d9 cf ee f7 13 09 38 d1 9a 62 dc c2 17 ce 12 49 5b
```

Remember that we also have those 32 bytes of bad CRCs

```
E8 FA 34 F7 B0 2A C1 7E 69 E7 08 31 A7 28 6F AD 04 9B DB C2 97 53 AB 8E 4D 52 DD CA 4D 8E 11 6F
```

A straight XOR does not work right away. But if we additionally take the 32 bytes of ***expected*** CRCs:

```
5B 7A C2 2D 98 4C 80 A2 E7 23 D2 B6 6E 40 69 47 AC 45 73 B2 F6 5F 16 78 70 FD 2F B1 F5 F9 3C 49
```

... tadam, [we get the flag](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'E8%20FA%2034%20F7%20B0%202A%20C1%207E%2069%20E7%2008%2031%20A7%2028%206F%20AD%2004%209B%20DB%20C2%2097%2053%20AB%208E%204D%2052%20DD%20CA%204D%208E%2011%206F'%7D,'Standard',false)XOR(%7B'option':'Hex','string':'5B%207A%20C2%202D%2098%204C%2080%20A2%20E7%2023%20D2%20B6%206E%2040%2069%2047%20AC%2045%2073%20B2%20F6%205F%2016%2078%2070%20FD%202F%20B1%20F5%20F9%203C%2049'%7D,'Standard',false)&input=YzAgZTggOTUgZTggMTggNTQgNzMgYTcgY2MgYTggYWYgYjQgOTYgNWQgNzIgZDkgY2YgZWUgZjcgMTMgMDkgMzggZDEgOWEgNjIgZGMgYzIgMTcgY2UgMTIgNDkgNWI&oeol=NEL)!

---

## `shc2022{Blu3_5t3g0_ch4ll_s0lved}`




<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
