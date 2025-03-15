# optimized-ntfs

[library.m0unt41n.ch/challenges/optimized-ntfs](https://library.m0unt41n.ch/challenges/optimized-ntfs) ![](../../resources/forensics.svg) ![](../../resources/medium.svg) 

# TL;DR

We are given a raw dump of a Windows image, we need to extract a deleted file from there.
We use the fact that deleted files are kept in MFT and, additionally, for small files, their
contents is stored in MFT too. From there, it's just hex editor's search function.

# Solution

First of all, the FS image is not simply mountable under Linux. As I found later, it's
actually not a FS dump, but rather memory dump!

Google-searching for `ntfs forensics deleted file` suggests that deleted files are kept in MFT.
So, should be greppable. Let's just look at suspicious strings:

```
$ strings image.raw  | grep Desktop
(...)
C:\Documents and Settings\xnull\Desktop\supersecretpassword.txt
C:\Documents and Settings\xnull\Desktop\AAAAA.txt
```

Further Google search ([example](https://superuser.com/questions/1185461/maximum-size-of-file-that-can-be-stored-entirely-in-ntfs-master-file-table-mft)), suggests that `FILE0` records in MFT will contain contents of small files.

Let's hex search for `supersecretpassword.txt`. Note that this needs to also search for two-byte characters, so:

```
73 00 75 00 70 00 65 00 72 00 73 00 65 00 63 00
72 00 65 00 74 00 70 00 61 00 73 00 73 00 77 00
6F 00 72 00 64 00 2E 00 74 00 78 00 74 00
```

Eventually, at `0x7589dd6a` we see:

```
7589DD60 20 00 00 00 │ 00 00 00 00 │ 17 01 73 00 │ 75 00 70 00   .........s.u.p.
7589DD70 65 00 72 00 │ 73 00 65 00 │ 63 00 72 00 │ 65 00 74 00  e.r.s.e.c.r.e.t.
7589DD80 70 00 61 00 │ 73 00 73 00 │ 77 00 6F 00 │ 72 00 64 00  p.a.s.s.w.o.r.d.
7589DD90 2E 00 74 00 │ 78 00 74 00 │ 40 00 00 00 │ 28 00 00 00  ..t.x.t.@...(...
7589DDA0 00 00 00 00 │ 00 00 06 00 │ 10 00 00 00 │ 18 00 00 00  ................
7589DDB0 1E 2C 28 62 │ 2F C5 EE 11 │ 9A 25 0C 7A │ 15 D4 5C 96  .,(b/....%.z..\.
7589DDC0 80 00 00 00 │ 50 00 00 00 │ 00 00 18 00 │ 00 00 01 00  ....P...........
7589DDD0 32 00 00 00 │ 18 00 00 00 │ 63 32 0D 0A │ 68 6A 0D 0A  2.......c2..hj..
7589DDE0 4D 6A 0D 0A │ 41 79 4E 48 │ 74 75 64 47 │ 5A 7A 58 32  Mj..AyNHtudGZzX2
7589DDF0 52 76 61 57 │ 35 6E 58 32 │ 35 30 5A 6E │ 4E 66 64 47  RvaW5nX250ZnNfdG
7589DE00 68 70 62 6D │ 64 7A 66 51 │ 6F 3D 00 00 │ 00 00 00 00  hpbmdzfQo=......
7589DE10 FF FF FF FF │ 82 79 47 11 │ 00 00 00 00 │ 00 00 00 00  .....yG.........
```

*   The `AyNHtudGZzX2RvaW5nX250ZnNfdGhpbmdzfQo=` does not decode to anything sensible.
*   But at least its suffix should - and indeed, `NHtudGZzX2RvaW5nX250ZnNfdGhpbmdzfQo=` decodes to `4{ntfs_doing_ntfs_things}`
*   And then, you notice that there are also `c2`, `hj` and `Mj` parts of Base64 string earlier, just separated with CR/LF

## The flag

All together, `c2hjMjAyNHtudGZzX2RvaW5nX250ZnNfdGhpbmdzfQo=` decodes to the final flag.

---

## `shc2024{ntfs_doing_ntfs_things}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
