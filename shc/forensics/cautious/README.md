# cautious

[library.m0unt41n.ch/challenges/cautious](https://library.m0unt41n.ch/challenges/cautious) ![](../../resources/forensics.svg) ![](../../resources/easy.svg) 

# TL;DR

We get Android backup and need to get the flag out of it.

# Getting the flag

Per [StackOverflow question](http://stackoverflow.com/questions/18533567),
this format is actually a `.tar.gz`, just with extra header. It can be
unpacked with a shell snippet:

```
$ ( printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" ; tail -c +25 backup.ab ) |  tar xfvz -
apps/android/_manifest
apps/android/r/wallpaper_info.xml
apps/com.android.bluetoothmidiservice/_manifest
(...)
gzip: stdin: unexpected end of file
tar: Child returned status 1
tar: Error is not recoverable: exiting now
```

(As mentioned in the source, the error is expected and the data should be there).

Let's poke in it:

```
$ grep -ri 'shc{' apps
grep: apps/com.android.providers.settings/f/flattened-data: binary file matches
$ strings apps/com.android.providers.settings/f/flattened-data | grep shc
	psk="shc{G3T TH3 S3CR3T W1F1 PW}"
```

That was too easy &#128578;

---

## `shc{G3T TH3 S3CR3T W1F1 PW}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
