# whiteboard

[library.m0unt41n.ch/challenges/whiteboard](https://library.m0unt41n.ch/challenges/whiteboard) ![](../../resources/pwn.svg) ![](../../resources/easy.svg) 

# TL;DR

Traditional "note keeper" app, with the flag saved as note #0.

The code:

*   Allows only retrieving notes from 1 up (adds `1` to the provided number)
*   Disallows negative numbers, which would make ^^^ fetch the note #0
*   But, with a custom `number_input()`, allows integer overflow on the note ID.

So, we need to "view" the note number `4294967295` &#128578;

---

## `stairctf{wh0_n33ds_s3cr3t5_4nyw4y5???}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
