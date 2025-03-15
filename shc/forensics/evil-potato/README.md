# evil-potato

[library.m0unt41n.ch/challenges/evil-potato](https://library.m0unt41n.ch/challenges/evil-potato) ![](../../resources/forensics.svg) ![](../../resources/baby.svg) 

# TL;DR

We don't even need to use packet analyzer for this one:

```
$ strings evil_potato.pcapng | grep shc
GET /search?q=shc2023%7Bdel3te_the_brows3r_hist0ry_before_i_di3%7D HTTP/1.1
Location: https://www.google.com/search?q=shc2023%7Bdel3te_the_brows3r_hist0ry_before_i_di3%7D&gws_rd=ssl
<A HREF="https://www.google.com/search?q=shc2023%7Bdel3te_the_brows3r_hist0ry_before_i_di3%7D&amp;gws_rd=ssl">here</A>.

$ strings evil_potato.pcapng | grep 'GET.*shc2023' | sed -r 's/.*shc2023%7B(.*)%7D.*/shc2023{\1}/'
shc2023{del3te_the_brows3r_hist0ry_before_i_di3}
```

---

## `shc2023{del3te_the_brows3r_hist0ry_before_i_di3}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
