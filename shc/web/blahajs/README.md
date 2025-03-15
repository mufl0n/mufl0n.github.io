# blahajs

[library.m0unt41n.ch/challenges/blahajs](https://library.m0unt41n.ch/challenges/blahajs) ![](../../resources/web.svg) ![](../../resources/baby.svg) 

# TL;DR

We get a web access to a simple image gallery.
There is not much of a hint in the description, perhaps except for:
*The site's not exactly Fort Knox*.

# Getting the flag

The gallery is super rudimentary:

```html
    <h1>Awesome Image Gallery</h1>
    <ul>
        <img src="/image?name=image1.jpg" />
        <img src="/image?name=image2.jpg" />
    </ul>
```

The hint in the description makes you think of the simples solutions like path traversal.

With a bit of trial and error, using `/image?name=../flag.txt` in the URL works.

---

## `SCD{d1r3ctory_tr4v3rsal_is_3asy}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
