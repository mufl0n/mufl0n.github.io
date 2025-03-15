# knowledge-archive

[library.m0unt41n.ch/challenges/knowledge-archive](https://library.m0unt41n.ch/challenges/knowledge-archive) ![](../../resources/web.svg) ![](../../resources/easy.svg) 

# TL;DR

We get a web application, for storing simple pieces of text.
The flag is a variable and can be extracted with format string vulnerability.

# Analysis

The code does not have any obvious weaknesses. While the flag is copied to each
new page's ini-file, it is not passed to the template for rendering.

However, `configparser` allows cross-reference between options, as described in
[Interpolation of values](https://docs.python.org/3/library/configparser.html#interpolation-of-values)
manual page:

```
[Paths]
home_dir: /Users
my_dir: %(home_dir)s/lumberjack
my_pictures: %(my_dir)s/Pictures
```

... so, we can try inserting `%(flag)s` in the input. And that works indeed.
Putting it in either of the inputs to the new page, renders the flag when
viewing it.

---

## `shc2032{n0_it_is_n0t_l3ttuce_049a01847cf64dd}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
