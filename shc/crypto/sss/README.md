# sss

[library.m0unt41n.ch/challenges/sss](https://library.m0unt41n.ch/challenges/sss) ![](../../resources/crypto.svg) ![](../../resources/baby.svg) 

# TL;DR

We get three PNG images wth QR codes

# Extracting QR code data

```
$ zbarimg --raw -q ?.png
1_0100013f062a81667e68428d80d56797990a025ced6e770dcfab5c60b71814eca5ec11a1d51102a62ab5d8046df7f7e7fec9f25ec08724a84b4f92db02c50e14d53c21
2_020004430255daa8eb6ae7bdfbfa1d4d9746e007869155b1e1ef79835f8b64306b1f09e4e36c945f65c3736aaa9ed3e5250f3572e2445cd13e376ce6a4a4d1d0d49941
3_0300090bf4820bc74707ef91716e2121fab698ffcb689bec36cc5767f959edcb4f993c0c6f8e285f149b05a71529fc2be5032871cd6c15ac4b16f25316d6b0996449dd
```

With some minor google search, this looks like
[Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing).

# Trying various SSS tools

What was super annoying here is that... none of the SSS tools that you can find online
worked. I tried

*   [bakaoh.com/sss-wasm](https://bakaoh.com/sss-wasm) - invalid inputs
*   [iancoleman.io/shamir](https://iancoleman.io/shamir) - gibberish
*   [simon-frey.com/s4](https://simon-frey.com/s4) - gibberish
*   Downloaded and compile [github.com/fletcher/c-sss](https://github.com/fletcher/c-sss) - nope
*   Installed [ssss](https://linux.die.net/man/1/ssss) - nope

Example of the latter:

```bash
$ C1=$(zbarimg --raw -q 1.png | cut -c3-)
$ C2=$(zbarimg --raw -q 2.png | cut -c3-)
$ C3=$(zbarimg --raw -q 3.png | cut -c3-)
$ echo -e "1-$C1\n2-$C2\n3-$C3" | ssss-combine -Q -t 3 -x -D 2>&1 | xxd -r -ps | xxd -g 1
00000000: 00 00 0c 77 f0 fd 50 09 d2 05 4a a1 0a 41 5b fb  ...w..P...J..A[.
00000010: f4 fa 7a a4 a0 97 b9 50 18 88 72 84 11 ca 9d 17  ..z....P..r.....
00000020: 81 6a 24 49 59 f3 be a6 5b ed ae c9 d2 40 d8 29  .j$IY...[....@.)
00000030: 3e c5 ef 5d ef af 6d d5 3e 6e 0c 6e b0 b7 6f 5d  >..]..m.>n.n..o]
00000040: 65 ec bb                                         e..
$ echo -e "1-$C1\n2-$C2\n3-$C3" | ssss-combine -Q -t 3 -x 2>&1 | xxd -r -ps | xxd -g 1
00000000: f1 bd d6 d2 d5 19 d5 a2 1f 30 5e 74 93 8b 9b f6  .........0^t....
00000010: 10 29 38 bc fb d6 e4 8e 74 18 0c 31 5d 60 16 e3  .)8.....t..1]`..
00000020: 18 b3 42 0e 6e f5 bf 8b 37 77 b0 c6 5b 6a b7 09  ..B.n...7w..[j..
00000030: d1 e9 50 b6 97 9f cc d7 d1 ed f2 06 0a c5 4f 24  ..P...........O$
00000040: c9 b1 9d                                         ...
```

(`-D` switches the internal algorithm, but neither worked)

I tried all kinds of XOR bruteforcing on these outputs, nothing worked.

# Trying Wikipedia code

Running out of ideas, I tried just running the code from Wikipedia:

```python
_PRIME = 2 ** 127 - 1

def _extended_gcd(a, b):
    x = 0
    last_x = 1
    y = 1
    last_y = 0
    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y

def _divmod(num, den, p):
    inv, _ = _extended_gcd(den, p)
    return num * inv

def _lagrange_interpolate(x, x_s, y_s, p):
    k = len(x_s)
    def PI(vals):
        accum = 1
        for v in vals:
            accum *= v
        return accum
    nums = []
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(PI(x - o for o in others))
        dens.append(PI(cur - o for o in others))
    den = PI(dens)
    num = sum([_divmod(nums[i] * den * y_s[i] % p, dens[i], p)
               for i in range(k)])
    return (_divmod(num, den, p) + p) % p

def recover_secret(shares, prime=_PRIME):
    x_s, y_s = zip(*shares)
    return _lagrange_interpolate(0, x_s, y_s, prime)

s1 = '1_0100013f062a81667e68428d80d56797990a025ced6e770dcfab5c60b71814eca5ec11a1d51102a62ab5d8046df7f7e7fec9f25ec08724a84b4f92db02c50e14d53c21'
s2 = '2_020004430255daa8eb6ae7bdfbfa1d4d9746e007869155b1e1ef79835f8b64306b1f09e4e36c945f65c3736aaa9ed3e5250f3572e2445cd13e376ce6a4a4d1d0d49941'
s3 = '3_0300090bf4820bc74707ef91716e2121fab698ffcb689bec36cc5767f959edcb4f993c0c6f8e285f149b05a71529fc2be5032871cd6c15ac4b16f25316d6b0996449dd'

shares = [(1, int.from_bytes(bytes.fromhex(s1[2:]), byteorder="big")),
          (2, int.from_bytes(bytes.fromhex(s2[2:]), byteorder="big")),
          (3, int.from_bytes(bytes.fromhex(s3[2:]), byteorder="big"))]
print(bytes.fromhex(hex(recover_secret(shares))[2:]))
```

... which did not work either:

```
b';\xf1+S\x989C\xcb\x18\xef\xa25\xceJ\x9a\x88'
```

# More digging

I found [Shamir Secret Sharing Best Practices](https://github.com/WebOfTrustInfo/rwot8-barcelona/blob/master/draft-documents/shamir-secret-sharing-best-practices.md) which mentions specific prime numbers. That made me realize that `_PRIME` is the only
variable parameter in above code and all these programs probably use different ones.
And that doc suggests that `secp256k1` is "commonly used".

I've set `_PRIME` to `2^256-2^32-2^9-2^8-2^7-2^6-2^4-1` and that worked better:

```
b'CD{s3cr3t_5h4r3_5h4m1r_d017\xb8ego@'
```

But, there's obviously some offset somewhere. The secret strings seem much longer than
(what I assume is) the flag - what happens if we try substrings of the shares?

```python
for l in range(2,80,2):
    shares = [(1, int.from_bytes(bytes.fromhex(s1[l:]), byteorder="big")),
              (2, int.from_bytes(bytes.fromhex(s2[l:]), byteorder="big")),
              (3, int.from_bytes(bytes.fromhex(s3[l:]), byteorder="big"))]
    secret = hex(recover_secret(shares))
    print("L:",l,"Secret:",secret, bytes.fromhex(secret[2:]))
```

Result:

```
L: 2 Secret: 0x43447b7333637233745f35683472335f3568346d31725f64303137b865676f40 b'CD{s3cr3t_5h4r3_5h4m1r_d017\xb8ego@'
L: 4 Secret: 0x43447b7333637233745f35683472335f3568346d31725f64303137b865676f40 b'CD{s3cr3t_5h4r3_5h4m1r_d017\xb8ego@'
(...)
L: 74 Secret: 0x447b7333637233745f35683472335f3568346d31725f64303137656566327d b'D{s3cr3t_5h4r3_5h4m1r_d017eef2}'
L: 76 Secret: 0xffff7b7333637233745f35683472335f3568346d31725f643031376465662eac b'\xff\xff{s3cr3t_5h4r3_5h4m1r_d017def.\xac'
L: 78 Secret: 0xfffffe7333637233745f35683472335f3568346d31725f643031376465662eac b'\xff\xff\xfes3cr3t_5h4r3_5h4m1r_d017def.\xac'
```

The output for `74` looked promising, so, I tried just prepending `SC` to that.
And it worked.

# Clean solution

Already after solving the challenge, I found out that
[github.com/shea256/secret-sharing](https://github.com/shea256/secret-sharing)
**could** have produced a clean solution here. I initially dismissed it because it had
some Python2-isms which I did not bother to fix
(`NameError: name 'long' is not defined`). But after replacing these `long`
instances with `int`:

```python
from secretsharing import SecretSharer
shares = [
    "1-0100013f062a81667e68428d80d56797990a025ced6e770dcfab5c60b71814eca5ec11a1d51102a62ab5d8046df7f7e7fec9f25ec08724a84b4f92db02c50e14d53c21",
    "2-020004430255daa8eb6ae7bdfbfa1d4d9746e007869155b1e1ef79835f8b64306b1f09e4e36c945f65c3736aaa9ed3e5250f3572e2445cd13e376ce6a4a4d1d0d49941",
    "3-0300090bf4820bc74707ef91716e2121fab698ffcb689bec36cc5767f959edcb4f993c0c6f8e285f149b05a71529fc2be5032871cd6c15ac4b16f25316d6b0996449dd"
]
secret = SecretSharer.recover_secret(shares)
print(bytearray.fromhex(secret).decode())
```
Result
```
SCD{s3cr3t_5h4r3_5h4m1r_d017eef2}
```

Interesting: it used **yet different** prime - the Mersenne prime #607. Once I
replaced `_PRIME` with `2**607-1` it produced the flag. Wonders of a finite
field algebra...

---

## `SCD{s3cr3t_5h4r3_5h4m1r_d017eef2}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
