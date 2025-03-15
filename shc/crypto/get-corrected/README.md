# get-corrected

[library.m0unt41n.ch/challenges/get-corrected](https://library.m0unt41n.ch/challenges/get-corrected) ![](../../resources/crypto.svg) ![](../../resources/medium.svg) 

# TL;DR

> _I was asking ChatGPT about the McEliece cryptosystem and I wanted_
> _to encrypt a text, but a bug made it execute the encryption code_
> _many times and delete my file :(_ <br>
> _Now I don't remember what it was and all I have left is the public_
> _key and the encrypted messages, can you help me recover my message?_

We get a 1024x524 binary matrix and 20 1024-bit crypttexts, each with
50 random bit flipped. First, we find a clean crypttext (statistical
analysis) and then, the original 524-bit flag (solving a linear equation
over GF(2))

# Analysis

## Generic functions

First, let's dissect the functions that are somewhat boilerplate:

### `msg_to_bin_msgs()`

This function takes a string `msg` and block size `size`. Then:

*   Creates a bistring out if bytes in `msg`
*   Cuts it down into `size`-sized chunks
*   Returns a list of these chunks as `GF(2)` vectors
    (last chunk is padded with zeros)

Note that this is called with `G.shape[0]` below, which is `524`.
Considering that our crypttexts are all 1024-bit, the `messages`
result will have only a **single** 524-element GF(2) vector.

```python
def msg_to_bin_msgs(msg: str, size: int) -> list[GF]:
    # Converts string to bitstring
    m = "".join(bin(ord(c))[2:].rjust(8, "0") for c in msg)
    # Splits m into 'size'-sized chunks, each of them result of GF2([0, 1, 0, 0, 1, 1, 1, 0])
    tmp = []
    messages = []
    for a in m:
        tmp.append(int(a))
        if len(tmp) == size:
            messages.append(GF(tmp))
            tmp = []
    # If we still have something in tmp, pad to 'size' and append it too.
    if len(tmp) != 0:
        while len(tmp) != size:
            tmp.append(0)
        messages.append(GF(tmp))
    return messages
```

### `generate_random_vector()`

Returns a random vector of length `size` with _exactly_
`weight` bits set to `1` (and all others set to `0`)

```python
def generate_random_vector(size: int,weight: int) -> list[int]:
    v = np.zeros(size, dtype=int)
    for i in range(weight):
        index = random.randint(0, size - 1)
        while v[index] == 1:
            index = random.randint(0, size - 1)
        v[index] = 1
    return v.tolist()
```

BTW, this will be an infinite loop if `weight > size` &#128539;

### `add_error()`

Takes a `vector` argument and, with help of `generate_random_vector()`,
flips *exactly 50* bits in it. (`t = 50` is imported from provided
`public_key.py` below)

```python
def add_error(vector:np.ndarray) -> str:
    vector = vector.tolist()
    error = generate_random_vector(len(vector), t)
    new_vector = ""
    for bit1, bit2 in zip(vector, error):
        new_vector+= str(bit1 ^ bit2)
    return new_vector
```

## Making sense out of encryption

With all this, what's left of the provided code is down to:

```python
from public_key import G, t
from secret_file import flag

GF = galois.GF(2)
pub_key_matrix = GF(G)

def encrypt(msg: str, G: GF) -> str:
    msgs = msg_to_bin_msgs(msg, G.shape[0])
    print("encoding : ", msgs)
    cprime = ""
    for msg in msgs:
        cprime += add_error(msg @ G)  # Matrix multiplication
    return cprime

with open("encrypted_msgs.txt","w") as f:
    for _ in range(20):
        f.write(encrypt(flag,pub_key_matrix)+"\n")
```

Few things to note:

*   Just running the program with a random `flag` produces a similar output file.
    It also prints `encoding : ...` output, which confirms above understanding of
    `msg_to_bin_msgs()` (encode flag as bit string and pad with zeros)
*   As mentioned above, `G.shape[0]` is 524, so `msgs` has only one item.
*   Overall, the "encryption" is down to:
    *   Take the bitstring of the flag as a 524-item GF(2) vector `msgs`
    *   Multiply it by 1024x524 GF(2) `pub_key_matrix`
    *   Fuzz 50 bits (out of 1024) in the resulting vector
    *   Return that as ciphertext
*   That is called 20 times, producing different ciphertexts

### Key observation

*   For a given flag, the `msg @ G` is **always the same**
*   We have **20 samples** of **1024-bit** arrays, each of them with **50** random
    bits flipped. This is more than enough to recover non-fuzzed result of
    `msg @ G` with statistical analysis.
*   Then, it should be down to just solving `crypttext = msg @ G` for `msg`.

<br>

# Getting the flag

First, load the encrypted message - create `ALL_CT` list, with all
crypttexts in `encrypted_msgs.txt` converted to lists of 0s and 1s.

```python
ALL_CT = []
for l in open('encrypted_msgs.txt', 'r').readlines():
    if l.startswith("c = "):
        ALL_CT.append([1 if c=='1' else 0 for c in l[4:].strip()])
print(ALL_CT)
____________________________________________________________________________
[[1, 1, 1, 1, 1, ... 1, 0, 1, 1, 0], [1, 1, 1, 1, 1, ... 0, 1, 0, 1, 1, 0]]
```

For each of the 1024 positions, calculate how many crypttexts have
respective bit set at that position:

```python
CT = []
for i in range(1024):
    CT.append(sum([ALL_CT[c][i] for c in range(20)]))
print(CT)
____________________________________________________________________________
[19, 20, 19, 19, 20, 19, 20, 1, 1, ... 20, 1, 19, 1, 1, 19, 0, 19, 19, 0]
```

This looks *bimodal-enough* &#128521;. But, just to be sure, confirm the distribution:

```python
print([CT.count(c) for c in range(21)])
____________________________________________________________________________
[186, 182, 89, 23, 8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 2, 35, 84, 226, 183]
```

Nice. That definitely confirms the above analysis. With that, reconstruct the non-fuzzed crypttext:

```python
CT = [1 if CT[i]>10 else 0 for i in range(len(CT))]
print(CT)
____________________________________________________________________________
[1, 1, 1, 1, 1, 1, 1, 0, 0, 1, ... 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0]

```

Now, we need to solve the linear equation system: `CT = PT * G` in GF(2) for `PT`.
First let's make sure that the input data has good shape:

```python
from public_key import G
import numpy as np

mtx = np.array(G, dtype=int) % 2
vec = np.array(CT, dtype=int) % 2
print(mtx, "\n", mtx.shape)
print(vec, "\n", vec.shape)
____________________________________________________________________________
[[1 0 1 ... 1 1 0]
 [1 1 0 ... 0 0 0]
 [0 0 0 ... 0 0 0]
 ...
 [1 0 0 ... 0 1 1]
 [0 1 1 ... 0 0 0]
 [1 1 1 ... 1 1 1]] 
 (524, 1024)
[1 1 1 ... 1 1 0] 
 (1024,)
```

... OK, it actually does not &#128578; `mtx` needs to be transposed:

```python
mtx = mtx.T
print(mtx, "\n", mtx.shape)
____________________________________________________________________________
[[1 1 0 ... 1 0 1]
 [0 1 0 ... 0 1 1]
 [1 0 0 ... 0 1 1]
 ...
 [1 0 0 ... 0 0 1]
 [1 0 0 ... 1 0 1]
 [0 0 0 ... 1 0 1]] 
 (1024, 524)
```

Now, perform Gaussian elimination in GF(2). With some help from ChatGPT &#128521;

```python
mtx = np.hstack((mtx, vec.reshape(-1, 1)))   # Augment mtx
rows, cols = mtx.shape
num_vars = cols - 1  # Last column is the vector
for col in range(num_vars):
    # Find a pivot row for the current column
    pivot_row = None
    for row in range(col, rows):
        if mtx[row, col] == 1:
            pivot_row = row
            break
    if pivot_row is None:   # If no pivot row, move to the next column
        continue
    if pivot_row != col:    # Swap current row with pivot row
        mtx[[col, pivot_row]] = mtx[[pivot_row, col]]
    for row in range(col+1, rows):   # Eliminate all rows below the pivot
        if mtx[row, col] == 1:
            mtx[row] ^= mtx[col]  # XOR operation for GF(2)
# Back-substitution to find the solution
PT = np.zeros(num_vars, dtype=int)
for row in range(num_vars - 1, -1, -1):
    if mtx[row, row] == 1:  # Diagonal must be 1 for a valid solution
        PT[row] = mtx[row, -1] ^ np.dot(mtx[row, row + 1:num_vars], PT[row + 1:]) % 2
# Print the result
print(PT)
____________________________________________________________________________
[0 1 1 1 0 0 1 1 0 1 1 0 1 0 0 0 0 1 1 0 0 0 1 1 0 0 1 1 0 0 1 0 0 0 1 1 0
 0 0 0 0 0 1 1 0 0 1 0 0 0 1 1 0 0 1 1 0 1 1 1 1 0 1 1 0 0 1 1 0 0 0 1 0 1
 1 1 0 1 0 0 0 1 0 1 1 1 1 1 0 0 1 1 0 0 0 1 0 1 1 1 0 0 1 1 0 1 0 1 1 1 1
 1 0 0 1 1 0 1 0 0 0 1 1 0 1 1 0 0 0 1 1 0 1 1 0 0 0 1 0 1 1 1 1 1 0 0 1 1
 0 1 0 0 0 1 1 0 0 0 1 0 0 0 1 1 0 0 0 0 0 1 1 1 0 1 0 1 0 1 1 1 0 1 0 0 0
 1 0 1 1 1 1 1 0 0 1 1 0 0 1 1 0 1 1 1 0 0 1 0 0 1 1 1 0 0 1 0 0 0 1 1 0 0
 0 0 0 1 1 1 0 0 1 0 0 1 0 1 1 1 1 1 0 1 1 0 0 0 1 1 0 0 1 1 0 0 0 0 0 1 1
 1 0 0 1 0 0 1 1 1 0 0 1 0 0 0 1 1 0 0 1 1 0 1 1 0 0 0 1 1 0 1 1 1 0 1 0 0
 0 0 1 1 0 0 0 1 0 0 1 1 0 0 0 0 0 1 1 0 1 1 1 0 0 1 0 1 1 1 1 1 0 1 1 0 0
 1 0 1 0 0 1 1 0 1 1 1 0 1 1 0 0 1 1 0 0 0 1 1 0 1 0 1 0 1 1 0 0 0 0 1 0 0
 1 1 0 1 0 0 0 1 1 1 1 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
 0 0 0 0 0 0]
```

This looks promising! Bunch of ASCII-looking values (clear top bits),
padded with zeros. Let's try to decode it:

```python
flag = ""
for p in range(0, len(PT), 8):
    c = int(''.join(map(str, PT[p:p+8])), 2)
    if c > 0:
        flag += chr(c)
print(flag)
____________________________________________________________________________
shc2023{1t_1s_4ll_4b0ut_3rr0r_c0rr3ct10n_e7f5a4}
```

This was not very hard &#128578; It was clear from the start that this will be down to
solving a linear y=Ax system over GF(2), but I spent way too much time trying
to find a tool that would 'just do it', before just implementing the Gaussian
elimination by hand.

---

## `shc2023{1t_1s_4ll_4b0ut_3rr0r_c0rr3ct10n_e7f5a4}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
