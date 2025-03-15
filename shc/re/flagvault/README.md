# flagvault

[library.m0unt41n.ch/challenges/flagvault](https://library.m0unt41n.ch/challenges/flagvault) ![](../../resources/re.svg) ![](../../resources/medium.svg) 

# TL;DR

We are given a Rust binary, with a dialog:

```
$ ./flagvault 
Welcome to our secure flag store.
> Please enter your password: ********
Your password is test.
Decryption result [100, 127, 117, 74, 84, 44, 31, 5, 118, 26, 92, 89, 90, 84, 77, 28, 65, 20, 66, 13, 65, 65].
Invalid password.

```

# Decompilation

I have not found any other method than brutal decompile and trying to make sense of the result.
I normally use [IDA](https://hex-rays.com/ida-free/), but this time
[Binary Ninja](https://binary.ninja/free/) produced much better results.

## Helper class and methods

First, apart from `main()` function, there are a few others with `xor` in the name, which seems
to be a class, that defines `InfiniteByteIterator` for a fancy reading from short key:

*   <details>
      <summary><code>InfiniteByteIterator::new()</code> constructor</summary>
    
      ```c
      00058140  int64_t* rust_chall::xor::InfiniteByteIterator::new::hb3f88f47694d34f0(int64_t* self, int64_t arg2, int64_t arg3)
    
      00058143      int64_t var_10 = arg2
      00058148      int64_t var_8 = arg3
      0005814d      *self = arg2
      00058150      self[1] = arg3
      00058154      self[2] = 0
      0005815c      return self
      ```
    </details>
*   <details>
      <summary><code>next()</code> method</summary>
    
      ```c
      00058160  int64_t _$LT$rust_chall..xor..InfiniteByteIterator$u20$as$u20$core..iter..traits..iterator..Iterator$GT$::next::h61e0f764d7e7fc08(int64_t* self)
    
      00058169      int64_t* self_1 = self
      0005816e      int64_t rax = self[2]
      00058177      int64_t rcx = self[1]
      00058177      
      00058183      if (rax u>= rcx)
      000581e8          core::panicking::panic_bounds_check::hd50e5569f1e9112b(rax, rcx)
      000581e8          noreturn
      000581e8      
      00058192      char* rcx_1
      00058192      rcx_1.b = (*self)[rax]
      00058199      char var_1 = rcx_1.b
      000581b2      int64_t result
      000581b2      result.b = rcx_1.b
      000581b6      self[2] = rust_chall::xor::next_index::hd21b15bb4a819776(self[2], self[1])
      000581ba      char var_11 = result.b
      000581c3      result.b = 1
      000581c7      int64_t rdx_1
      000581c7      rdx_1.b = var_11
      000581cf      return result
      ```
    </details>

... and then, some static methods for actually doing stuff:

*   <details>
      <summary><code>next_index()</code></summary>
    
      ```c
      000581f0  int64_t rust_chall::xor::next_index::hd21b15bb4a819776(int64_t arg1, int64_t arg2)
      000581fe      int64_t var_10 = arg1
      00058203      int64_t var_8 = arg2
      00058208      bool c = arg1 u>= -1
      00058211      int64_t rax
      00058211      rax.b = c
      00058211      
      00058214      if (c)
      00058235          core::panicking::panic_c...const_add_overflow::h7b9a9aabd4b1769b()
      00058235          noreturn
      00058235      
      00058223      if (arg1 + 1 u>= arg2)
      00058237          return 0
      00058237      
      00058247      bool c_1 = arg1 u>= -1
      0005824f      int64_t rax_3
      0005824f      rax_3.b = c_1
      0005824f      
      00058252      if (not(c_1))
      00058264          return arg1 + 1
      00058264      
      00058279      core::panicking::panic_c...const_add_overflow::h7b9a9aabd4b1769b()
      00058279      noreturn
      ```
    </details>
*   <details>
      <summary><code>xor()</code></summary>
    
      ```c
      00057fb0  int64_t* rust_chall::xor::xor::hf165f24b7f27abe7(int64_t* arg1, int64_t arg2, int64_t arg3, char* key, int64_t keyLen)
      00057fd4      int64_t var_20 = arg2
      00057fdc      int64_t var_18 = arg3
      00057fe4      char* key_1 = key
      00057fec      int64_t keyLen_1 = keyLen
      00057fec      
      00057ff7      if (keyLen == 0)
      00058078          _$LT$T$u20$as$u20$core.....LT$U$GT$$GT$::into::he6afabf4ee71ee7e(arg1, arg2, arg3)
      00057ff7      else if (keyLen == 1)
      00058088          if (0 u>= keyLen)
      000580cd              core::panicking::panic_bounds_check::hd50e5569f1e9112b(0, keyLen)
      000580cd              noreturn
      000580cd          
      000580b0          rust_chall::xor::xor_with_byte::h053435e3af6c5dc3(arg1, arg2, arg3, key: *key)
      00058003      else
      00058015          void var_b8
      00058015          rust_chall::xor::InfiniteByteIterator::new::hb3f88f47694d34f0(self: &var_b8, key, keyLen)
      00058024          int64_t rax_3
      00058024          int64_t rdx_1
      00058024          rax_3, rdx_1 = core::slice::_$LT$impl$u...b$T$u5d$$GT$::iter::h14e5d7edc823c887(arg2, arg3)
      0005803a          void var_60
      0005803a          core::iter::traits::iterator::Iterator::zip::h48a25e162b38f3c0(&var_60, rax_3, rdx_1, &var_b8)
      0005804c          void var_a0
      0005804c          core::iter::traits::iterator::Iterator::map::hbb41b27aaa87dd45(&var_a0, &var_60)
      0005805b          core::iter::traits::iter...:Iterator::collect::hd6e061cb5ecb7eb4(arg1, &var_a0)
      0005805b      
      00058098      return arg1
      ```
    </details>
*   <details>
      <summary><code>xor_with_bytes()</code></summary>
    
      ```c
      000580d0  int64_t* rust_chall::xor::xor_with_byte::h053435e3af6c5dc3(int64_t* arg1, int64_t arg2, int64_t arg3, char key)
      000580fa      char key_1 = key
      000580fe      int64_t var_10 = arg2
      00058103      int64_t var_8 = arg3
      00058108      int64_t rax_1
      00058108      int64_t rdx
      00058108      rax_1, rdx = core::slice::_$LT$impl$u...b$T$u5d$$GT$::iter::h14e5d7edc823c887(arg2, arg3)
      0005811b      void var_28
      0005811b      core::iter::traits::iterator::Iterator::map::h561531d4c82c8a1c(&var_28, rax_1, rdx, &key_1)
      0005812a      core::iter::traits::iter...:Iterator::collect::h18f988de7c31ef0d(arg1, &var_28)
      00058138      return arg1
      ```
    </details>

... and finally:

*   <details>
      <summary><code>main()</code> function</summary>
    
      ```c
      00059d80  int64_t* rust_chall::main::h06fa0dcc19e9a5bd()
    
      00059d8e      char const* const var_550 = &data_166b1[0x2b]
      00059d93      char var_b1 = 0
    
      00059d9b      // .
      00059d9b      // Print welcome banner
      00059d9b      // .
      00059d9b      char var_b2 = 0
      00059db2      void ptrStrWelcomeCopy
      00059db2      core::fmt::Arguments::new_const::h316b7084252ab927(&ptrStrWelcomeCopy, &ptrStrWelcome)
      00059dc0      std::io::stdio::_print::he9151e825de397de(&ptrStrWelcomeCopy)
    
      00059dda      // .
      00059dda      // Read password
      00059dda      // .
      00059dda      void password_input
      00059dda      inquire::prompts::password::Password::new::hfee08116fe868084(&password_input, "Please enter your password:src/m…", 0x1b)
    
      00059df0      // .
      00059df0      // Read password again and check
      00059df0      // .
      00059df0      int64_t passCheckResult
      00059df0      inquire::prompts::password::Password::prompt::h2cd2d67f2625b33b(&passCheckResult, &password_input)
    
      00059dff      // .
      00059dff      // Bail out if incorrect
      00059dff      // .
      00059dff      int64_t passCopy1_1
      00059dff      
      00059dff      if (passCheckResult != 0)
      00059e0d          int64_t var_4e8
      00059e0d          int64_t var_18 = var_4e8
      00059e1d          int128_t var_28 = passCopy1_1.o
      00059e4e          core::result::unwrap_failed::h9b24819c02d169b5("called `Result::unwrap()` on an …", 0x2b, &var_28)
      00059e4e          noreturn
    
      00059e9e      // .
      00059e9e      // Print "Your password is: "
      00059e9e      // .
      00059e9e      int64_t passCopy1 = passCopy1_1
      00059f6a      int128_t passCopy = (&passCopy1).o
      00059f90      void var_2d8
      00059f90      core::fmt::Arguments::new_v1::h88d2bdce603dd763(&var_2d8, &ptrStrYourPasswordIs, &passCopy)
      00059fa3      std::io::stdio::_print::he9151e825de397de(&var_2d8)
    
      00059faf      // .
      00059faf      // Get password as bytes slice
      00059faf      // .
      00059faf      int64_t passBytesOrLen
      00059faf      int64_t passLenOrBytes
      00059faf      passBytesOrLen, passLenOrBytes = alloc::string::String::as_bytes::h4ab6d9519b1afcdf(&passCopy1)
    
      00059fff      // .
      00059fff      // XOR password byes with "l33t"
      00059fff      // .
      00059fff      void passXorredWithl33t
      00059fff      rust_chall::xor::xor::hf165f24b7f27abe7(&passXorredWithl33t, passBytesOrLen, passLenOrBytes, key: "l33ttputNonecolsshim5;15    \x1b…", keyLen: 4)
    
      0005a00d      // .
      0005a00d      // Create byte array object, with 22 bytes:
      0005a00d      // 7c 29 35 4a 4c 7a 5f 05
      0005a00d      // 6e 4c 1c 59 42 02 0d 1c
      0005a00d      // 59 42 02 0d 59 17
      0005a00d      // .
      0005a00d      int64_t arrayOf22Byte = core::array::_$LT$impl$u...u5d$$GT$::as_slice::hc876afe158fb88fd(&data_166b1[0x2b])
    
      0005a08d      // .
      0005a08d      // var_238 = arrayOf22Byte ^ passXorredWithl33t
      0005a08d      // .
      0005a08d      char* key
      0005a08d      int64_t keyLen
      0005a08d      key, keyLen = _$LT$alloc..vec..Vec$LT$.....Deref$GT$::deref::h83c6c1d138c69fa4(&passXorredWithl33t)
      0005a0b7      int128_t var_260
      0005a0b7      rust_chall::xor::xor::hf165f24b7f27abe7(&var_260, arrayOf22Byte, 22, key, keyLen)
    
      0005a0ce      // .
      0005a0ce      // Print: "Your password is ..."
      0005a0ce      // .
      0005a0ce      int128_t* var_1e8 = &var_260
      0005a177      int128_t var_208 = (&var_1e8).o
      0005a19d      void var_238
      0005a19d      core::fmt::Arguments::new_v1::h88d2bdce603dd763(&var_238, &ptrStrYourPasswordIs, &var_208)
      0005a1b0      std::io::stdio::_print::he9151e825de397de(&var_238)
      0005a1b4      char var_b1_1 = 0
      0005a1c4      int64_t var_250
      0005a1c4      int64_t var_1a8 = var_250
      0005a1d4      int128_t var_1b8 = var_260
      0005a1ec      int64_t var_1e0
      0005a1ec      alloc::string::String::from_utf8::h5d5fb47ef29c5522(&var_1e0, &var_1b8)
      0005a1f3      char var_b2_1 = 1
      0005a205      int64_t rax_9 = 1
      0005a205      
      0005a214      if (var_1e0 == -0x8000000000000000)
      0005a214          rax_9 = 0
      0005a214      
      0005a21c      int128_t decryptedFlag_1
      0005a21c      
      0005a21c      if (rax_9 != 0)
      0005a275          void var_e8
      0005a275          core::fmt::Arguments::new_const::h316b7084252ab927(&var_e8, &ptrStrInvalidPassword)
      0005a47f          std::io::stdio::_print::he9151e825de397de(&var_e8)
      0005a21c      else
      0005a21e          var_b2_1 = 0
      0005a22e          int64_t var_1c8
      0005a22e          int64_t var_188_1 = var_1c8
    
      0005a23e          // .
      0005a23e          // See if decrypted password starts with "SCD{"
      0005a23e          // .
      0005a23e          int128_t decryptedFlag = decryptedFlag_1
      0005a24e          int64_t decryptedFlagPtr
      0005a24e          int64_t decryptedFlagLen
      0005a24e          decryptedFlagPtr, decryptedFlagLen = _$LT$alloc..string..Stri.....Deref$GT$::deref::hf4bf40b3a5bed533(&decryptedFlag)
      0005a2be          char rax_11 = core::str::_$LT$impl$u20$str$GT$::starts_with::h8be0d8b49bb66469(decryptedFlagPtr, decryptedFlagLen, "SCD{Some <= truechar5;12 -> l33t…", 4)
      0005a2cf          char rax_13
      0005a2cf          
      0005a2cf          if ((rax_11 & 1) != 0)
      0005a2f8              int64_t rax_12
      0005a2f8              int64_t rdx_4
      0005a2f8              rax_12, rdx_4 = _$LT$alloc..string..Stri.....Deref$GT$::deref::hf4bf40b3a5bed533(&decryptedFlag)
      0005a31f              rax_13 = core::str::_$LT$impl$u20$str$GT$::ends_with::hc5732ee448de45b9(rax_12, rdx_4, "}Invalid password.\nThe flag of …", 1)
      0005a31f          
      0005a330          if ((rax_11 & 1) != 0 && (rax_13 & 1) != 0)
      0005a33c              int128_t* var_120 = &decryptedFlag
      0005a3e4              int128_t var_148 = (&var_120).o
      0005a40a              void var_178
      0005a40a              core::fmt::Arguments::new_v1::h88d2bdce603dd763(&var_178, &ptrStrTheFlagOfThe, &var_148)
      0005a41d              std::io::stdio::_print::he9151e825de397de(&var_178)
      0005a330          else
      0005a2e9              void var_118
      0005a2e9              core::fmt::Arguments::new_const::h316b7084252ab927(&var_118, &ptrStrInvalidPassword)
      0005a3c3              std::io::stdio::_print::he9151e825de397de(&var_118)
      0005a3c3          
      0005a3d8          core::ptr::drop_in_place...string..String$GT$::h8d1d881c9762758d(&decryptedFlag)
      0005a3d8      
      0005a44c      char var_b1_2 = 0
      0005a463      core::ptr::drop_in_place....Vec$LT$u8$GT$$GT$::haf139de0d4ac9efd(&passXorredWithl33t)
      0005a4bd      core::ptr::drop_in_place...string..String$GT$::h8d1d881c9762758d(&passCopy1)
      0005a509      int64_t* result = &(*nullptr->ident.signature)[1]
      0005a509      
      0005a518      if (var_1e0 == -0x8000000000000000)
      0005a518          result = nullptr
      0005a518      
      0005a520      if (result != 0)
      0005a536          result = core::ptr::drop_in_place...mUtf8Error$GT$$GT$::h024bd46f9516b105(&var_1e0)
      0005a520      else if ((var_b2_1 & 1) != 0)
      0005a557          result = core::ptr::drop_in_place...string..String$GT$::h8d1d881c9762758d(&decryptedFlag_1)
      0005a557      
      0005a53b      char var_b2_2 = 0
      0005a54a      return result
      ```
    </details>

# Analysis of main()

I can't claim to have understood all this code, but what seems to be roughly going on:

Print a welcome banner

```c
core::fmt::Arguments::new_const::h316b7084252ab927(
    &ptrStrWelcomeCopy,
    &ptrStrWelcome)
std::io::stdio::_print::he9151e825de397de(
    &ptrStrWelcomeCopy)
```

Read the password

```c
inquire::prompts::password::Password::new::hfee08116fe868084(
    &password_input,
    "Please enter your password:src/m…", 0x1b)
```

Read the password again and bail out if it's not the same

```c
inquire::prompts::password::Password::prompt::h2cd2d67f2625b33b(
    &passCheckResult,
    &password_input)
if (passCheckResult != 0)
    (...)
```

Print the password

```c
core::fmt::Arguments::new_v1::h88d2bdce603dd763(
    &var_2d8,
    &ptrStrYourPasswordIs,
    &passCopy)
std::io::stdio::_print::he9151e825de397de(&var_2d8)
```

Convert the password to bytes (note how I don't know which is which &#128578;)

```c
passBytesOrLen, passLenOrBytes =
    alloc::string::String::as_bytes::h4ab6d9519b1afcdf(&passCopy1)
```

XOR the password bytes with `l33t`

```c
rust_chall::xor::xor::hf165f24b7f27abe7(
    &passXorredWithl33t,
    passBytesOrLen, passLenOrBytes,
    key: "l33ttputNonecolsshim5;15    \x1b…", keyLen: 4)
```

Create another byte array (slice?), from a predefined location in the data segment:

```c
int64_t arrayOf22Byte =
    core::array::_$LT$impl$u...u5d$$GT$::as_slice::hc876afe158fb88fd(&data_166b1[0x2b])
```

That location in memory contains following 22 bytes:

```
7c 29 35 4a 4c 7a 5f 05 6e 4c 1c 59 42 02 0d 1c 59 42 02 0d 59 17
```

XOR that array with the XORed password above

```c
rust_chall::xor::xor::hf165f24b7f27abe7(&var_260, arrayOf22Byte, 22, key, keyLen)
```

Print the password

```c
core::fmt::Arguments::new_v1::h88d2bdce603dd763(&var_238, &ptrStrYourPasswordIs, &var_208)
std::io::stdio::_print::he9151e825de397de(&var_238)
```

... something with `String::from_utf8` that I did not quite get &#128578;

But then, the key part

```c
decryptedFlagPtr, decryptedFlagLen =
    _$LT$alloc..string..Stri.....Deref$GT$::deref::hf4bf40b3a5bed533(&decryptedFlag)
char rax_11 = core::str::_$LT$impl$u20$str$GT$::starts_with::h8be0d8b49bb66469
    (decryptedFlagPtr, decryptedFlagLen, "SCD{Some <= truechar5;12 -> l33t…", 4)
```
Note the `SCD{` prefix and that the last argument (key length) is `4`.

At this point, the hypothesis was that the password is 4 characters, which:

*   ... once XORed with `l33t`
*   ... and used as a key to decrypt the 22-byte array

... will produce the flag.

# Decrypting the 4-byte password

```python
def xor(arg, key):
    res = b''
    for i in range(len(arg)):
        res += bytes([arg[i] ^ key[i % len(key)]])
    return res


KEY_1337 = b'l33t'
DATA_166DC = bytes([0x7c, 0x29, 0x35, 0x4a, 0x4c, 0x7a, 0x5f, 0x05,
                    0x6e, 0x4c, 0x1c, 0x59, 0x42, 0x02, 0x0d, 0x1c,
                    0x59, 0x42, 0x02, 0x0d, 0x59, 0x17])
PREFIX = b'SCD{'

passwd = b''
for pos in range(len(PREFIX)):
    for c in range(256):
        attempt = passwd + bytes([c])
        xorred = xor(attempt, KEY_1337)
        dec = xor(DATA_166DC, xorred)
        print(attempt," --> ", xorred, " --> ", dec)
        if dec[len(passwd)]==PREFIX[len(passwd)]:
            print("Success")
            passwd = attempt
            break
```

Result:

```
(...)
b'CYBD'  -->  b'/jq0'  -->  b'SCDzc\x10.5A&mimh|,v(s=v}'
b'CYBE'  -->  b'/jq1'  -->  b'SCD{c\x10.4A&mhmh|-v(s<v}'
Success
```

That's not the flag though.

# Getting the flag

At this point I just YOLO'd and assumed that the password is `CYBER`. And I was right &#128578;

```
$ ./flagvault 
Welcome to our secure flag store.
> Please enter your password: ********
Your password is CYBER.
Decryption result [83, 67, 68, 123, 114, 85, 53, 116, 95, 114, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 118, 125].
The flag of the day is SCD{rU5t_r3333333333v}.
```

---

## `SCD{rU5t_r3333333333v}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
