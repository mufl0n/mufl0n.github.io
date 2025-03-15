# aindroid

[library.m0unt41n.ch/challenges/aindroid](https://library.m0unt41n.ch/challenges/aindroid) ![](../../resources/forensics.svg) ![](../../resources/medium.svg) 

# TL;DR

> _The presidents phone contains secret AI deactivation codes. But dammit, he forgot his_
> _password so we can't hit him with a wrench. We need those code in so we can deactivate_
> _the AI watermark warriors. Please help us!_
>
> ***Wrap the SHA512 hash of the phone password in the flag format:***<br>
> `echo "cyberskills23{$(echo -n "" | sha512sum | awk '{print $1}')}" `

# Cleaning up the image

The provided AVD is a Pixel 3 XL image (API version 23). It encodes a few paths from author's
Windows machine. I'll clean these up first:

```bash
$ API=23
$ AVD=Pixel_3_XL_API_$API
$ SDK=/home/local/Android
$ JRE=/usr/lib/jvm/jre/bin
$ sdkmanager --install "platforms;android-$API" "system-images;android-$API;google_apis;x86"
$ export ANDROID_AVD_HOME=${PWD}
$ /bin/rm -rf $AVD.avd
$ mkdir $AVD.avd
$ unzip -d $AVD.avd ../aindroid.zip
$ sed -e "s|\\\\|/|g" -e "s|C:/Users/xnull/AppData/Local/Android/Sdk|$SDK|g" \
      -e "s|C:/Program Files/Android/Android Studio/jre/jre/bin|$JRE|g" \
      -e "s|C:/Users/xnull/.android/avd|$PWD|g" -i $AVD.avd/*.{txt,ini}
$ echo "path=$PWD/$AVD.avd" >$AVD.ini
```

> Technically speaking, probably only `image.sysdir` needs to be fixed, but I like
> my environment clean &#128521;.

The image uses a custom skin, let's get it too:

```bash
$ git clone https://github.com/larskristianhaga/Android-emulator-skins $AVD.avd/skins
```

With that, `emulator -avd Pixel_3_XL_API_23` starts just fine - and I can `adb shell` too.

# Inspecting the system

It is Android 6.0 "Marshmallow" (a.k.a. Android M), 2016-09-06 build 6695544. API version 23.
Poking around with `adb shell`, these files seem relevant:

```bash
$ adb pull /data/system/gatekeeper.password.key
$ adb pull /data/system/device_policies.xml
$ adb pull /data/system/locksettings.db
$ adb pull /data/misc/gatekeeper/0
$ adb pull /data/misc/keystore/user_0/10008_USRSKEY_android_pay_recent_unlock_key_2
```

`device_policies.xml` contains:

```xml
<active-password quality="262144" length="9" uppercase="0" lowercase="9" letters="9" numeric="0" symbols="0" nonletter="0"/>
```

`262144` is
[PASSWORD_QUALITY_ALPHABETIC](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#PASSWORD_QUALITY_ALPHABETIC).
So, the password is 9 lowercase chars. Only 5'429'503'678'976 combinations! &#128521;

`gatekeeper.*.key` files have the actual auth secrets:

```bash
$ ls -la /data/system/gatekeeper.*
-rw------- system   system         58 2023-06-17 20:16 gatekeeper.password.key
-rw------- system   system          0 2023-06-17 20:16 gatekeeper.pattern.key
```

In particular, removing `/data/system/gatekeeper.password.key` removes the lock - but this is
obviously not helping with solving the challenge (we need the password, not unlocked phone).

# Decrypting the password

5T combinations for the password looked like crackable at first (I have a nice PC &#128539;). However,
it turns out that this version of Android uses SCRYPT hash, which, compared to MD5 or SHA, is
very computationally expensive and made specifically to prevent brute-forcing.

[This blog post](https://nelenkov.blogspot.com/2015/06/password-storage-in-android-m.html)
describes in detail how password encryption on Android 6 works, in particular the internals
of `gatekeeper.password.key`. It is a binary file that has few parts, mapping to a C struct.
Hex dump of the file:

```bash
$ xxd -c0 -ps gatekeeper.password.key
02eb0927382ab9214401000000000000003a9db29a1cdf68a9c3b516202ed66587616532b96b8ea81c866738888ca1db328cfa1c278279aebc00
```

... can be mapped to:

```c
typedef uint64_t secure_id_t;
typedef uint64_t salt_t;
static const uint8_t HANDLE_VERSION = 2;
struct password_handle_t {
    uint8_t version;        // 02
    secure_id_t user_id;    // eb0927382ab92144
    uint64_t flags;         // 0100000000000000
    salt_t salt;            // 3a9db29a1cdf68a9
    uint8_t signature[32];  // c3b516202ed66587616532b96b8ea81c866738888ca1db328cfa1c278279aebc
    bool hardware_backed;   // 00
};
```

(BTW, there is also and 8-byte `/data/misc/gatekeeper/0`, that contains the `user_id` value above)

What do all these things mean? Quoting the article:

> _the 'signature' stored in the password handle file is indeed the scrypt value of the blob's `version`,_
> _the 64-bit secure `user_id`, and the blob's `flags` field, concatenated with the plaintext pattern_
> _value. The scrypt hash value is calculated using the stored 64-bit salt and the scrypt parameters_
> _`N=16384`, `r=8`, `p=1`. Password handles for PINs or passwords are calculated in the same way, using_
> _the PIN/password string value as input._

<br>Hashcat has `SCRYPT` [mode 8900](https://hashcat.net/wiki/doku.php?id=example_hashes),
where the hash format is `SCRYPT:N:r:p:base64(salt):base64(digest)`. But, as described above, we can't
feed the wordlist to it directly, but have to prefix each word with 17 bytes of `version+user_id+salt`.
This can be done using a
[prepend rule](https://hashcat.net/wiki/doku.php?id=rule_based_attack). Let's create `gatekeeper.rule`:

```
^\x00^\x00^\x00^\x00^\x00^\x00^\x00^\x01^\x44^\x21^\xb9^\x2a^\x38^\x27^\x09^\xeb^\x02
```

(Note that the order is reverse - each of the prepend chars stack on top of each other).

Then, remaining values are:

*   `N=16384`, `r=8`, `p=1`
*   `base64(salt)`: [`Op2ymhzfaKk=`](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')To_Base64('A-Za-z0-9%2B/%3D')&input=M2E5ZGIyOWExY2RmNjhhOQ)
*   `base64(digest)`: [`w7UWIC7WZYdhZTK5a46oHIZnOIiModsyjPocJ4J5rrw=`](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')To_Base64('A-Za-z0-9%2B/%3D')&input=YzNiNTE2MjAyZWQ2NjU4NzYxNjUzMmI5NmI4ZWE4MWM4NjY3Mzg4ODhjYTFkYjMyOGNmYTFjMjc4Mjc5YWViYw)

Armed with all that and [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt):

```
$ hashcat -m 8900 -a 0 -r gatekeeper.rule "SCRYPT:16384:8:1:Op2ymhzfaKk=:w7UWIC7WZYdhZTK5a46oHIZnOIiModsyjPocJ4J5rrw=" rockyou.txt

(...)

SCRYPT:16384:8:1:Op2ymhzfaKk=:w7UWIC7WZYdhZTK5a46oHIZnOIiModsyjPocJ4J5rrw=:$HEX[02eb0927382ab92144010000000000000073706f6e6765626f62]
```

Which, after trimming the initial 17 bytes,
[decodes back](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')Tail('Nothing%20(separate%20chars)',9)&input=MDJlYjA5MjczODJhYjkyMTQ0MDEwMDAwMDAwMDAwMDAwMDczNzA2ZjZlNjc2NTYyNmY2Mg)
to: **spongebob** &#128512;<br>

> BTW, there is apparently an [android-cracker](https://github.com/TheMythologist/android-cracker)
tool which can do all this automatically - but I much prefer to a) understand the logic
b) be able to use the power of hashcat &#128578;

<br>Now the only thing left is to generate a SHA512 sum, as instructed:

```bash
$ echo -n "spongebob" | sha512sum | awk '{print "cyberskills23{"$1"}"}'
```

---

## `cyberskills23{8803bca23b52054117e8637fae45d4a40f26a9a72c049fe54bbe33b09c2bf53cb01353f9ae10b343c1c38787011a0e19a8933b86d617e91020305490f14ebaad}`




<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
