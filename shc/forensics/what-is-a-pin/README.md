# what-is-a-pin

[library.m0unt41n.ch/challenges/what-is-a-pin](https://library.m0unt41n.ch/challenges/what-is-a-pin) ![](../../resources/forensics.svg) ![](../../resources/easy.svg) 

# TL;DR

We get an USB packet dump of an exchange with a card reader. We know the protocil (included PDF), need
to understand the packet dump and extract the PIN from it.

# Solution

## Parsing the USB capture file

```
$ tshark -r apdu.pcapng -T fields -e usb.capdata
```

## Analysing the USB payload

All of this is documented in the [specifications](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/forensics/what-is-a-pin/spec.pdf) (included in the challenge)

```
6f0b0000000055000000 00478100000002a400010e
                     CLA=00 INS=47(GENERATE ASYMMETRIC KEY PAIR) P1=81(read pubkey template) P2=00 Lc00....
80020000000055000000 6581
                     Memory failure?
6f050000000056000000 00ca007a00
                     CLA=00 INS=CA(GET DATA) P1=00(one byte) P2=0x7a(security support template) LC=00
80090000000056000000 7a0593030000019000
                     7A: security support template
                     05: len
                     93: 03 000001 (counts usage of compute signature command)
                     9000 STatus: OK
6f050000000057000000 00ca00c400
                     CLA=00 INS=CA(GET DATA) P1=00(one byte) P2=0xc4(PW status bytes) LC=00
80090000000057000000 ff
                     7f PW1 max len=127, UTF-or-derived (not PIN block format 2)
                     7f max len of reset code for PW1
                     7f max len and format of PW3 (same as for PW1)
                     03 error counter of PW1
                     00 error counter for RC
                     03 error counter for P3
                     90 00: STATUS OK
```
Here comes the PIN:
```
6f0b0000000058000000 0020008106263e764c7b54
                     CLA=00 INS=20(VERIFY) P1=00 P2=81(PW1) Lc=06 DATA=263e764c7b54  &>vL{T
```

## The flag

... so, flag is: `shc2024{&>vL{T}`. Took me a while to actually try it, it looked like garbage at first.

## Rest of the dump

Now, the rest of the dump just for completeness:
```
80020000000058000000 9000
                     SW1=90 SW2=00
6f5c0000000059000000 002a9e9a COMPUTE DIGITAL SIGNATURE
                     0000533051300d06096086480165030402030500044090cb2f4f5f4d25a6932fda313b50ab28b8d7a30c96fdd58017ea5888f305724b49e0f0bc248fedfaa0e9ff8a2565d30507e7e4cf12cdcc519e2d332f64aff9010200
80000000000059800100
80000000000059800100
80020200000059000100 aef50ad0d524ea4d06eadad77730729945169792fc05df816825daeab0b0c3bb2cc9abcee1d14c6108ce9dd9e535a22c836103e7c804af8aac555b0d173da49ce245be5f05fd5353a66fa96bb4672e9ce2313f558c6c18b84a777c65a88029a075910cb017bba8cd99ca024d98c8cc3407120ff921d70c76f513863a867892a1506259099566616b1346eb155a2dcee0c733ebdfa1cec6116480ab756ba684ad695a637f8b0a236caa9e7853f94c03dfd489625b2836bac243ed654d9946af773639d50d7206a37b709eeae352822af00617d78de19cad90c882143fe52215c1e56ad0606a803338f445b26dca46659884444c030097e368fa863d05a6a81c7442a3f3a6aa99dcee4db3133304f984a49f5fbc2a35c430b1296382b692c8af5d684bbaea677daf1bc476db2757ebe2a4e05dc6952f3050ce1cb813e3303cdffdb760427d1d1eb865b7fe8434b1a4b0e6fe609ae888f6d01c199753d861b13ff9a271ed217ca2759d359ad6a4a094cd44824ddeb6bdc6ecc2e288ea93ff3777f094901b2195f420c54cd2c375570f6987fadd76cf87e13cef6addfda0706273ef71911b3fba2bd52a54f20cec458db0f15ce9bf1865041b92a3518c47526a9b2d5fee05f99ba43b0b7e540abaafeb1f59a67b4314c8979999302afa7aafb1945dd6d83d7dad868aa5321d012022cad63bfbaf598bcf46e9d62a481659626667c59000
```

---

## `shc2024{&>vL{T}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
