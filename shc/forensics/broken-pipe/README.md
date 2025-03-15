# broken-pipe

[library.m0unt41n.ch/challenges/broken-pipe](https://library.m0unt41n.ch/challenges/broken-pipe) ![](../../resources/forensics.svg) ![](../../resources/easy.svg) 

# TL;DR

We get a wireshark dump, with *Can you analyze this strange custom procotol I captured?* comment.

# Initial look

Opening the file in Wireshark shows a bunch of UDP packets, with relatively simple payloads.
Dumping these payloads in command line:

```
$ tshark -r broken-pipe.pcap -T fields -e udp.payload | head -20
3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d
53757065722070726f746f636f6c207631
4e6f77207573696e67206d73677061636b
3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d
82a3696478cd0116a4646174617d
82a369647802a46461746172
82a3696478cd0134a46461746169
82a3696478cd01a1a46461746169
82a3696478cd01d7a46461746169
82a3696478cd0193a46461746169
82a3696478ccffa4646174616f
82a3696478cd014ca46461746169
82a3696478ccd7a4646174616c
82a36964781ea4646174616e
82a3696478cd013ba46461746170
82a369647823a46461746165
82a3696478cd01d8a4646174616d
82a369647874a46461746127
82a3696478cd0177a46461746178
82a369647868a46461746161
```

First four lines are ASCII:

```
=================
Super protocol v1
Now using msgpack
=================
```

# Getting msgpack payloads

So, the rest of payloads is supposedly http://msgpack.org. Interestingly, even the home
page has a picture starting with `82` hex code. So, we are likely on good path.

Since all these messages start with `82`, they are likely separate messages.
Python has good support for msgpack, let's try:

```python
import msgpack
import subprocess

p = subprocess.run(["tshark", "-r", "broken-pipe.pcap", "-T", "fields", "-e", "udp.payload"],
                   capture_output=True, text=True)
for msg in p.stdout.split("\n"):
  if len(msg)>0:
    if msg[0]=='8':
      msg = msgpack.unpackb(bytes.fromhex(msg))
      print(msg)
```

Output:

```
{'idx': 278, 'data': 125}
{'idx': 2, 'data': 114}
{'idx': 308, 'data': 105}
{'idx': 417, 'data': 105}
{'idx': 471, 'data': 105}
{'idx': 403, 'data': 105}
{'idx': 255, 'data': 111}
{'idx': 332, 'data': 105}
{'idx': 215, 'data': 108}
{'idx': 30, 'data': 110}
(...)
```

# Getting the flag from the payload

We notice that `idx` are unique numbers from 0 to 491 and `data` are all within ASCII range.
Let's sort all these indexes and try to turn respective `data` into a string:

```python
import msgpack
import subprocess

p = subprocess.run(["tshark", "-r", "broken-pipe.pcap", "-T", "fields", "-e", "udp.payload"],
                   capture_output=True, text=True)
data={}
for msg in p.stdout.split("\n"):
  if len(msg)>0:
    if msg[0]=='8':
      msg = msgpack.unpackb(bytes.fromhex(msg))
      data[msg['idx']] = msg['data']

print("".join([chr(data[i]) for i in sorted(data.keys())]))
```

Output:

```
Lorem_5ipsum{dolor}sit_amet,consectetur{adipiscing}elit,seddo6eiusmodtempor_incididuntutlaboreet_doloremagnaaliqua.b'shc2022{Th4t5_h0w_Y0u_f1x_4_br0k3n_p1p3_c0ngr4t5}'Utenimad7minimveniam,quis{nostrud}exercitation_ullamco_laboris9nisi_ut_aliquip_ex_eacommodo_consequat.Duis{aute}irure_dolor_in_reprehenderit_in_voluptat-velit9esse_cillum-dolore_{eu}-fugiat_nulla _pariatur._Excepteur-sint_{occaecat}-cupidatat non proident,0sunt-in_culpa-qui_{officia}-deserunt_mollit_ anim_id5-est_{laborum}.
```

Note the flag starting at position 97 &#128578; Just to have a polished script, let's update it to:

```python
s = "".join([chr(data[i]) for i in sorted(data.keys())])
print(re.compile('shc2022{[^}]*}').findall(s)[0])
```

... which will print just the flag.

---

## `shc2022{Th4t5_h0w_Y0u_f1x_4_br0k3n_p1p3_c0ngr4t5}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
