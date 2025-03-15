# cheated-results

[library.m0unt41n.ch/challenges/cheated-results](https://library.m0unt41n.ch/challenges/cheated-results) ![](../../resources/misc.svg) ![](../../resources/medium.svg) 

# TL;DR

We are given an XLSX file which has per-person accounting data of printer usage.
That data was supposedly tampered with, we need to discover which parts.

# Excel forensics

Google: [excel forensics "calcChain.xml"](https://www.google.com/search?q=excel+forensics+%22calcChain.xml%22)

Example: [https://office-watch.com/2023/how-excels-hidden-calcchain-can-catch-data-cheats](https://office-watch.com/2023/how-excels-hidden-calcchain-can-catch-data-cheats)

## Extract calcChain.xml

```
unzip -j print-results.xlsx xl/calcChain.xml
```

## Analyze

Looking at `calcChain.xml`, we see a nice ordered list of fields, but, with some disturbances:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<calcChain xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <c r="D5" i="1" l="1"/>
  <c r="D6" i="1"/>
  <c r="D7" i="1"/>
  (…)
  <c r="D22" i="1"/>
  <c r="D158" i="1"/>   <===
  <c r="D24" i="1"/>
  (…)
  <c r="D97" i="1"/>
  <c r="D155" i="1"/>   <===
  <c r="D152" i="1"/>   <===
  <c r="D100" i="1"/>
  (…)
  <c r="D148" i="1"/>
  <c r="D149" i="1"/>
  <c r="D99" i="1"/>
  <c r="D153" i="1"/>
  <c r="D154" i="1"/>
  <c r="D98" i="1"/>
  <c r="D156" i="1"/>
  <c r="D157" i="1"/>
  <c r="D23" i="1"/>
</calcChain>

```

Which means that:

- `D23` (Carol Hughes) was `D158`
- `D98` (Benjamin Patterson) was `D155`
- `D99` (Michelle Price) was `D152`

# Construct the flag

Per task description:

> The flag is the list of people that have been falsley accused of printing, in
> the order they would have appeared in the original document, separated by a
> dash.

Therefore:

---

## `shc2024{Michelle Price-Benjamin Patterson-Carol Hughes}`




<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
