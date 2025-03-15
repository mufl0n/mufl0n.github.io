# memedump

[library.m0unt41n.ch/challenges/memedump](https://library.m0unt41n.ch/challenges/memedump) ![](../../resources/forensics.svg) ![](../../resources/medium.svg) 

We get a zipped Windows memory dump and a `Hint: MemProcFS`.
Which, indeed, is much more convenient than Volatility &#128578;

```bash
$ memprocfs -device memedump.raw -mount /tmp/mnt -forensic 1
```

Interesting files are in `forensic/files/ROOT/Users/xthé418/Downloads/memes`,
in particular:

![](what-no-pwease.jpg "")

Slightly cleaning up the QR code into a 33x33 PNG and 
[decoding it with CyberChef](https://gchq.github.io/CyberChef/#recipe=Parse_QR_Code(false)&input=iVBORw0KGgoAAAANSUhEUgAAACEAAAAhCAMAAABgOjJdAAABfmlDQ1BJQ0MgcHJvZmlsZQAAKJF9kTlIA1EURc9MDIoLFkkhYjFFtDKFC2KpUQhChBAVkmjhLGaBzCTMJNikFGwDFi6NUQsba20tbAVBcAGxF6wUbURGfhJIEONr/uH%2Bdx//3Q9yNaebTscMmFbRjoVDSjyRVDpfkPDRg5cxVXcKs9FohLb1eYckztugmNW%2B78/qMzYcHSQFmNELdhGkdWBqs1gQvAf49YxqgHQGjNrxRBKkB6FrdX4VnK6xLGb67eXYHMh%2BQEm3sNbCesY2QZ4EAoZpGSDH62wILgs2cyW98U6xYe%2BGtbIkdGCIMAssEkVBo0SWHEWCZLFQcIgRJtTGP1jzRymhkSOLjsI8eUzUmh/xB7%2BzdVIT4/VJvSHwPrvu%2BzB07sB3xXW/jlz3%2Bxg8T3BpNf35Kkx/gKfS1AKH0L8F51dNTduFi20YeCyotlqTPICcSsHbKfQlwHcD3av13Br3nNzDchki17B/ACNp6F9rs3dXa27/9jTy%2BwF0Y3Kn91IVbQAAAAZQTFRFAAAA////pdmf3QAAAAlwSFlzAAAPYQAAD2EBqD%2BnaQAAAAd0SU1FB%2BkBEwsKLqg/O48AAADaSURBVDjLbVMJDsMwCLP//%2BmpDfhIt2hqC4T4IMD5kcQsTgBwjso9y5H3CZz/RE/s1MHZ/Dr9OadWxWlQOJSdjJvdOKb1n5VUFnQhdXwx7jYG84lR7C6k9E7zMVIsuYKSOCBBW5nEoXOwErZikK6L6qOYuBT%2BSw/j0GvrMQeJ7qUHpl0699HDfT0zqcfwmTY3M%2BmxO8Gg4Un2loU1526xR0sOUQQIBEjrs5YiMBHp6%2BofVqHnlHKsLo18upPbLC2NobSVrjAeYQSqwm1sFNA3rPWoiYubizLrWT%2BO1QIZ%2B6hZUgAAAABJRU5ErkJggg)
returns the flag.

---

## `stairctf{m3m3dump_g0_brrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
