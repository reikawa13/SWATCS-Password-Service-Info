# PasswordService

![Tests Status](ims/tests-badge.svg)
![Coverage](ims/coverage-badge.svg)

Our new [CS self-service password app](https://password.cs.swarthmore.edu/), 
written with python and [flask](https://flask.palletsprojects.com/en/2.0.x/).

![app login screen](ims/login.png)

## About

This is a [flask](https://flask.palletsprojects.com/en/2.0.x/) web app to allow our users to:
 - reset their own password
 - change their login shell 
 - change their gecos information (their DisplayName)
Additionally, special users with admin priviledges 
can reset passwords for *other* users and see logging info on how the
service is being used. 

All user information is stored in an 
[LDAP server](https://jeffknerr.github.io/ldap/linux/debian/ubuntu/2021/04/28/ldap-for-small-department.html).
First-time users are shown a "user agreement form"
that they have to read and agree to *before* setting their 
initial account password.

**All of this is based on 
Miguel Grinberg's *awesome*
[Flask Mega-Tutorial](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world).**
Miguel's tutorial covers logging in users, password security, resetting passwords,
database models, and a whole lot more. The main difference is we don't need user
blog posts, and our user data is stored in an LDAP server.
Our app talks to the LDAP server using the 
[FlaskLDAP3Login extension](https://flask-ldap3-login.readthedocs.io/en/latest/).

This web app was written by 
[Jeff Knerr](https://jeffknerr.github.io/)
and 
[Emma Jin](https://github.com/EmmaJin0210)
during the summer
of 2020 (during a global pandemic!). We have been using it for our department
ever since. This has been *very* useful while many of our students are now
studying from remote locations.

Here are two screenshots showing the admin home screen (with extra menu bar options)
and the "Change Shell" screen:

![app home screen](ims/home.png "home screen for admin user")

![app change shell screen](ims/shell.png "change shell options for user")

## Details

- users can either login (if they know their password) and change certain things:
  their current password, their shell, their display name (e.g., Jeff instead of Jeffrey)
- or they can request a password reset email if they have forgotten their current password
- if resetting their password, they will get an email with a link sent to their
  campus email address (which is stored in the LDAP server)
- clicking on the link in the email will take them to a route in the app that
  allows them (assuming they have the correct token) to pick a new password
- when entering passwords, users are required to satisfy certain strength requirements
- password strength is shown using a 
  [python implementation of zxcvbn](https://github.com/dwolfhub/zxcvbn-python)
- all actions (changing password, requesting password reset, admin resetting a
  user's password, changing shell, etc) are logged
- admin users can see logging info in the app
- admin users can change/set a password for another user (in case the user
  is having trouble with the password reset email or something else)
- users are shown their "Last Login", and that information is stored in LDAP
  using a custom LDAP attribute
- new accounts, having a special "Last Login" date (1970), are required to view
  and accept a "user agreement form" before being allowed to set their password
- we use [flask-limiter](https://flask-limiter.readthedocs.io/en/stable/) to limit 
  brute-force attempts on certain routes (e.g., login attempts per day, password
  reset emails per hour, etc)

TODO:
x how to unit test???
- full code review/clean up the code!
- make sure all local stuff is in .env file
- change branch master to main 
- make sure non-ascii chars work for DisplayNames?

## Development Setup

    git clone git@github.swarthmore.edu:CS-Sysadmins/PasswordService
    cd PasswordService
    python3 -m venv venv
    source venv/bin/activate       (or activate.fish)
    pip install flask
    pip install -r requirements.txt
    pip install flask-ldap3-login

Also need an `.env` file with things like these in it (see `config.py`):

    SECRET_KEY = 'your-secret-key'
    MAIL_SERVER = yourmailserver.example.com
    ADMINS = ["admin1@yourmailserver.example.com","admin2@yourmailserver.example.com"]
    LDAP_DC = "dc=yourdomain,dc=example,dc=com"
    LDAP_HOST = "yourldapserver.example.com"
    LDAP_ADMIN = "yourldapadminaccount"
    LDAP_PW = "your ldap admin acct password"
    LDAP_ATTR = ["objectClass", "uid", "sn", "givenName", "cn", "otherAttributes"]

And obviously you need an 
[LDAP server](https://jeffknerr.github.io/ldap/linux/debian/ubuntu/2021/04/28/ldap-for-small-department.html).
Better if you have two, one for testing and one for production. :)

## NEW Dev Setup Using Vagrant

I wrote some vagrant/ansible stuff to create a dummy virtual machine
that has a working ldap server. You can now use this server for testing,
instead of using your real ldap server.

The development ldap server should have three accounts:

- admin1:we love ldap
- user1:we love ldap
- user2:we love ldap

The `admin1` account should be in the `pwapp` group and have extra permissions
(i.e., be able to see/use the ResetUserPassword and Logs tabs).

Here's how to create and use the development ldap server:

- see Jeff's [ldapexample](https://github.com/jeffknerr/ldapexample) repo to set up ansible and vagrant
- create the vagrant ldap server:
```
cd ldapvg
vagrant up
ping 192.168.56.6
ansible ldap -a date
ansible-playbook  ldap.yml
vagrant ssh ldap
sudo slapcat
exit
```
- fix your workstation's `ldap.conf` file (set to never):
```
$ grep REQ /etc/ldap/ldap.conf
TLS_REQCERT     never
```
- run the unit tests (assuming you did above stuff to set up venv):
```
source venv/bin/activate
(venv) python -m pytest -v
======================== test session starts ===============================================
tests/functional/test_auth.py::test_log_in_as_user PASSED               [ 25%]
tests/functional/test_auth.py::test_logged_in_tabs PASSED               [ 50%]
tests/functional/test_auth.py::test_NOT_logged_in_tabs PASSED           [ 75%]
tests/functional/test_auth.py::test_pwapp_group PASSED                  [100%]
...
```

## Production Setup

- set up PasswordService server VM using kvm, running Debian Buster
- install nginx, webhook, supervisor, python3-venv, mariadb-server (see Miguel's [Deployment on Linux](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-xvii-deployment-on-linux) page for good details)
- add [certbot/letsencrypt](https://certbot.eff.org/) to PasswordService VM so web server uses https
  (install certbot and python3-certbot-nginx)
- set up PasswordService git repo to auto-deploy to the VM (see 
  [webhook documentation](https://github.com/adnanh/webhook) and info below)
- install gunicorn into the PasswordService venv
- configure the mariadb
- set up nginx to handle website requests (send to gunicorn) and webhook requests (send to webhook)
- set up an [LDAP server](https://jeffknerr.github.io/ldap/linux/debian/ubuntu/2021/04/28/ldap-for-small-department.html)


## mariadb

Here's how to test some of this manually...

```
$ whoami     # pwa?
$ git clone git@github.swarthmore.edu:CS-Sysadmins/PasswordService.git
$ cd PasswordService
$ python3 -m venv venv
$ source venv/bin/activate
(venv) $ pip install -r requirements.txt
(venv) $ pip install gunicorn pymysql cryptography
(venv) $ vim .env
 SECRET_KEY=whateveryouwant
 MAIL_SERVER=localhost
 MAIL_PORT=25
 DATABASE_URL=mysql+pymysql://PasswordService:dbpassword@localhost:3306/PasswordService
 (probably need some LDAP vars here...)
$ sudo mysql -u root
mysql> create database PasswordService character set utf8 collate utf8_bin;
mysql> create user 'pwa'@'localhost' identified by 'dbpassword';
mysql> grant all privileges on PasswordService.* to 'pwa'@'localhost';
mysql> flush privileges;
mysql> quit;
(venv) $ flask db upgrade
(venv) $ gunicorn -b localhost:8000 -w 4 PasswordService:app
```

## auto-deploy

- use pwa (password account) ssh key as deploy key in github (i.e., set up 
  and account that can "git pull" from github with an empty ssh passphrase)
- on PasswordService server, need: nginx, webhook, supervisor, gunicorn
- for webhook, set up hooks.json file (with secret, id, command, etc)
- set up the webhook deploy script (to actually do the pull, deploy)
- set up deployLocal script (called by webhook deploy to rsync certain files to `/var/www/wherever`)
- set up github webhook with secret (with correct payload url)
- set up nginx to send any url with /hooks/ to localhost port 9000
- set up supervisor to start webhook on localhost port 9000
- add staff/sudoers stuff to allow supervisorctl restart of PasswordService
- add chmod/chown info to /etc/supervisor/supervisord.conf
    [unix_http_server]
    file=/var/run/supervisor.sock
    chmod=0770                  
    chown=root:staff
- try it a million times, make sure it works :)

Below are some config file snippets to help.

For `nginx`, we set it to:
 - use/forward to https (443)
 - forward urls that start with `/hooks` to webhook server (9000)
 - forward everything else (this is the only web app running on this
   server) to gunicorn server (8000)

```bash
$ cat /etc/nginx/sites-enabled/pwapp
server {
    listen 80;
    server_name password.cs.swarthmore.edu;
    #root /var/www/html;
# needed for letsencrypt
    location ~ /.well-known {
        #root /path/to/letsencrypt/verification/directory;
        root /var/www/le;
    }
# redirect any requests to the same URL but on https
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name password.cs.swarthmore.edu; # managed by Certbot

    ssl_certificate /etc/letsencrypt/live/password.cs.swarthmore.edu/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/password.cs.swarthmore.edu/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    ssl_session_cache shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;
    add_header Strict-Transport-Security max-age=15768000;

    # write access and error logs to /var/log
    access_log /var/log/PasswordService_access.log;
    error_log /var/log/PasswordService_error.log;

    # forward webhook requests to local webhooks server
    location /hooks/ {
        proxy_pass http://127.0.0.1:9000/hooks/;
    }

    location / {
        # forward application requests to the gunicorn server
        proxy_pass http://127.0.0.1:8000;
        proxy_redirect off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

We use `supervisord` to run both the webhook and the PasswordService/gunicorn:

```bash
$ cat /etc/supervisor/conf.d/webhook.conf
[program:webhook]
command=/usr/bin/webhook -hooks hooks.json -verbose -port 9000
directory=/home/pwa/hooks
user=pwa
autostart=true
autorestart=true
stopasgroup=true
killasgroup=true

$ cat /etc/supervisor/conf.d/PasswordService.conf
[program:PasswordService]
command=/var/www/PasswordService/venv/bin/gunicorn -b 127.0.0.1:8000 -w 2 PasswordService:app
directory=/var/www/PasswordService
user=pwa
autostart=true
autorestart=true
stopasgroup=true
killasgroup=true
```

And here are the two *deploy* scripts and the `hooks.json` file for webhook
(where everything is run from our *pwa* user):

```bash
$ cat /home/pwa/hooks/hooks.json

[
  {
    "id": "deploy-app",
    "execute-command": "/home/pwa/scripts/deploy.sh",
    "command-working-directory": "/home/pwa/scripts",
    "pass-arguments-to-command":
    [
      {
        "source": "payload",
        "name": "head_commit.message"
      },
      {
        "source": "payload",
        "name": "pusher.name"
      },
      {
        "source": "payload",
        "name": "head_commit.id"
      }
    ],
    "trigger-rule":
    {
      "and":
      [
        {
          "match":
          {
            "type": "payload-hash-sha1",
            "secret": "your-secret-here",
            "parameter":
            {
              "source": "header",
              "name": "X-Hub-Signature"
            }
          }
        },
        {
          "match":
          {
            "type": "value",
            "value": "refs/heads/master",
            "parameter":
            {
              "source": "payload",
              "name": "ref"
            }
          }
        }
      ]
    }
  }
]
```

```bash
$ cat /home/pwa/scripts/deploy.sh
#! /bin/bash -e

PREFIX=/usr/swat/tmp
GHRDIR=${PREFIX}/PasswordService
REPO=git@github.swarthmore.edu:CS-Sysadmins/PasswordService.git
TMPFILE=${PREFIX}/PSdebug.txt
DEPLOY=/home/pwa/scripts/deployLocal

D=`date`
touch $TMPFILE
echo "---------------------------------" >> $TMPFILE
echo $D >> $TMPFILE
echo "---------------------------------" >> $TMPFILE

function cleanup {
     echo "Error occurred"
     # !!Placeholder for Slack notification
}
trap cleanup ERR

commit_message=$1   # head_commit.message
pusher_name=$2      # pusher.name
commit_id=$3        # head_commit.id

# if it doesn't exist, clone it
if [ ! -e $GHRDIR ] ; then
   cd $PREFIX
   git clone $REPO >> $TMPFILE 2>&1
else
   cd $GHRDIR
   git reset --hard HEAD >> $TMPFILE 2>&1
   git pull origin master >> $TMPFILE 2>&1
fi

echo "---------------------------------" >> $TMPFILE
echo "---------------------------------" >> $TMPFILE
$DEPLOY >> $TMPFILE
echo "---------------------------------" >> $TMPFILE
echo "---------------------------------" >> $TMPFILE
```

```bash
$ cat /home/pwa/scripts/deployLocal
#!/bin/bash

# deploy from /usr/swat to /var/www
# J. Knerr -- Summer 2020

umask 0022

HN=`/bin/hostname -f`
if [ $HN != "password.cs.swarthmore.edu" ] ; then
  echo "not on password???"
  exit 1
fi

NAME=PasswordService
PREFIX=/usr/swat/tmp
REPO=${PREFIX}/$NAME
WHERE=/var/www

if [ -d $REPO ] ; then
  cd $REPO
else
  echo "no $REPO directory???"
  exit 1
fi

# stop
supervisorctl stop $NAME

# copy files
rsync -aq --delete --exclude-from ${REPO}/sync-exclude ${REPO} $WHERE

# check for venv file
# make if it doesn't exist
if [ ! -d ${WHERE}/${NAME}/venv ] ; then
  cd ${WHERE}/${NAME}
  python3 -m venv venv
  # must be bash for source to work...
  source ./venv/bin/activate
  pip install -r ${REPO}/requirements.txt
  pip install gunicorn
  deactivate
fi

# check for .env file, cp in if it doesn't exist
if [ ! -e ${WHERE}/${NAME}/.env ] ; then
  cd ${WHERE}/${NAME}
  cp /home/pwa/.env .
fi

# apply db upgrades, if any
cd ${WHERE}/${NAME}
source ./venv/bin/activate
flask db upgrade
deactivate

# restart
supervisorctl start $NAME
```

## testing and coverage


### running unit tests

```
# pytest
python -m pytest
# pytest with verbosity
python -m pytest -v
# if you need to see print() output
python -m pytest -v -s
# just run specific tests
python -m pytest tests/unit
python -m pytest tests/functional
# look at coverage
python -m pytest --cov=app
```

### generate badges

```
python -m pytest
coverage run -m pytest
coverage report -m
python -m pytest --junitxml=reports/junit/junit.xml
genbadge tests -o ./badges/tests-badge.svg
coverage xml
genbadge coverage -i ./coverage.xml -o ./badges/coverage-badge.svg
cp badges/* ims
```

## reset a password

```
$ cd ldapvg
$ vg ssh ldap
Last login: ...
vagrant@pw-ldap:~$ sudo ldapsetpasswd user1
Changing password for user uid=user1,ou=people,dc=test
New Password:
Retype New Password:
Successfully set password for user uid=user1,ou=people,dc=test
vagrant@pw-ldap:~$
```
