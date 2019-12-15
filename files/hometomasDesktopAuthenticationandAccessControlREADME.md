# Authentication-and-Access-Control

## Installation:

    $ virtualenv -p python3 venv

    $ source ./venv/bin/activate

    $ pip3 install -r requirements.txt


## Usage:

    $ source ./venv/bin/activate

    $ python server.py

    $ python client.py


## CheatSheet:

### Create client certificates:

	$ openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout client.key -out client.crt

### Create server certificates:

	$ openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout server.key -out server.crt
