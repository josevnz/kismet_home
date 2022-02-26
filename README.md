# kismet_home
Kismet home contains a group of scripts to help you secure your wireless home network.

## Installation

```shell
python3 -m venv ~/virtualenv/kismet_home
. ~/virtualenv/kismet_home/bin/activate
python -m pip install --upgrade pip
git clone git@github.com:josevnz/kismet_home.git
python setup.py bdist_wheel
pip install kismet_home-0.0.1-py3-none-any.whl
```

Then create a configuration file:

```shell
(kismet_home) [josevnz@dmaf5 kismet_home]$ kismet_home_config.py 
Please enter the URL of your Kismet server: http://raspberrypi.home:2501/
Please enter your API key: E41CAD466552810392D538FF8D43E2C5
[13:02:35] Added: server: url = http://raspberrypi.home:2501/                                                                                 config.py:44
           Added: server: api_key = E41CAD466552810392D538FF8D43E2C5                                                                          config.py:44
           Configuration file /home/josevnz/.config/kodegeek/kismet_home/config.ini written                                                   config.py:58 
```

