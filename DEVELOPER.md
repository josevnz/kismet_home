# Installation

## First create your virtual environment
```shell
python3 -m venv ~/virtualenv/kismet_home
. ~/virtualenv/kismet_home/bin/activate
python -m pip install --upgrade pip
```

## Then clone the code from GitHub:

```shell
git clone git@github.com:josevnz/kismet_home.git
```

After that compile your wheel and install it

```shell
python setup.py bdist_wheel
pip install kismet_home-0.0.1-py3-none-any.whl
```

## Working with developer mode

Or deploy it in 'developer' mode

```shell
python setup.py develop
```

## pip-audit

I also try to check this code for third party vulnerabilities

```shell
# Example session
(kismet_home) [josevnz@dmaf5 kismet_home]$ pip-audit  --requirement requirements.txt 
No known vulnerabilities found  
```

If you find any, please report it as an [issue](https://github.com/josevnz/kismet_home/issues) 

## Unit tests

Yes, you can run the unit tests from the command line

```shell
(kismet_home) [josevnz@dmaf5 kismet_home]$ python -m unittest test/unit_test_config.py 
.
----------------------------------------------------------------------
Ran 1 test in 0.000s

OK

(kismet_home) [josevnz@dmaf5 kismet_home]$ python -m unittest /home/josevnz/kismet_home/test/test_integration_kismet.py 
[09:13:05] DEBUG    Starting new HTTP connection (1): raspberrypi.home:2501                                                                                                                                                        connectionpool.py:228
           DEBUG    http://raspberrypi.home:2501 "GET /session/check_session HTTP/1.1" 200 None                                                                                                                                    connectionpool.py:456
.           DEBUG    Starting new HTTP connection (1): raspberrypi.home:2501                                                                                                                                                        connectionpool.py:228
           DEBUG    http://raspberrypi.home:2501 "GET /system/status.json HTTP/1.1" 200 None                                                                                                                                       connectionpool.py:456
.           DEBUG    Starting new HTTP connection (1): raspberrypi.home:2501                                                                                                                                                        connectionpool.py:228
           DEBUG    http://raspberrypi.home:2501 "GET /alerts/definitions.json HTTP/1.1" 200 None                                                                                                                                  connectionpool.py:456
.[09:13:05] 'ADMIN_SESSION_API' environment variable not defined. Skipping this test                                                                                                                                       test_integration_kismet.py:105
....
----------------------------------------------------------------------
Ran 7 tests in 0.053s

OK
```

To run the integration tests, you need a working installation of Kismet running with an API key.

