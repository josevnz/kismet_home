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
```

To run the integration tests, you need a working installation of Kismet running with a API key.

