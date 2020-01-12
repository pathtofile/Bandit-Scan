# Bandit Scan (POC)
Use Bandit to scan all new and updated packages in Python

This script constatly monitors Python's PyPi repository for new packages and updates to packages.
It will then download these packages and scan them using [PyCQA's Bandit](https://github.com/PyCQA/bandit).

# Prerequisites
 - Python 3.7+
 - `Bandit` instaled on the commandline
 - `requests` package

# TODO
Cleanup, make real packages with an entrypoint
