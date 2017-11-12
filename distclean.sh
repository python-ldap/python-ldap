#!/bin/sh

python setup.py clean
rm -r MANIFEST dist/* build/* Lib/*.egg-info .tox 
rm Lib/_ldap.so Lib/*.py? Lib/ldap/*.py? Lib/ldap/*/*.py? Tests/*.py? *.py?
