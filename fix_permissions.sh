#!/usr/bin/env bash
# set -x

find . -type d -exec chmod 755 {} \;
find . -type f -name *conf -exec chmod 644 {} \;
find TA-ipqualityscore/lib/ -type f -exec chmod 644 {} \;
find TA-ipqualityscore/bin/ -type f -exec chmod 755 {} \;