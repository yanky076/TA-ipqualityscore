#!/usr/bin/env bash
# set -x

PWD=`pwd`
app="TA-ipqualityscore"
version=`grep 'version =' TA-ipqualityscore/default/app.conf | awk '{print $3}' | sed 's/\.//g'`

find . -name "*.pyc" -type f -exec rm -f {} \;
rm -f *.tgz
tar -czf ${app}_${version}.tgz --exclude=${app}/local --exclude=${app}/metadata/local.meta --exclude=${app}/lookups/lookup_file_backups ${app}
echo "Wrote: ${app}_${version}.tgz"

exit 0
