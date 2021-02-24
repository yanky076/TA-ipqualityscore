#!/usr/bin/env bash
# set -x

sh ./fix_permissions.sh 

PWD=`pwd`
app="TA-ipqualityscore"
version=`grep 'version =' TA-ipqualityscore/default/app.conf | awk '{print $3}' | sed 's/\.//g'`

find . -name "*.pyc" -type f -exec rm -f {} \;
rm -f *.tgz
tar -czf dist/${app}_${version}.tgz --exclude=${app}/bin/splunklib --exclude=${app}/local --exclude=${app}/metadata/local.meta --exclude=${app}/lookups/lookup_file_backups ${app}
echo "Wrote: dist/${app}_${version}.tgz"

exit 0
