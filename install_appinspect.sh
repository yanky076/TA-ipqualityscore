
#!/bin/bash

#set -x

VIRTUAL_ENV_PATH=venv

# activateing virtual enviornment
source ${VIRTUAL_ENV_PATH}/bin/activate

# Installing dependencies
sudo apt-get update
sudo apt-get install -y libxml2-dev libxslt-dev lib32z1-dev python-lxml

# Downloading installation package
cd /tmp
sudo wget https://download.splunk.com/misc/appinspect/splunk-appinspect-latest.tar.gz
pip3 install --upgrade pip
pip3 install splunk-appinspect-latest.tar.gz
rm -f /tmp/splunk-appinspect-latest.tar.gz

# Validating install
cd ~
splunk-appinspect --help

exit 0