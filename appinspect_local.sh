
#!/bin/bash

#set -x

for app in $(ls dist/*.tgz); do

    echo -n "RUN: Please confirm submitting the app ${app} to appinspect vetting (yes / no) ?  "; read submit
    case ${submit} in
    y|yes|Yes)
        splunk-appinspect inspect ${app} --mode precert --included-tags cloud
        ;;
    n|no|No)
        echo "INFO: Operation completed for ${app} - thank you."
        ;;
    esac
done

exit 0