#!/bin/bash

platform='unknown'
unamestr=$(uname)
case $unamestr in
  "SunOs") echo "\033[31;1m SOLARIS is not yet supported, contact us to get support status or open a github issue\033[0m" ; exit 0;;
  "Darwin")  platform="mac" ;;
  "Linux")   platform="linux" ;;
  "FreeBSD")     echo "\033[31;1m BSD is not yet supported, contact us to get support status or open a github issue\033[0m" ; exit 0;; 
  "WindowsNT")    echo "\033[31;1m WINDOWS is not yet supported, contact us to get support status or open a github issue\033[0m" ; exit 0;; 
  *)        echo "\033[31;1m unknown: $OSTYPE is not yet supported, contact us to get support status or open a github issue\033[0m" ; exit 0;;  
esac
echo "\033[32;1m DETECTED OS - ${platform}\033[0m";
filename="cherrybomb_${platform}"
url=https://cherrybomb.blstsecurity.com/download_cherrybomb
c_t="Content-Type: application/json"
payload="{\"file\":\"${filename}\"}"
echo "\033[34;1m DOWNLOADING CHERRYBOMB\033[0m"
presigned=$(curl -s ${url} -H "${c_t}" -d $payload);
pre=$(echo "$presigned" | sed -e 's/^"//' -e 's/"$//');
c=$(curl -s ${pre} -o cherrybomb);
echo "\033[32;1m DONE DOWNLOADING\033[0m"
echo "\033[34;1m INSTALLING\033[0m"
mkdir ~/.cherrybomb 2> /dev/null
chmod +x cherrybomb;
sudo mv cherrybomb /usr/local/bin/
echo "\033[32;1m DONE INSTALLING RUN cherrybomb to test\033[0m"
