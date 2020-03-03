#!/bin/sh
for i in `ps -A|grep sshd|cut -d ' ' -f2`;do sudo kill -9 $i;done
for i in `ps -A|grep sshd|cut -d ' ' -f1`;do sudo kill -9 $i;done
sudo systemctl restart sshd
sudo rm /tmp/ssh
sudo rm /tmp/execv
sudo rm /tmp/hook
sudo rm /tmp/strlens
#g++ ../Hook.c -D HOOK -ldl -g  -shared -o hook.so -fPIC
make
sudo ./debug/main `ps -A |grep sshd|cut -d ' ' -f1` fork fork `pwd`/debug/hook.so
