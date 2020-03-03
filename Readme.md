# Linux library call hooking

编译：

```Complile:
make
```

测试：

```test

$ ./debug/test
$ sudo ./debug/main `ps -A|grep test|cut -d ' ' -f1` printf printf `pwd`/debug/hook.so //Runtime Hook
$ sudo ./debug/inject `ps -A|grep test|cut -d ' ' -f 1` `pwd`/debug/hook.so //So Injection
```

Usage:

```
$ sudo ./debug/main [target pid]  [Import Function Name(origin)]  [Hook Function Name(hook)]  [Path/to/Library/Injected]  
$ sudo ./debug/inject [target pid]    [Path/to/Library/Injected]  
``` 
