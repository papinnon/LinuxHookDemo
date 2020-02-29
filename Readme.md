# Linux library call hooking

编译：

```Complile:
$ g++   -std=c++2a ./src/inject.cpp  -o main
```

测试：

```test

$ gcc -D HOOK -shared ./Hook.c -o hook.so
$ gcc -D MAIN ./Hook.c -o test
$ ./test
$ sudo ./main `ps -A|grep test|cut -d ' ' -f1` printf printf `pwd`/hook.so
```

Usage:

```$ sudo ./main [target pid]  [Import Function Name(origin)]  [Hook Function Name(hook)]  [Path/to/Library/Injected]  ``` 