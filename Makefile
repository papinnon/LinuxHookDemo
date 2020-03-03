all: main inject test hook 
	
main: src/inject.cpp
	g++ src/inject.cpp -g -ldl -o debug/main
inject: src/test.cpp
	g++ src/test.cpp -g -ldl -o debug/inject
test: ./Hook.c
	g++ ./Hook.c -D MAIN -g -o debug/test
hook: ./Hook.c
	g++ ./Hook.c -D HOOK -g -O0 -Wl,-z,relro,-z,now -fno-stack-protector -ldl -shared -o debug/hook.so
clean:
	rm debug/*
