#ifdef MAIN
#include<stdio.h>
#include <unistd.h>
int volatile main()
{
	while(1)
	{
		printf("%s%d\n","Hello World",1);
		sleep(3);
	}
	return 0;
}
#endif
#ifdef HOOK
#include <stdarg.h>
#include <stdio.h>
#include <dlfcn.h>
typedef int(*PRINTF)(const char * ,...);
#include <string.h>

#define MaxArgCount 8
typedef struct{
	long long int t;
	void * ptr[MaxArgCount];
}list;

#include <stdarg.h>
#define ARG(plst) plst->ptr[0], plst->ptr[1], plst->ptr[2], plst->ptr[3],plst->ptr[4], plst->ptr[5], plst->ptr[6], plst->ptr[7] 
#define getlist(arg) ((list *)*(void**)((char*)&arg+16)) //return list *
//Usage :
// va_list args;
// va_start(args, TYPE);
// list * plst= getlist(args);
// func(t1 a1, t2 a2, ARG(plst)); == func(t1 a1, t2 a2, ...)
// va_end(args);

int printf(const char * format, ...)
{
	va_list args;
	char * stack[8];
	void * handle =dlopen("libc.so.6",RTLD_LAZY);
	PRINTF fnc = (PRINTF)dlsym(handle, "printf");
	if(!fnc)
		puts("Failed get sym");
	fnc("Hey, Fuck YOU!\n");
	va_start(args, format);
	list * plst = getlist(args);
	int ret =fnc(format, plst->ptr[0], plst->ptr[1], plst->ptr[2]);	
	va_end(args);
	return ret;

}
void __attribute((constructor)) con()
{
	puts("shiiiiiiiiiiiiiiiiiiiit");
	return;
}
#endif
