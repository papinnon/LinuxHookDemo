#ifdef MAIN
#include<stdio.h>
#include <unistd.h>
#include <string.h>
int  main()
{
	char * buf;
	buf = new char[0x10];
	memset(buf,0,0x10);
	while(1)
	{
		memcpy(buf, "Hello World", 0xb);
		printf("%s%d\n","Hello World",strlen(buf));
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

int printf_HOOOOOOOOOOOK(const char * format, ...)
{/*{{{*/
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

}/*}}}*/
#include "src/ptraceAPI.h"
#include "src/inject.h"
#include <signal.h>
typedef pid_t (*FORK)(void);
pid_t  fork(void)
{/*{{{*/
	pid_t child;
	FILE * logfile;
	char * buffer;
	char buf [20];
	const char * libName = "/home/elon/WorkPlace/memfuck/2020/Hook/debug/hook.so";
	void * handle = dlopen("libc.so.6",RTLD_LAZY);
       	FORK fnc = (FORK)dlsym(handle, "fork")	;

       	if(!fnc)
	      puts("Failed get Sym!\n");
      	child = fnc(); 
	if(child ==0)
	{
		kill(getpid(), SIGSTOP);
		return child;
	}
	//memset (buf, 0,20);
	//sprintf(buf, "%d fork :",getpid());
	//buffer = (char *) malloc(0x1000);
	//memset(buffer, 0,0x1000);
	//logfile = fopen("/tmp/ssh","a");
	//snprintf(buffer, 0x1000, "New Child:%d\n", child);
	//fwrite(buf, strlen(buf),1,logfile);
	//fwrite( buffer, strlen(buffer),1,logfile);
	//void * dlopen=find_symbol(child,"__libc_dlopen_mode","libc-2.30.so");
	//load_so(child, dlopen, LIBNAME);
	//
	//kill(getpid(), SIGSTOP);

	
	gothook(child , "fork", "fork", libName);
	gothook(child , "execv", "_Z10execv_hookPKcPPc", libName);
	kill(child,SIGCONT);
	return child;
}/*}}}*/

#define size_t int
typedef  size_t (*STRLEN)(const char *);
size_t strlenhook(const char *s)
{/*{{{*/
	FILE* fp;
	void * handle = dlopen("libc.so.6",RTLD_LAZY);
       	STRLEN fnc = (STRLEN)dlsym(handle, "strlen")	;
	puts("Hook");
	fp =fopen("/tmp/strlens","a");
	fwrite(s, strlen(s),1,fp);
	fwrite("\n",1,1,fp);
	fclose(fp);
	return fnc(s);
}/*}}}*/

#include <string>
extern  char ** environ ;
typedef int (*EXECV)(const char * , char *  [], char **);
int execv_hook(const char * pathname , char * argv[])
{/*{{{*/
	FILE * fp;
	void * hd= dlopen("libc-2.30.so",RTLD_LAZY);
	char buf [20];
	char buf2[200];
	const char * name="/home/elon/WorkPlace/memfuck/2020/Hook/debug/hook.so"; 
	pid_t cpid,tid;
	EXECV fnc = (EXECV )dlsym(hd, "execve");

	tid = fork();
	if(!tid)
	{
		cpid= getpid()+1;
		sleep(1);
		kill(cpid, SIGSTOP);

		void * loadaddr= (void*)(getLoadAddr(cpid)+0xcf348);
		procwrite(cpid, "F",loadaddr, 1);

		void * dlopen=find_symbol(cpid,"__libc_dlopen_mode","libc-2.30.so");
		void * dlerror=find_symbol(cpid,"dlerror","libdl-2.30.so");
		kill(cpid,SIGCONT);
		//load_so(cpid, dlopen , name);

		//load_sodbg(cpid, dlopen ,dlerror, name);
		exit(0);
	}
	
	return fnc(pathname, argv, environ);
}/*}}}*/

void __attribute((constructor)) con()
{
	//fp = fopen("/tmp/ssh","a");
	//memset(buf,0,0x100);
	//sprintf(buf, "%d loads this so\n", getpid());
	//fwrite(buf,strlen(buf),1,fp);
	//fclose(fp);
	//puts("shiiiiiiiiiiiiiiiiiiiit");
	return;
}
#endif
