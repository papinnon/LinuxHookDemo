#include <stdio.h>
#include <dlfcn.h>
#include <signal.h>
#include <unistd.h>
typedef  size_t (*STRLEN)(const char *);
size_t strlen(const char *s)
{/*{{{*/
	kill(getpid(),SIGSTOP);
	FILE* fp;
	void * handle = dlopen("libc.so.6",RTLD_LAZY);
       	STRLEN fnc = (STRLEN)dlsym(handle, "__strlen_avx2")	;

	fp =fopen("/tmp/strlens","a");
	fwrite(s, strlen(s),1,fp);
	fwrite("\n",1,1,fp);
	fclose(fp);
	return fnc(s);
}/*}}}*/

