#ifndef PTRACEAPI_H
#define PTRACEAPI_H


#include <elf.h>
#include <sys/ptrace.h>
#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>


static pid_t g_pid;
#define MaxPidLength 0x100
static uint64_t getLoadAddr(pid_t pid)
{/*{{{*/
	const char * fmt = "/proc/%lu/maps";
	char  path[MaxPidLength];
	FILE * fp;
	uint64_t result,trash;
	usleep(100);
	memset(path,0 ,MaxPidLength);
	snprintf(path, 0x100, fmt, (unsigned long )pid);
	if( (fp = fopen(path, "r")) == NULL)
	{
		puts("Error open file");
		exit(1);
	}	
	fscanf(fp, "%lx-",&result );
	fclose(fp);
	return result;
}/*}}}*/

#include "./string_handling.h"
static uint64_t getlibAddr(pid_t pid, const char * libName)
{/*{{{*/
	const char * fmt = "/proc/%ld/maps";
	char * fmt2 =0;
	char  path[MaxPidLength];
	FILE * fp;
	uint64_t result,size;
	char * buffer, *interator , *leftover, * garbage;
	char search[] = "%lx-%lx r--p %s %s";
	memset(path,0 ,MaxPidLength);
	snprintf(path, 0x100, fmt, pid);
	// Open file read all in buffer
	if( (fp = fopen(path, "r")) == NULL)
	{
		puts("Error open file");
		exit(1);
	}	
	if((buffer= (char *)malloc(0x20000))== 0)
	{
		puts("getlibAddr: malloc Error");
		exit(1);
	}	
	garbage = (char *)malloc(0x2000);
	fread(buffer, 0x20000, 1 , fp);
	interator= buffer;
	result =0;
	while((interator = split(interator,'\n', &leftover))!= NPOS)
	{
		char tmp[7];
		if(!strstr(leftover, libName))
		{
			free(leftover);
			continue;
		}
		sscanf(leftover, search, &result, garbage,garbage+0x100,tmp);
		free(leftover);
		break;
	}
	free(garbage);
	free(buffer);
	fclose(fp);
	return result;
}/*}}}*/

int ptrace_attach(pid_t pid, int boolean)
{/*{{{*/
	switch(boolean){
		case(0):
		if(-1== ptrace(PTRACE_DETACH, pid, NULL, NULL))
		{
		puts("Error DEAttach pid");
		exit(1);
		}
		g_pid = 0;
		break;
		case(1):
		if(-1== ptrace(PTRACE_ATTACH, pid, NULL, NULL))
		{
		puts("Error Attach pid");
		exit(1);
		}
		g_pid = pid;
		default:
			return 0;
	}
	return 0;
}/*}}}*/

#include <sys/user.h> // for struct user_xxregs_struct
#include <errno.h>
typedef  struct user_fpregs_struct  fpregs;
typedef  struct user_regs_struct regs;
int ptrace_getregs(pid_t pid, regs * user_regs, fpregs* user_fpregs)
{/*{{{*/
	pid_t tarpid;
	if(pid == 0)
		tarpid= g_pid;
	else
		tarpid= pid;
	if(user_regs)
		if(   -1== ptrace(PTRACE_GETREGS, tarpid, NULL, (void *)user_regs ))
		{
			puts("Error PTRACE_GETREGS");
			perror("ptrace");
			exit(1);
		}
	if(user_fpregs)
		if(-1== ptrace(PTRACE_GETFPREGS, tarpid, NULL, (void *)user_fpregs))
		{
			puts("Error PTRACE_GETFPREGS");
			perror("ptrace");
			exit(1);
		}
	return 0;
}/*}}}*/

int ptrace_setregs(pid_t pid, regs * user_regs, fpregs* user_fpregs)
{/*{{{*/
	pid_t tarpid;
	if(pid == 0)
		tarpid= g_pid;
	else
		tarpid= pid;
	if(user_regs)
		if(   -1== ptrace(PTRACE_SETREGS, tarpid, NULL, (void *)user_regs ))
		{
			puts("Error PTRACE_GETREGS");
			perror("ptrace");
			exit(1);
		}
	if(user_fpregs)
		if(-1== ptrace(PTRACE_SETFPREGS, tarpid, NULL, (void *)user_fpregs))
		{
			puts("Error PTRACE_SETFPREGS");
			perror("ptrace");
			exit(1);
		}
	return 0;

}/*}}}*/


int procread(pid_t pid, void * buffer, void * addr,int size)
{/*{{{*/
	const char * fmt = "/proc/%lu/mem";
	char  path[MaxPidLength];
	FILE* fp;
	memset(path,0 ,MaxPidLength);
	snprintf(path, 0x100, fmt, (unsigned long )pid);
	if( (fp = fopen(path, "r")) == NULL)
	{
		puts("Error open file");
		exit(1);
	}	
	fseek(fp, (uint64_t)addr, SEEK_SET);
	int n = fread(buffer,1, size, fp);
	if(n == -1 )
	{
		perror("fread");
		exit(1);
	}
	fclose(fp);
	return n;
}/*}}}*/

int procwrite(pid_t pid, const void * buffer, const void * addr,int size)
{/*{{{*/
	const char * fmt = "/proc/%lu/mem";
	char  path[MaxPidLength];
	FILE* fp;
	memset(path,0 ,MaxPidLength);
	snprintf(path, 0x100, fmt, (unsigned long )pid);
	if( (fp = fopen(path, "w")) == NULL)
	{
		puts("Error open file");
		exit(1);
	}	
	fseek(fp, (uint64_t)addr, SEEK_SET);
	int n = fwrite(buffer,1, size, fp);
	if(n == 0 )
	{
		perror("fwrite");
		exit(1);
	}
	fclose(fp);
	return n;
}/*}}}*/

#ifdef ISCPP
#include "hexdump.h"
#include <iostream>
int main(int argc, char * argv[])
{/*{{{*/
	regs ureg;
	pid_t pid = atoi(argv[1]);
	std::cout <<std::hex<<	getLoadAddr(1951242) <<std::endl;
	ptrace_attach(pid, 1);
	const char * data = "XXPORNHUB";
	unsigned char buf[0x40];
	memset(buf, 0 ,0x40);
	std::cout <<procwrite(pid, data, (void *)getLoadAddr(pid), sizeof(data))<<std::endl;
	procread(pid, buf, (void *)getLoadAddr(pid), 0x40);
	hexdump(buf, 0x40);
	procwrite(pid, buf, (void *)getLoadAddr(pid), 0x40);
	ptrace_attach(pid, 0);

}/*}}}*/
#endif
#endif
