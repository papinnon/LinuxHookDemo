#include "./ptraceAPI.h"
#include <elf.h>

#include <wait.h>
void load_so(pid_t pid, void * dlopen, const char * soPath)
{
	regs reg_orig, reg;
	fpregs fpreg_orig, fpreg;
	char * buffer;
	int length  = strlen(soPath);
	int stacksize = length+0x10;
	uint64_t ret = 0xdeadbeefcafebabe;
	int status;
	ptrace_attach(pid, 1);
	buffer = (char *)malloc(stacksize);
	sleep(0.5);
	memset(&reg, &reg_orig, sizeof(reg));
	ptrace_getregs(pid, &reg_orig, &fpreg_orig);
	ptrace_read(pid, buffer, (void *)reg.rsp, stacksize);
	ptrace_write(pid, &ret, (void* )reg.rsp, sizeof(ret));
	ptrace_write(pid, soPath, (void*)(reg.rsp+ sizeof(ret)), strlen(soPath) );
	sleep(0.5);
	reg.rdi= reg.rsp+sizeof(ret);
	reg.rsi= RTLD_NOW|RTLD_GLOBAL|RTLD_NODELETE;
	reg.rip= (uint64_t)dlopen+2;

	ptrace_setregs(pid, &reg, 0);

	if(ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
	{
		puts("error Continue");
		exit(1);
	}
	waitpid(pid, &status, 0);
	ptrace_getregs(pid, &reg, 0);
	std::cout << "dlopen addr:"<<std::hex<<dlopen<<std::endl;
	std::cout << "finish addr:"<< std::hex<< reg.rip<< std::endl;
	
	ptrace_write(pid, buffer, reg_orig.rsp, stacksize);
	ptrace_setregs(pid, &reg_orig, &fpreg_orig);
	free(buffer);
	ptrace_attach(pid,0);
	return;
}


