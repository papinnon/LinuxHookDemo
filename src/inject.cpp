#include "./ptraceAPI.h"
#include <elf.h>

#include <iostream>
#include <wait.h>
#include <dlfcn.h>
void load_so(pid_t pid, void * dlopen, const char * soPath)
{/*{{{*/
	regs reg_orig, reg;
	fpregs fpreg_orig, fpreg;
	char * buffer;
	int length  = strlen(soPath);
	int stacksize = length+0x10;
	uint64_t ret = 0xdeadbeefcafebabe;
	int status;
	ptrace_attach(pid, 1);
	buffer = (char *)malloc(stacksize);
	sleep(1);
	ptrace_getregs(pid, &reg_orig, &fpreg_orig);
	memcpy(&reg, &reg_orig, sizeof(reg));
	procread(pid, buffer, (void *)reg.rsp, stacksize);
	procwrite(pid, &ret, (void* )reg.rsp, sizeof(ret));
	procwrite(pid, soPath, (void*)(reg.rsp+ sizeof(ret)), strlen(soPath) );
	sleep(1);
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
	
	procwrite(pid, buffer, (void *)reg_orig.rsp, stacksize);
	ptrace_setregs(pid, &reg_orig, &fpreg_orig);
	free(buffer);
	ptrace_attach(pid,0);
	return;
}/*}}}*/

#define EHDR Elf64_Ehdr
#define PHDR Elf64_Phdr
#define DYN Elf64_Dyn
#define SYM Elf64_Sym
#define addr_t void *
#define addr(a,b) (void *)((char *)a+b)
void * find_symbol(pid_t pid , const char * SymName, const char * LibName)
{/*{{{*/
	EHDR ehdr;
	PHDR * phdr;
	DYN  * dyn_ent;
	SYM  * sym_ent;
	addr_t dyn_section;
	addr_t sym_section;
	addr_t str_section;
	uint64_t phsize;
	uint64_t dyn_size;
	uint64_t sym_cnt;
	uint64_t str_size;
	char * buffer;

	//parse EHDR and PHDR
	void * ehdrp= (void *)getlibAddr(pid, LibName);
	procread(pid, &ehdr, ehdrp, sizeof(ehdr));
	phdr= (PHDR *)(ehdr.e_phoff+(char *)ehdrp);
	phsize= ehdr.e_phentsize* ehdr.e_phnum;
	buffer= new char[phsize];
	procread(pid, buffer, phdr, phsize);	
	for(int i=0; i< ehdr.e_phnum; ++i )
	{
		phdr= (PHDR *)(buffer+i*ehdr.e_phentsize);
		if(phdr->p_type == PT_DYNAMIC)
			break;
	}
	dyn_section = (addr_t) addr(ehdrp,phdr->p_vaddr);
	dyn_size = (uint64_t) phdr->p_memsz;
	delete [] buffer;
	//parse .DYNAMIC seg
	buffer = new char[dyn_size];
	int && dyncnt= dyn_size/sizeof(DYN);
	procread(pid , buffer, dyn_section, dyn_size);
	for(int i=0; i< dyncnt; ++i)
	{
		dyn_ent= (DYN *)(buffer+ i* sizeof(DYN));
		if(dyn_ent->d_tag == DT_STRTAB)
			str_section= addr(dyn_ent->d_un.d_ptr,0);
		else if(dyn_ent->d_tag == DT_SYMTAB)
			sym_section= addr(dyn_ent->d_un.d_ptr,0);
		else if(dyn_ent->d_tag == DT_STRSZ)
			str_size= (uint64_t) dyn_ent->d_un.d_val;

	}	
	delete [] buffer;
	// parse .dynsym
	buffer = new char[0x10000];
	sym_cnt= 0x10000/0x18;
	procread(pid, buffer, sym_section, 0x10000);
	int len = strlen(SymName);
	char * buf = new char[len+1];
	for(int i=0; i< sym_cnt; ++i)
	{
		memset(buf, 0, len+1);
		sym_ent= (SYM*)(buffer+ i*sizeof(SYM));
		void * ptr = addr(str_section,sym_ent->st_name);
		procread(pid, buf, ptr, len);
		if(!strncmp(SymName, buf, len))
			break;
	}
	return addr(ehdrp,sym_ent->st_value);
}/*}}}*/

int main(int argc, char *argv[])
{
	pid_t pid =  atol(argv[1]);
	void * dlopen=find_symbol(pid,"__libc_dlopen_mode","libc-2.30.so");
	load_so(pid, dlopen, "/tmp/Hook/src/hook.so");
}


