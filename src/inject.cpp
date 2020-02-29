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
//Set G_gotplt
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

void * GOTPLT;
void gothook(pid_t pid, const char * funcorig, const char * funchook, const char * LibName)
{
	EHDR ehdr;
	PHDR * phdr;
	DYN  * dyn_ent;
	SYM  * sym_ent;
	addr_t dyn_section;
	addr_t sym_section;
	addr_t str_section;
	addr_t rela_section;
	addr_t target; // the hook gotplt entry
	uint64_t phsize;
	uint64_t dyn_size;
	uint64_t sym_cnt;
	uint64_t str_size;
	uint64_t rela_sz;
	uint64_t relaentsz;
	char * buffer;
	char * namebuf;
	//parse EHDR and PHDR
	int origlen = strlen(funcorig)+1;
	namebuf = new char[origlen];
	memset(namebuf, 0, origlen);
	
	void * ehdrp= (void *)getLoadAddr(pid);
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
		if(dyn_ent->d_tag == DT_PLTGOT)
			GOTPLT= addr(dyn_ent->d_un.d_ptr,0);
		else if(dyn_ent->d_tag == DT_JMPREL)
			rela_section= addr(dyn_ent->d_un.d_ptr,0);
		else if(dyn_ent->d_tag ==DT_RELSZ)
			rela_sz = dyn_ent->d_un.d_ptr;
		else if(dyn_ent->d_tag == DT_RELENT)
			relaentsz= dyn_ent->d_un.d_ptr;
		else if(dyn_ent->d_tag == DT_STRTAB)
			str_section= addr(dyn_ent->d_un.d_ptr,0);
		else if(dyn_ent->d_tag == DT_SYMTAB)
			sym_section= addr(dyn_ent->d_un.d_ptr,0);
		else if(dyn_ent->d_tag == DT_STRSZ)
			str_size= (uint64_t) dyn_ent->d_un.d_val;

	}	
	delete [] buffer;
	//parse rela
	buffer = new char[0x10000];
	relaentsz=0x18;
	procread(pid, buffer, rela_section, 0x10000);
	Elf64_Rela *rela_ent;
	for(int i=0;i < 0x10000/relaentsz; ++i)
	{
		rela_ent= (Elf64_Rela *)(buffer+i*relaentsz);
		if(ELF64_R_TYPE(rela_ent->r_info) == R_X86_64_JUMP_SLOT)
		{
			uint32_t symidx= ELF64_R_SYM(rela_ent->r_info);
			uint32_t strpos =0;
			procread(pid, &strpos, addr(sym_section,symidx*0x18), 4);
			procread(pid, namebuf, addr(str_section,strpos), origlen);
			if(!strncmp(namebuf, funcorig, origlen-1))
				break;
		}

	}
	target = addr(ehdrp,rela_ent->r_offset);
	std::cout <<"Found "<<funcorig <<" Got Entry: "<< std::hex<<target<<std::endl;
	//Hooking
	void *pfunchook= find_symbol(pid, funchook, LibName);
	procwrite(pid, &pfunchook, target, sizeof(pfunchook));
	delete []buffer;
	delete []namebuf;
	return ;
}
int main(int argc, char *argv[])
{
	pid_t pid =  atol(argv[1]);
	char * origfunc = argv[2];
	char * hookfunc = argv[3];
	char * libPath = argv[4];
	void * dlopen=find_symbol(pid,"__libc_dlopen_mode","libc-2.30.so");
	std::cout<<"DLL Injection: "<<libPath<<std::endl;
	load_so(pid, dlopen, libPath);
	gothook(pid, origfunc, hookfunc,libPath);
}


