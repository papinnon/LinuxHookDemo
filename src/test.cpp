#include "./inject.h"

int main(int argc, char * argv[])
{
	pid_t pid =  atol(argv[1]);
	char * libPath = argv[2];

	void * dlopen=find_symbol(pid,"__libc_dlopen_mode","libc-2.30.so");
	std::cout<<"DLL Injection: "<<libPath<<std::endl;
	load_so(pid, dlopen, libPath);
}
