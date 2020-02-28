#ifndef STRING_HANDLING_H
#define STRING_HANDLING_H
#include <string.h>
#define NPOS (char * )-1
char * split(char * src, char delim, char ** left )
{
	char * ptr = strchr(src, delim);
	if(ptr==0 )
		return NPOS;
	*left = strndup(src, ptr-src);
	return ptr+1;	
		
}
#endif
