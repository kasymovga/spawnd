#ifndef _MISC_H_
#define _MISC_H_
#include <stdarg.h>
#include <stdio.h>

char*vmprintf(const char*,va_list);
char*mprintf(const char*,...);
char*rprintf(char*,const char*,...);
char*rstrncat(char*,const char*,size_t);
char*mgets(FILE*);
char**file_lines(const char*);
void charpp_free(char**);
int lock_file(const char*);
int unlock_file(const char*);
int rmr(const char*);

#endif
