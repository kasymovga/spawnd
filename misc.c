#define _XOPEN_SOURCE 500
#include "misc.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

char*vmprintf(const char*fmt,va_list ap){
	va_list ap_copy;
	size_t len=16,need_len;
	char*dst=malloc(sizeof(char)*len);
	if(dst){
		char*new_dst;
		va_copy(ap_copy,ap);
		while((need_len=vsnprintf(dst,len,fmt,ap_copy))>=len){
			va_end(ap_copy);
			va_copy(ap_copy,ap);
			new_dst=realloc(dst,(need_len+1)*sizeof(char));
			if(!new_dst){
				free(dst);
				dst=NULL;
				break;
			};
			dst=new_dst;
			len=need_len+1;
		};
		va_end(ap_copy);
		if(need_len<0){
			free(dst);
			dst=NULL;
		};
	};
	return dst;
};

char*mprintf(const char*fmt,...){
	va_list ap;
	va_start(ap,fmt);
	char*dst=vmprintf(fmt,ap);
	va_end(ap);
	return dst;
};

char*rprintf(char*prev,const char*fmt,...) {
	va_list ap;
	va_start(ap,fmt);
	char*dst=vmprintf(fmt,ap);
	free(prev);
	va_end(ap);
	return dst;
};

char*rstrncat(char*dst,const char*src,size_t len) {
	char*ret=NULL;
	size_t dst_len=dst?strlen(dst):0;
	if(!(ret=malloc(dst_len+len+1))) goto finish;
	if(dst) strcpy(ret,dst);
	if(len)
		strncpy(&ret[dst_len],src,len);
	ret[dst_len+len]='\0';
	free(dst);
finish:
	return ret;
};

char*mgets(FILE*file) {
	char*ret=NULL;
	char*new_ret=NULL;
	char*tail=NULL;
	size_t ret_len=0;
	for(;;) {
		if(!(new_ret=realloc(ret,ret_len+64))) {
			ret_len=0;
			goto finish_fail;
		};
		ret=new_ret;
		tail=&ret[ret_len];
		if(!fgets(tail,64,file)) {
			if(!ret_len) {
				goto finish_fail;
			} else {
				break;
			};
		};
		ret_len+=strlen(tail);
		if(ret[ret_len-1]=='\n') {
			ret[ret_len-1]='\0';
			break;
		};
	};
	goto finish;
finish_fail:
	free(ret);
	ret=NULL;
finish:
	return ret;
};

void charpp_free(char**pp) {
	if(!pp) return;
	char**p;
	for(p=pp;*p;p++) {
		free(*p);
	};
	free(pp);
};

char**file_lines(const char*path) {
	char*record=NULL;
	char**ret=NULL;
	char**new_ret=NULL;
	size_t ret_len=0;
	size_t ret_size=0;
	size_t new_ret_size=0;
	FILE*file;
	if(!(file=fopen(path,"r"))) {
		goto finish_fail;
	};
	for(;;) {
		record=mgets(file);
		if(ret_size<ret_len+1) {
			new_ret_size=(((ret_len+1)/16)+1)*16;
			new_ret=realloc(ret,sizeof(char*)*new_ret_size);
			if(!new_ret) goto finish_fail;
			ret=new_ret;
			ret_size=new_ret_size;
		};
		ret[ret_len]=record;
		if(!record) break;
		record=NULL;
		ret_len++;
		//ret[ret_len]=NULL;
	};
	if(!feof(file)) {
		goto finish_fail;
	};
	goto finish;
finish_fail:
	free(record);
	charpp_free(ret);
	ret=NULL;
finish:
	if(file) fclose(file);
	return ret;
};

int lock_file(const char*path) {
	int ret=-1;
	char*lock_path=NULL;
	if(!(lock_path=rprintf(NULL,"%s.LOCK",path))) goto finish;
	if(mkdir(lock_path,0700)) goto finish;
	ret=0;
finish:
	return ret;
};

int unlock_file(const char*path) {
	int ret=-1;
	char*lock_path=NULL;
	if(!(lock_path=rprintf(NULL,"%s.LOCK",path))) goto finish;
	if(rmdir(lock_path)) goto finish;
	ret=0;
finish:
	return ret;
};

int rmr(const char*path) {
	int ret=-1;
	DIR*dir=NULL;
	struct stat st;
	struct dirent*dirent;
	char*sub_path=NULL;
	if(lstat(path,&st)) goto finish;
	if(S_ISDIR(st.st_mode)) {
		dir=opendir(path);
		while((dirent=readdir(dir))) {
			if(!strcmp(dirent->d_name,".") || !strcmp(dirent->d_name,"..")) continue;
			if(!(sub_path=rprintf(sub_path,"%s/%s",path,dirent->d_name))) goto finish;
			if(rmr(sub_path)) goto finish;
		};
		closedir(dir);
		dir=NULL;
		rmdir(path);
	} else {
		unlink(path);
	};
	ret=0;
finish:
	free(sub_path);
	if(dir) closedir(dir);
	return ret;
};
