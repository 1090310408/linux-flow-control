#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <dirent.h>

#define MAX 1024 
#define PATH_SIZE 128  
 
void checkfd(FILE* fout);
struct dirent* entry;
char nodeid[100];
//char checknodeid[100];
	
int main(){
	FILE* fin;
	FILE* fout;
	
	
	typedef struct	colomon{
		char attribute[100];
	}colomon;
	colomon tcpinfo[10000];
	int i=0;	
	int inodecount=-1;
	int localttycount=-2;
	fin=fopen("/proc/net/tcp","r");
	
	if(!fin)	printf("Open infile error\n");
	
	while(!feof(fin)){	
		fscanf(fin,"%s",tcpinfo[i].attribute);
		if(!strcmp(tcpinfo[i].attribute,"01")){	
			inodecount=i+6;
			localttycount=i-2;
			//printf("%s\n",tcpinfo[i].attribute);
		}
		if(inodecount==i){	
			//printf("%s %s\n",tcpinfo[localttycount].attribute,tcpinfo[inodecount].attribute);
			//fprintf(fout,"%s %s\n",tcpinfo[localttycount].attribute,tcpinfo[inodecount].attribute);
			sprintf(nodeid,"socket:[%s]",tcpinfo[inodecount].attribute);
			printf("%s\n",nodeid);
			checkfd(fout);
		}
		i++;
	}

	return 0;
}


void checkfd(FILE* fout){
	DIR *dir;
	DIR *subdir;
	FILE *tempfile;
	struct dirent* subentry;	
	char path[PATH_SIZE];
	char subpath[PATH_SIZE];
	char temppath[PATH_SIZE];
	char pidname[100];
	if((dir=opendir("/proc"))==NULL)	printf("Open error\n");
	fout=fopen("/home/administrator/lab/outfile","w+");
	if(!fout)	printf("process %s Open outfile error\n",entry->d_name);

	while((entry=readdir(dir))!=NULL){
		if(entry->d_name[0]=='.')	continue;
		if((entry->d_name[0]<'0')||(entry->d_name[0]>'9'))	continue;
		sprintf(path,"/proc/%s/fd",entry->d_name);
		//printf("%s\n",path);


		if((subdir=opendir(path))==NULL){
			//printf("Open subdir error.\n");
			continue;
		}
		while((subentry=readdir(subdir))!=NULL){
			if(subentry->d_name[0]=='.')	continue;
			if((subentry->d_name[0]<'0')||(subentry->d_name[0]>'9'))	continue;
			//printf("%s %d\n",subentry->d_name,subentry->d_type);
			sprintf(subpath,"%s/%s",path,subentry->d_name);
			//printf("%s\n",subpath);
		
			enum { BUFFERSIZE = 100 };
			char buf[BUFFERSIZE];
			ssize_t len = readlink(subpath, buf, sizeof(buf)-1);
			if (len != -1) {
 				buf[len] = '\0';
				//printf("%s\n\n",buf);
				fprintf(fout,"%s\n",buf);
				if(!strcmp(nodeid,buf)){

					sprintf(temppath,"/proc/%s/comm",entry->d_name);
					tempfile=fopen(temppath,"r");
					if(!tempfile)	printf("Open tempfile error\n");
					fscanf(tempfile,"%s",pidname);
					printf("process %s : %s is connecting to the Internet now.\n",entry->d_name,pidname);
				}	
			}
			else {
 				 /* handle error condition */
				printf("readlink error.\n");
			}
		}

		closedir(subdir);	
	}
	fclose(fout);		
	closedir(dir);
	//return 0;   

}



