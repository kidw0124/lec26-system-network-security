//main.cpp
#include<stdio.h>
#include "add-nbo.h"

int main(int argc, char*argv[]){
	uint32_t a,b;
	if(argc!=3){
		fprintf(stderr,"The following error occurred : argc different\n");
		return 1;//returned with error code 1(argc diff)
	}
	FILE*file1=fopen(argv[1],"rb");
	if(!file1){
		perror("The following error occurred");
		return 2;//returend with error code 2(nofile)
	}
	else{
		int err=fread(&a,sizeof(uint32_t),1,file1);
		if(!err){
			perror("The following error occurred");
			return 3;//error code 3(read bin err)
		}
	}
	FILE*file2=fopen(argv[2],"rb");
        if(!file2){
                fprintf(stderr, "Second file is none\n");
                return 2;//returend with error code 2(nofile)
        }
	else{
                int err=fread(&b,sizeof(uint32_t),1,file2);
                if(!err){
                        perror("The following error occurred");
                        return 3;
                }
        }
	uint32_t c=add(a,b);
	printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n",ntohl(a),ntohl(a),ntohl(b),ntohl(b),c,c);
	return 0;
}
