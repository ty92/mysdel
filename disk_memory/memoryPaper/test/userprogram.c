#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/types.h>

void main(void) {
	int ret;
	char str[] = "hello world hello world hello world hello world hello world";
	
	printf("my pid is %d\n",getpid());
	//sleep(20); /* 睡眠是为了获得pid后，插入内核模块 */
	printf("printf str is %s, sizeof is %ld\n",str,sizeof(str));
	
	ret = chdir("/tmp");
        printf("chdir return ret = %d\n", ret);

	printf("uid is %d\n",geteuid());
	//while(1);
}
