/*************************************************************************
        > File Name: userprogram.c
        > Author: tiany
        > Mail: tianye04@qq.com
	> Description: 先打印出当前进程的pid，使得程序睡眠一段时间，然后根据pid
	> 	挂载内核进程，此时程序睡眠结束，执行chdir()函数切换工作目录，陷入
	>	内核，调用挂载的内核模块中的chdir()处理函数，在该自定义函数中写
	>	进程地址空间；
	>	chdir()函数返回，用户程序while(1);循环等待，保持进程不退出，使用gdb
	>	验证成功覆写进程地址空间。
 ************************************************************************/
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/types.h>

void main(void) {
	int ret;
	char str[] = "hello world hello world hello world hello world hello world";
	
	printf("my pid is %d\n",getpid());
	sleep(20); /* 睡眠是为了获得pid后，插入内核模块 */
	printf("printf str is %s, sizeof is %ld\n",str,sizeof(str));
	
	ret = chdir("/tmp");
        printf("chdir return ret = %d\n", ret);

	printf("uid is %d\n",geteuid());
	while(1);
}
