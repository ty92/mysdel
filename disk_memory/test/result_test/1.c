#include <stdio.h>
#include <malloc.h>
#include <unistd.h>


int main (int argc, char **argv)
{
        char str[] = "hello world###"; 
        printf("pid is %d\n",getpid());

        sleep(200);
        return 0;
}
