#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define N 10
int main(void){
        int begin, end;
        char *string = (char*)malloc(N);
        char std[N];
        int i=0;
        for(i=0; i<N - 1; i++)
                std[i] = 'c';
        printf("sizeof=%ld\n",sizeof(std));

        begin = clock();
        memcpy(string, std, N);
        end = clock();

        printf("%d, pid=%d\n",end-begin,getpid());
//        sleep(30);
        return 0;
}
