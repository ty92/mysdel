/*************************************************************************
	> File Name: syscall.c
	> Author: 
	> Mail: 
	> Created Time: 2017年06月15日 星期四 11时02分58秒
 ************************************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fdtable.h>
#include <linux/syscalls.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/limits.h>

#define BLOCKSIZE 32769
#define FLUSH       orig_sync()

//通过内核符号表查找到的sys_call_table的地址
void **sys_call_table = (void **)0xffffffff81801400;
unsigned long *orig_unlinkAT = NULL;  //用来指向系统调用地址的

int (*orig_rename)(const char *oldname, const char *newname);
long (*orig_brk)(unsigned long brk);
long (*orig_open)(const char __user *filename, int flags, umode_t mode);
unsigned long (*orig_write)(unsigned int fd, const char __user* buf, size_t count);
long (*orig_unlinkat)(int dfd, const char __user *pathname, int flag);
long (*orig_rmdir)(const char __user *pathname);
int (*orig_getcwd)(char __user *buf, unsigned long size);
int (*orig_lstat)(const char __user *filename, struct stat __user *statbuf);
int (*orig_fstat)(unsigned int fd, struct stat __user *statbuf);
int (*orig_fsync)(unsigned int fd);
int (*orig_sync)(void);

unsigned long bufsize = BLOCKSIZE;
char buf[BLOCKSIZE];

unsigned char write_modes[27][3] = { 
   {"\x55\x55\x55"}, {"\xaa\xaa\xaa"}, {"\x92\x49\x24"}, {"\x49\x24\x92"},
   {"\x24\x92\x49"}, {"\x00\x00\x00"}, {"\x11\x11\x11"}, {"\x22\x22\x22"},
   {"\x33\x33\x33"}, {"\x44\x44\x44"}, {"\x55\x55\x55"}, {"\x66\x66\x66"},
   {"\x77\x77\x77"}, {"\x88\x88\x88"}, {"\x99\x99\x99"}, {"\xaa\xaa\xaa"},
   {"\xbb\xbb\xbb"}, {"\xcc\xcc\xcc"}, {"\xdd\xdd\xdd"}, {"\xee\xee\xee"},
   {"\xff\xff\xff"}, {"\x92\x49\x24"}, {"\x49\x24\x92"}, {"\x24\x92\x49"},
   {"\x6d\xb6\xdb"}, {"\xb6\xdb\x6d"}, {"\xdb\x6d\xb6"}
};  

unsigned char std_array[3] = "\xff\xff\xff";


void sdel_random_filename(char *filename) {
    int i;
    unsigned char rand;
    for (i = strlen(filename) - 1; (filename[i] != '/') && (i >= 0);i--)
        if (filename[i] != '.') { /* keep dots in the filename */
            get_random_bytes(&rand, 1);   //export kernel function
            filename[i] = 97 + (int) ((int) rand % 26);
        }
}

static void fill_buf(char pattern[3])
{
    int loop;
    int where;

    for (loop = 0; loop < (bufsize / 3); loop++)
    {
        where = loop * 3;
        buf[where] = pattern[0];
        buf[where+1] = pattern[1];
        buf[where+2] = pattern[2];
    }
}

/* make the page writable */
int make_rw(unsigned long address)
{
        unsigned int level;
        pte_t *pte = lookup_address(address, &level);//查找虚拟地址所在的页表地址
    //设置页表读写属性
        pte->pte |=  _PAGE_RW;

        return 0;
}

/*
 * make_ro: 
 * make the page write protected 
 *
 */
int make_ro(unsigned long address)
{
        unsigned int level;
        pte_t *pte = lookup_address(address, &level);
        pte->pte &= ~_PAGE_RW; //设置只读属性

        return 0;
}

/*
 * getUserMem: 使用brk内核函数获取大小为 @length 的用户空间内存缓冲区
 * @length：要获取用户空间的内存大小
 * return：成功则返回申请的用户空间内存的unsigned long地址，否则返回 -ENOMEM
 * get userspace memory
 * */
unsigned long getUserMem(int length)
{
    unsigned long mmm = 0;
    int ret;
    
    mmm = current->mm->brk;
    ret = orig_brk(mmm+length);
    if(ret <0)
    {
        printk(KERN_ERR "Can't allocate userspace mem\n");
        return (-ENOMEM);
    }

    return mmm;
}

/* 
 * smash_file: 根据文件描述符@fd、文件名@ufilename和struct stat结构体对象@klstat对要删除的文件进行覆写操作
 * @fd：要删除的文件的文件描述符
 * @ufilename：要删除文件的文件名（用户空间）
 * @klstat：struct stat 结构体，可以获取文件状态
 * return：成功返回0，否则返回非0
 *
 */
int smash_file(int dfd, const char *ufilename, struct stat klstat)
{
    unsigned int filesize;
    int writes, lastWrites;
    char *user_buf = NULL;
    int counter, ret;

    filesize = klstat.st_size;
    printk(KERN_INFO "filename %s size is %ud\n",ufilename, filesize);
    writes = filesize / bufsize;
    lastWrites = filesize % bufsize;

    //填充用户态缓冲区
    fill_buf(std_array);

    user_buf = (void*)getUserMem(bufsize) + 2;
    if((ret = copy_to_user(user_buf, buf, bufsize)) != 0)
        return ret;
    for(counter=1; counter <= writes; counter++)
    {
        if((ret=orig_write(dfd, user_buf, bufsize)) < 0)
        {   
            printk(KERN_ERR "write error");
            return ret;
        }   
    }
    if(lastWrites > 0)
    {
        if((ret=orig_write(dfd, user_buf, lastWrites)) < 0)
        {
            printk(KERN_ERR "write error");
            return ret;
        }
    }
    if(orig_fsync(dfd) < 0)
       orig_sync();
    printk(KERN_INFO "write over\n");
    return 0;
}

/*
 * get_absolute_pathWithFd: 根据进程的task_struct 和 fd（文件描述符）获取当前工作路径
 * @mytask: 进程的task_struct结构体
 * @fd: 进程打开的文件描述符
 * return：返回当前路径（内核空间）
 */
 char *get_absolute_pathWithFd(struct task_struct *mytask, int fd)
 {
    struct file *myfile = NULL;
    struct files_struct *files = NULL;
    char *path = (char*)kzalloc(PATH_MAX,GFP_KERNEL);
    char *ppath = NULL;

    files = mytask->files;
    if(!files)
    {
        printk(KERN_ERR "(files_struct)files is null..\n");
        kfree(path);
        return NULL;
    }

    myfile = files->fdt->fd[fd];
    if(!myfile) {
       printk(KERN_ERR "(struct file)myfile is null..\n");
       kfree(path);
       return NULL;
    }
    ppath = d_path(&(myfile->f_path), path, PATH_MAX);
    return ppath;
 }

/*
 * smash_fileHeader: 使用了ecryptfs加密后，对文件的header元数据进行覆写
 * @dfd：要覆写的文件描述符
 * return：成功返回0，否则返回非0
 */
int smash_fileHeader(int dfd)
{
    int error;
    struct file *myfile = NULL;
    struct inode *myinode = NULL;
    long long size;
    long long offsetTemp = 0;

    int (*orig_ecryptfs_write)(struct inode *ecryptfs_inode,char *data, loff_t offset, size_t size);
    orig_ecryptfs_write = (void*)kallsyms_lookup_name("ecryptfs_write");

    //fill_buf(std_array);
    myfile = current->files->fdt->fd[dfd];
    myinode = myfile->f_inode;

    size = i_size_read(myinode); 

    printk("ecryptfs_write address is 0x%p, inode=%ld\n", orig_ecryptfs_write,myinode->i_ino);   
    if(size <= 4096)
    {
        if((error = orig_ecryptfs_write(myinode, buf, 0, 8)) != 0)
        {
            printk(KERN_ERR "ecryptfs_write error %d\n",error);
            return error;
        }
        printk(KERN_INFO "ecryptfs_write success %d, file_size=%lld\n",error,size);
    } else {
        while( offsetTemp < size )
        {
            if((error = orig_ecryptfs_write(myinode, buf, offsetTemp, 8)) != 0)
                return error;
            offsetTemp += 4096;
        }
        printk(KERN_INFO "ecryptfs_write success %d, file_size=%lld\n",error,size);
    }

    FLUSH;

    return 0;
}

/*
 * my_unlinkat: 最重要的安全删除实现逻辑，其中实现文件名rename，打开文件，在文件成功
 *              删除后再根据打开的文件描述符进行覆写操作（加密后的文件header覆写及全文覆写）
 * @dfd：
 */
int my_unlinkat(int dfd, const char __user *pathname, int flag)
{
    int ret, fd;
    char *newfilename = 0;
    unsigned long mmm = 0;
    struct stat *user_lstat;
    struct stat kernel_lstat;
    char newname[strlen(pathname) + 1];
    char *dirPath;
    char *userPath;
    const char *absolutePath;
    const char *newPathFile;
    char * tempPath;
    int HeaderCount;
    int BodyCount;

    strcpy(newname, pathname);
    sdel_random_filename(newname);

    //getname、putname
    newfilename = (void*)getUserMem(strlen(pathname) + 1)+2;
    if((ret = copy_to_user(newfilename,newname, strlen(newname))) != 0)
        return ret;

    printk("unlink pathname: %s, dfd:%d\n", pathname,dfd);
    
    /* 当dfd文件描述符不等于-100时，则dfd为要删除文件所在目录项的文件描述符，
     * 因而可以根据当前进程和目录项的文件描述符确定要删除文件所在目录的绝对路径；
     * 仅仅是删除文件时不需要考虑绝对路径，但是在rename和open操作时，必须知道文件
     * 的绝对路径，否则会报错，找不到文件
     */
    if(dfd != -100)
    {
        dirPath = get_absolute_pathWithFd(current, dfd); //路径问题

        mmm = getUserMem(strlen(dirPath)*2+1);
        userPath = (void*)mmm+2;

        mmm = getUserMem(strlen(dirPath)*2+1);
        tempPath = (void*)mmm+2;

        if((ret = copy_to_user(userPath, dirPath, strlen(dirPath))) != 0)
        {
            printk(KERN_ERR "copy_to_user userPath error %d\n", ret);
            return ret;
        }
        /*
        if((ret = copy_to_user(tempPath, dirPath, strlen(dirPath))) != 0)
        {
            printk(KERN_ERR "copy_to_user tempPath error %d\n", ret);
            return ret;
        }*/

        /*同为用户空间内存，可以直接使用strcpy*/
        strcpy(tempPath, userPath);
        printk(KERN_ALERT "#####userPath=%s, tempPath=%s\n", userPath, tempPath);

        absolutePath = strcat(strcat(userPath, "/"), pathname);
        printk(KERN_ALERT "#####absolutePath=%s,newfilename=%s\n", absolutePath,newfilename);

        newPathFile = strcat(strcat(tempPath, "/"), newfilename); 
        printk(KERN_ALERT "#####newPathFileISNOTNULL=%s\n",newPathFile);

        if((ret = orig_rename(absolutePath, newPathFile)) < 0)
        {
            printk(KERN_ERR "orig_rename error %d\n",ret); 
            return ret;
        }

        /*删除文件成功，通过open返回的文件描述符fd写文件*/
        if((fd = orig_open(newPathFile, O_RDWR | O_SYNC, 0)) < 0)
        {   
            printk(KERN_INFO "open %s failed %d\n",newPathFile, fd);
            return fd;
        }   
    } else {
        ret = orig_rename(pathname, newfilename);
        if((fd = orig_open(newfilename, O_RDWR | O_SYNC, 0)) < 0)
        {
            printk(KERN_INFO "open %s failed %d\n",newfilename, fd);
            return fd;
        }   
    }


    if((ret = orig_unlinkat(dfd, newfilename, flag)) < 0)
    {
        if(dfd != -100)
            orig_rename(newPathFile, absolutePath);
        else
            orig_rename(newfilename, pathname); //文件删除失败，rename回原本的文件名
        printk(KERN_ALERT "unlinkat file %s error\n",pathname);
        return ret;
    }

    user_lstat = (void*)getUserMem(sizeof(struct stat)) + 2;

    if((ret = orig_fstat(fd, user_lstat)) < 0)
    {    printk(KERN_ERR "lstat %s error\n", pathname);
         if(orig_brk(mmm) < 0)
            return (-ENOMEM);
    } else {
        printk(KERN_INFO "orig_lstat %s\n",pathname);
        if((ret = copy_from_user(&kernel_lstat, user_lstat, sizeof(struct stat))) != 0)
        {
            printk(KERN_ERR "copy_to_user error %d\n",ret);
            if(orig_brk(mmm) < 0)
                return (-ENOMEM);
        }
        printk(KERN_INFO "orig_lstat %s size is %ld\n",newfilename,kernel_lstat.st_size);

        //printk(KERN_INFO "S_ISREG(kernel_lstat.st_mode) is %d, ret=%d\n",S_ISREG(kernel_lstat.st_mode), ret);
        //printk(KERN_INFO "kernel_lstat.st_nlink is %lu, kernel_lstat.st_size is %lu\n", kernel_lstat.st_nlink,kernel_lstat.st_size);
        //上边执行unlinkat删除操作后，进程虽然仍打开文件，但是st_nlink（硬链接计数）已经为0，则可以覆写，若不为0，则说明存在硬链接不能覆写
        if(S_ISREG(kernel_lstat.st_mode) && ret >= 0 && kernel_lstat.st_nlink == 0 && kernel_lstat.st_size > 0)
        {
            HeaderCount = 2;
            printk(KERN_INFO "isreg file, %s size is %ld\n",newfilename, kernel_lstat.st_size);
            while(HeaderCount) {
                printk(KERN_INFO "overwrite header HeaderCount is %d\n",HeaderCount);
                smash_fileHeader(fd);
                HeaderCount--;
            }
            BodyCount = 1;
            while(BodyCount) {
                printk(KERN_INFO "overwrite body BodyCount is %d\n",BodyCount);
                smash_file(fd, pathname, kernel_lstat);
                BodyCount--;
            }
        
        }
    }
    return 0; /*everything is ok, but he new systemcall does nothing*/
}

//unlink的函数原型,这个函数的原型要和系统的一致
asmlinkage long hacked_unlink(int dfd, const char __user *pathname, int flag)
{
    int ret = 0;

    if((flag & ~AT_REMOVEDIR) != 0)
        return -EINVAL;
    if(!(flag & AT_REMOVEDIR))
    {
        ret = my_unlinkat(dfd, pathname, flag);

    } else {
        printk(KERN_INFO "has AT_REMOVEDIR %d flag %d\n",dfd, flag);
        ret = orig_unlinkat(dfd, pathname, flag);
    }

    return ret;
}

//内核初始化函数
static int syscall_init_module(void)
{
        printk(KERN_ALERT "sys_call_table: 0x%p\n", sys_call_table);
        orig_unlinkAT = (unsigned long *)(sys_call_table[__NR_unlinkat]); //获取原来的系统调用地址
        orig_unlinkat = sys_call_table[__NR_unlinkat];
        orig_rename = sys_call_table[__NR_rename];
        orig_brk = sys_call_table[__NR_brk];
        orig_open = sys_call_table[__NR_open];
        orig_lstat = sys_call_table[__NR_lstat];
        orig_fstat = sys_call_table[__NR_fstat];
        orig_fsync = sys_call_table[__NR_fsync];
        orig_getcwd = sys_call_table[__NR_getcwd];
        orig_sync = sys_call_table[__NR_sync];
        orig_write = sys_call_table[__NR_write];

    printk(KERN_ALERT "orig_unlinkat: 0x%p\n", orig_unlinkAT);

        make_rw((unsigned long)sys_call_table); //修改页属性
        sys_call_table[__NR_unlinkat] = (unsigned long *)hacked_unlink; //设置新的系统调用地址
        make_ro((unsigned long)sys_call_table);

        return 0;
}

//内核注销函数
static void syscall_cleanup_module(void)
{
        printk(KERN_ALERT "Module syscall unloaded.\n");

        make_rw((unsigned long)sys_call_table);
        sys_call_table[__NR_unlinkat] = (unsigned long *)orig_unlinkAT;
        /*set mkdir syscall to the origal one*/
        make_ro((unsigned long)sys_call_table);
}

module_init(syscall_init_module);
module_exit(syscall_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("hack syscall");
