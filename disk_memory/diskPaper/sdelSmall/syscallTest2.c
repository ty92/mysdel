/*************************************************************************
	> File Name: syscallTest2.c
	> Author: tiany
	> Mail: tianye04@qq.com
 ************************************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

#define BLOCKSIZE 32769

//通过内核符号表查找到的sys_call_table的地址
//grep sys_call_table /boot/System.map-`uname -r` 
void **sys_call_table = (void **)0xffffffff81801400;
unsigned long *orig_unlinkAT = NULL;  //用来指向系统调用地址的
int (*orig_rename)(const char *oldname, const char *newname);
long (*orig_brk)(unsigned long brk);
long (*orig_open)(const char __user *filename, int flags, umode_t mode);
unsigned long (*orig_write)(unsigned int fd, const char __user* buf, size_t count);
long (*orig_unlinkat)(int dfd, const char __user *pathname, int flag);
int (*orig_lstat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);
int (*orig_fstat)(unsigned int fd, struct __old_kernel_stat __user *statbuf);
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


//long *orig_openat = NULL;

/* make the page writable */
int make_rw(unsigned long address)
{
        unsigned int level;
        pte_t *pte = lookup_address(address, &level);//查找虚拟地址所在的页表地址
    //设置页表读写属性
        pte->pte |=  _PAGE_RW;

        return 0;
}
/* make the page write protected */
int make_ro(unsigned long address)
{
        unsigned int level;
        pte_t *pte = lookup_address(address, &level);
        pte->pte &= ~_PAGE_RW; //设置只读属性

        return 0;
}

int smash_file(int dfd, const char *ufilename, struct __old_kernel_stat klstat)
{
    unsigned int filesize;
    int writes, lastWrites;
    char *user_buf = NULL;
    int counter, ret;
    unsigned long mmm;

    filesize = klstat.st_size;
    printk(KERN_INFO "filename %s size is %ud\n",ufilename, filesize);
    writes = filesize / bufsize;
    lastWrites = filesize % bufsize;

    //填充用户态缓冲区
    fill_buf(std_array);
    mmm = current->mm->brk;
    if(orig_brk(mmm + bufsize) < 0)
    {
        printk(KERN_ERR "brk failed");
        return (-ENOMEM);
    }
    user_buf = (void*)mmm + 2;
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


//unlink的函数原型,这个函数的原型要和系统的一致
asmlinkage long hacked_unlink(int dfd, const char __user *pathname, int flag)
{
    int ret, fd;
    char *newfilename = 0;
    unsigned long mmm = 0;
    struct __old_kernel_stat *user_lstat;
    struct __old_kernel_stat kernel_lstat;
    //getname、putname

    mmm = current->mm->brk;  /*定位当前进程数据段的大小*/
    ret = orig_brk(mmm+strlen(pathname)+1);
    if(ret < 0)
    {
        printk(KERN_INFO "Can't allocate userspace mem \n");
        return (-ENOMEM);
    }
    newfilename = (void*)mmm+2;
    if((ret = copy_to_user(newfilename,"testRename",strlen("testRename"))) != 0)
        return ret;

    printk("unlink pathname: %s, dfd:%d, flag:%d\n", pathname,dfd,flag);
   // ret = orig_rename(pathname, newfilename);
    if((fd = orig_open(pathname, O_RDWR | O_SYNC, 0)) < 0)
    {
        printk(KERN_INFO "open %s failed %d\n",newfilename,fd);
        return fd;
    }
    
    
  //  printk(KERN_ALERT "rename is %d, unlinkat file %s of rename testRename\n",ret, newfilename);
/*    if((ret = orig_unlinkat(dfd, newfilename, flag)) < 0)
    {
        orig_rename(newfilename, pathname); //文件删除失败，rename回原本的文件名
        printk(KERN_ALERT "unlinkat file %s error\n",pathname);
        return ret;
    }
*/

    mmm = current->mm->brk;
    ret = orig_brk(mmm + sizeof(struct __old_kernel_stat));
    user_lstat = (void*)mmm + 2;
    //printk(KERN_INFO "after %s\n",newfilename);
    if((ret = (*orig_lstat)(pathname, user_lstat)) < 0)
    {    printk(KERN_ERR "lstat %s error\n",newfilename);
        //if(orig_brk(mmm) < 0)
        //    return (-ENOMEM);
    } else {
        printk(KERN_INFO "orig_lstat %s\n",pathname);
        if((ret = copy_to_user(&kernel_lstat, user_lstat, sizeof(struct __old_kernel_stat))) != 0)
        {
            printk(KERN_ERR "copy_to_user error");
            return ret;
        }
        //if(orig_brk(mmm) < 0)
        //    return (-ENOMEM);
        printk(KERN_INFO "orig_lstat %s size is %d\n",pathname,kernel_lstat.st_size);
        if(S_ISREG(kernel_lstat.st_mode) && ret >= 0 && kernel_lstat.st_nlink == 1 && kernel_lstat.st_size > 0)
        {
            printk(KERN_INFO "isreg file, %s size is %ud\n",pathname, kernel_lstat.st_size);
            smash_file(fd, pathname, kernel_lstat);
        }
    }
    /*删除文件成功，通过open返回的文件描述符fd写文件*/
   // smash_file(int fd,)

    return 0; /*everything is ok, but he new systemcall does nothing*/
}

long hacked_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
    printk(KERN_INFO "filename=%s, flags=%d, mode=%d\n",filename, flags, mode);
    return 0;
}

//也是内核初始化函数
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
