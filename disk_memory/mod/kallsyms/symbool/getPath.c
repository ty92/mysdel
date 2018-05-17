/*************************************************************************
	> File Name: getPath.c
	> Author: 
	> Mail: 
	> Created Time: 2017年06月22日 星期四 09时37分46秒
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

void **sys_call_table = (void **)0xffffffff81801400;
long (*orig_unlinkat)(int dfd, const char __user *pathname, int flag);
unsigned long *orig_unlinkAT = NULL;  //用来指向系统调用地址的
long (*orig_open)(const char __user *filename, int flags, umode_t mode);
int (*orig_rename)(const char *oldname, const char *newname);
long (*orig_brk)(unsigned long brk);
unsigned long (*orig_write)(unsigned int fd, const char __user* buf, size_t count);
long (*orig_unlinkat)(int dfd, const char __user *pathname, int flag);
long (*orig_rmdir)(const char __user *pathname);
int (*orig_getcwd)(char __user *buf, unsigned long size);
int (*orig_lstat)(const char __user *filename, struct stat __user *statbuf);
int (*orig_fstat)(unsigned int fd, struct stat __user *statbuf);
int (*orig_fsync)(unsigned int fd);

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

/*
 * 根据task_struct、fd（文件描述符）获取当前工作路径
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
    if(!myfile)
    {
        printk(KERN_ERR "(struct file)myfile is null..\n");
        kfree(path);
        return NULL;
    }
    ppath = d_path(&(myfile->f_path), path, PATH_MAX);
    printk(KERN_INFO "get_absolutepath :inode=%ld, path=%s, ppath=%s\n",myfile->f_inode->i_ino, path,ppath);

    return ppath;
 }

char* getCurrentPath(char *path)
{
    int error;
    char *pathBuffer = NULL;    /*userspace path, path为kernelspace path*/
    unsigned long mmm = 0;

    mmm = current->mm->brk;
    error = orig_brk(mmm+ PATH_MAX);
    if(error < 0)
    {
        printk(KERN_INFO "Can't allocate userspace mem \n");
        return NULL;
    }
    pathBuffer = (void*)mmm+2;
    orig_getcwd(pathBuffer, PATH_MAX);
    if((error = copy_from_user(path, pathBuffer, strlen(pathBuffer))) != 0)
    {
        printk(KERN_ERR "copy_from_user error %d\n",error);
        return NULL;
    }
    return pathBuffer;
}

//unlink的函数原型,这个函数的原型要和系统的一致
asmlinkage long hacked_unlink(int dfd, const char __user *pathname, int flag)
{
    int ret = 0;
    char *path = NULL;

    if((flag & ~AT_REMOVEDIR) != 0)
        return -EINVAL;
    if(!(flag & AT_REMOVEDIR))
    {
        //ret = my_unlinkat(dfd, pathname);
        if(dfd != -100)
        {
            path = get_absolute_pathWithFd(current, dfd);   
            printk(KERN_INFO "dfd %d, pathname %s \n",dfd, pathname);
        }
    } else {
        printk(KERN_INFO "has AT_REMOVEDIR %d flag %d\n",dfd, flag);
        ret = orig_unlinkat(dfd, pathname, flag);
    }
    
    return ret;
}

//也是内核初始化函数
static int syscall_init_module(void)
{
   printk(KERN_ALERT "sys_call_table: 0x%p\n", sys_call_table);
   orig_unlinkAT = (unsigned long *)(sys_call_table[__NR_unlinkat]); //获取原来的系统调用地址
   orig_unlinkat = sys_call_table[__NR_unlinkat];
   orig_brk = sys_call_table[__NR_brk];
   orig_open = sys_call_table[__NR_open];
   orig_getcwd = sys_call_table[__NR_getcwd];

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
