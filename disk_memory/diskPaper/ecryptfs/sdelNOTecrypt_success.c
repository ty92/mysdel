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

//通过内核符号表查找到的sys_call_table的地址
//grep sys_call_table /boot/System.map-`uname -r` 
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

/*get userspace memory*/
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

int smash_file(int dfd, const char *ufilename, struct stat klstat)
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
    if(!myfile) {
       printk(KERN_ERR "(struct file)myfile is null..\n");
       kfree(path);
       return NULL;
    }
    ppath = d_path(&(myfile->f_path), path, PATH_MAX);
    return ppath;
 }

char *get_absolute_path(struct task_struct *task)
{
    char *ret_ptr = NULL;
    char *tpath = NULL;
    struct vm_area_struct *vma = NULL;
    struct path base_path;

    tpath = (char*)kmalloc(512, 0);
    if(NULL == tpath || NULL == task)
        return NULL;

    memset(tpath, '\0', 512);

    task_lock(task);

    /*获取当前进程的内存空间信息*/
    if(task->mm && task->mm->mmap)
        vma = task->mm->mmap;
    else
    {
        task_unlock(task);
        kfree(tpath);
        return NULL;
    }

    /*取得path(a struct 含dentry和vfsmount)*/
    while(vma)
    {
        if((vma->vm_flags & VM_EXEC) && vma->vm_file)
        {
            base_path = vma->vm_file->f_path;
            break;
        }
        vma = vma->vm_next;
    }
    task_unlock(task);

    /*调用d_path,得到绝对路径*/
    ret_ptr = d_path(&base_path, tpath, 512);

    return ret_ptr;
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

int my_openfile(int dfd, const char __user *pathname)
{
    int error;
    unsigned long mmm = 0;
    char *userPath = NULL;
    char *dirPath = NULL;
    const char *absolutePath = NULL;

   if(dfd != -100)
    {
        dirPath = get_absolute_pathWithFd(current, dfd);
        
        if((mmm = getUserMem(strlen(dirPath)*2)) < 0)
            return (-ENOMEM);
        else
            userPath = (void*)mmm+2;

        if((error = copy_to_user(userPath, dirPath, strlen(dirPath))) != 0)
            return error;
        
        absolutePath = strcat(strcat(userPath, "/"), pathname);  /*将文件名和绝对路径连接起来，形成的完整的路径传给open*/
        printk(KERN_ALERT "###############dfd is %d,----opening %s in %s dir.....\n", dfd, pathname, absolutePath);
    } else {
        absolutePath = pathname;
    }

    if((error = orig_open(absolutePath, O_RDWR | O_SYNC, 0)) < 0)
    {
        printk(KERN_INFO "open %s failed %d\n",absolutePath,error);
        return error; 
    }

    return error;
}

int my_unlinkat(int dfd, const char __user *pathname, int flag)
{
    int ret, fd;
    char *newfilename = 0;
    unsigned long mmm = 0;
    struct stat *user_lstat;
    struct stat kernel_lstat;
    char newname[strlen(pathname) + 1];
    char *dirPath = NULL;
    char *userPath = NULL;
    const char *absolutePath = NULL;
    const char *newPathFile = NULL;
    char * tempPath = NULL;

    strcpy(newname, pathname);
    sdel_random_filename(newname);

    //getname、putname

    mmm = current->mm->brk;  /*定位当前进程数据段的大小*/
    ret = orig_brk(mmm+strlen(pathname)+1);
    if(ret < 0)
    {
        printk(KERN_INFO "Can't allocate userspace mem \n");
        return (-ENOMEM);
    }
    newfilename = (void*)mmm+2;
    //if((ret = copy_to_user(newfilename,"testRename",strlen("testRename"))) != 0)
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
        dirPath = get_absolute_pathWithFd(current, dfd);

        if((mmm = getUserMem(strlen(dirPath)*2+1)) < 0)
            return (-ENOMEM);
        else
            userPath = (void*)mmm+2;

        if((mmm = getUserMem(strlen(dirPath)*2+1)) < 0)
            return (-ENOMEM);
        else
            tempPath = (void*)mmm+2;
        printk(KERN_INFO "userPath=%s\n", userPath);
        if((ret = copy_to_user(userPath, dirPath, strlen(dirPath))) != 0)
        {
            printk(KERN_ERR "copy_to_user userPath error %d\n", ret);
            return ret;
        }
        if((ret = copy_to_user(tempPath, dirPath, strlen(dirPath))) != 0)
        {
            printk(KERN_ERR "copy_to_user tempPath error %d\n", ret);
            return ret;
        }
        printk(KERN_ALERT "#####kernel_dirpath=%s, userPath=%s\n", dirPath, userPath);
        absolutePath = strcat(strcat(userPath, "/"), pathname);
        printk(KERN_ALERT "#####absolutePath=%s, newPathFileNULL=%s, pathname=%s, newfilename=%s\n", absolutePath, newPathFile, pathname, newfilename);
        printk(KERN_ALERT "#####tempPath=%s\n",tempPath);
        newPathFile = strcat(strcat(tempPath, "/"), newfilename); 
        printk(KERN_ALERT "#####absolutePath=%s, newPathFileISNOTNULL=%s, pathname=%s, newfilename=%s\n", absolutePath, newPathFile, pathname, newfilename);
        ret = orig_rename(absolutePath, newPathFile);
        
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
  //  printk(KERN_ALERT "rename is %d, unlinkat file %s of rename testRename\n",ret, newfilename);
    if((ret = orig_unlinkat(dfd, newfilename, flag)) < 0)
    {
        if(dfd != -100)
            orig_rename(newPathFile, absolutePath);
        else
            orig_rename(newfilename, pathname); //文件删除失败，rename回原本的文件名
        printk(KERN_ALERT "unlinkat file %s error\n",pathname);
        return ret;
    }

    mmm = current->mm->brk;
    ret = orig_brk(mmm + sizeof(struct stat));
    user_lstat = (void*)mmm + 2;
    //printk(KERN_INFO "after %s\n",newfilename);
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
        if(S_ISREG(kernel_lstat.st_mode) && ret >= 0 && kernel_lstat.st_nlink == 1 && kernel_lstat.st_size > 0)
        {
            printk(KERN_INFO "isreg file, %s size is %ld\n",newfilename, kernel_lstat.st_size);
            smash_file(fd, pathname, kernel_lstat);
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
