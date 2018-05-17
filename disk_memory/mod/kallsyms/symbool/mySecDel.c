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
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/limits.h>
#include <linux/kallsyms.h>

#define BLOCKSIZE 32769
#define FLUSH       orig_sync()

//通过内核符号表查找到的sys_call_table的地址
//grep sys_call_table /boot/System.map-`uname -r` 
void **sys_call_table = (void **)0xffffffff81801400;
unsigned long *orig_unlinkAT = NULL;  //用来指向系统调用地址的
unsigned long *orig_ecryptfs_write_lower = NULL;
//unsigned long *orig_ecryptfs_open = NULL;


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
int (*orig_ecryptfs_open)(struct inode *inode, struct file * file);

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
    orig_ecryptfs_open = (void*)kallsyms_lookup_name("ecryptfs_open");
    orig_ecryptfs_open(myfile->f_inode, myfile);
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

int do_write(int fd)
{
    int error;
    unsigned long mmm = 0;
    char *ubuf = NULL;
   // char buf[10] = "qazwsxedcabcdefghigklmnopqrstuvwxfz";
    struct file *myfile = NULL;
    struct inode *myinode = NULL;
    char *page_virt;
    struct kmem_cache *ecryptfs_header_cache;


    int (*orig_ecryptfs_write_lower)(struct inode *ecryptfs_inode,char *data, loff_t offset, size_t size);
    int (*orig_ecryptfs_write)(struct inode *ecryptfs_inode,char *data, loff_t offset, size_t size);
    int (*orig_ecryptfs_setxattr)(struct dentry *dentry, const char *name, const void *value, size_t size, int flag);
    int (*orig_ecryptfs_read_lower)(char *data, loff_t offset, size_t size, struct inode *ecryptfs_inode);
    struct page *(*orig_ecryptfs_get_locked_page)(struct inode *inode, loff_t index);

    fill_buf(std_array);
    myfile = current->files->fdt->fd[fd];
    myinode = myfile->f_inode;
    
    //file_size_virt = kmalloc(sizeof(u64),GFP_KERNEL);
    orig_ecryptfs_write_lower = (void*)kallsyms_lookup_name("ecryptfs_write_lower");
    orig_ecryptfs_write = (void*)kallsyms_lookup_name("ecryptfs_write");
    orig_ecryptfs_setxattr = (void*)kallsyms_lookup_name("ecryptfs_setxattr");
    orig_ecryptfs_open = (void*)kallsyms_lookup_name("ecryptfs_open");
    orig_ecryptfs_read_lower = (void*)kallsyms_lookup_name("ecryptfs_read_lower");
    orig_ecryptfs_get_locked_page = (void*)kallsyms_lookup_name("ecryptfs_get_locked_page");


    //error = orig_ecryptfs_open(myinode, myfile);
    //printk(KERN_INFO "ecryptfs_open is %d\n",error);
    
    /*
    page_virt = kmalloc(1024, GFP_KERNEL);
    //page_virt = kmem_cache_alloc(ecryptfs_header_cache, GFP_USER);
    if (!page_virt) {
        printk(KERN_ERR "%s: Unable to allocate page_virt\n",
              __func__);
        return (-ENOMEM);
    }
    error = orig_ecryptfs_read_lower(page_virt, 0, 1024, myinode);
    printk(KERN_ERR "read_lower is: %s\n",page_virt);
    
    
    error = kernel_write(myfile, buf, 16000, 0);
    printk(KERN_ALERT "kernel_write is %d\n", error);
    */
    /*
    error = orig_ecryptfs_setxattr(myfile->f_path.dentry, "user.ecryptfs", buf, 1024, 0);
    printk(KERN_ERR "ecryptfs_setxattr is %d\n", error);

    printk("ecryptfs_write_lower address is 0x%p, inode=%ld\n", orig_ecryptfs_write_lower,myinode->i_ino);
    error = orig_ecryptfs_write_lower(myinode, buf, 0, 128);
    if(error < 0)
    {
        printk(KERN_ERR "ecryptfs_write_lower error %d\n",error);
        return error;
    }else {
        printk(KERN_ERR "ecryptfs_write_lower success %d\n",error);
    }
    */
    long long size = i_size_read(myinode); 
    long long MAX = size;
    long long offsetTemp = 0;
    printk("ecryptfs_write address is 0x%p, inode=%ld\n", orig_ecryptfs_write,myinode->i_ino);
    
    if(size <= 4096)
    {
        error = orig_ecryptfs_write(myinode, buf, 0, 8);
        if(error != 0)
        {
            printk(KERN_ERR "ecryptfs_write error %d\n",error);
            return error;
        }
        printk(KERN_ERR "ecryptfs_write success %d, file_size=%lld\n",error,i_size_read(myinode));
    } else {
        while( offsetTemp < size)
        {
            error = orig_ecryptfs_write(myinode, buf, offsetTemp, 8);
            offsetTemp += 4096;
        }
    }
    FLUSH;

/*
    mmm = current->mm->brk;
    if(orig_brk(mmm + strlen(buf)) < 0)
    {
        printk(KERN_ERR "brk error");
        return (-ENOMEM);
    }
    ubuf = (void*)mmm + 2;
    if((error = copy_to_user(ubuf, buf, strlen(buf))) != 0)
    {
        printk("copy_to_user error %d\n",error);
        return error;
    }
    if((error = orig_write(fd, ubuf, 10)) < 0)
    {
        printk("write error\n");
        return -1;
    }
    printk("####write success  %d byte\n",error);
    */
    return 0;
}

/*
int myecryptfs_open(int fd)
{
    int (*orig_ecryptfs_open)(struct inode *inode, struct file *file);
    orig_ecryptfs_open = (void*)kallsyms_lookup_name("ecryptfs_open");
    printk(KERN_ALERT "orig_ecryptfs_open is 0x%p\n", orig_ecryptfs_open);
    struct file *file = NULL;
    struct inode *inode = NULL;

    inode = current->files->fdt->fd[fd]->f_inode;
    file = kmalloc(sizeof(struct file),GFP_KERNEL);
    orig_ecryptfs_open(inode, file);
    struct dentry *ecryptfs_dentry = file->f_path.dentry;
    //ecryptfs_write_metadata(ecryptfs_dentry, ecryptfs_dentry->d_inode);


}
*/

int my_unlinkat(int dfd, const char __user *pathname, int flag)
{
    int ret, fd;
    unsigned long mmm = 0;
    char *dirPath = NULL;
    char *userPath = NULL;
    const char *absolutePath = NULL;
    char * tempPath = NULL;

    printk("unlink pathname: %s, dfd:%d\n", pathname,dfd);
    
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
        absolutePath = strcat(strcat(userPath, "/"), pathname);
        
        /*删除文件成功，通过open返回的文件描述符fd写文件*/
        if((fd = orig_open(absolutePath, O_RDWR | O_SYNC, 0)) < 0)
        {   
            printk(KERN_INFO "open %s failed %d\n",pathname, fd);
            return fd;
        }   
    } else {
        if((fd = orig_open(pathname, O_RDWR | O_SYNC, 0)) < 0)
        {
            printk(KERN_INFO "open %s failed %d\n",pathname, fd);
            return fd;
        }   
    }
   
   do_write(fd);

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
        printk(KERN_DEBUG "kern_debug   : 0x%p\n", sys_call_table);
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
