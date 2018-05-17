#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>
  
#define FILE_PATH_READ "/home/tiany/paper/test/hello"
#define FILE_PATH_WRITE "/home/tiany/paper/test/hello"
  
struct file *file = NULL;
struct inode *inode = NULL;
  
unsigned char *file_buf;
loff_t fsize;
mm_segment_t old_fs;
  
/*
 * 内核文件打开函数
 * 参数为文件路径
 * 操作file类型结构变量
 *
 */
static int kernel_file_open(char*file_path)
{
    file = filp_open(file_path,O_RDWR|O_CREAT,0777);
    if(IS_ERR(file)){
        printk("Open file %s failed..\n",file_path);
        return 0;
    }
    inode = file->f_dentry->d_inode;
    printk(KERN_ALERT "###file nlink=%d icount=%d, inode=%ld\n",inode->i_nlink,inode->i_count.counter,inode->i_ino);
  
    return 0;
}
  
/*
 * 内核文件大小获取
 * 参数为获得的文件file结构体
 * 返回文件大小
 *
 */
static loff_t kernel_file_size(struct file *file)
{
    inode = file->f_dentry->d_inode;
    fsize = inode->i_size;
    printk(KERN_ALERT"size = %d\n",(int)fsize);
    return fsize;
}
  
/*
 * 内核文件读函数
 * 封装了vfs_read函数
 *
 */
void* kernel_file_read(struct file *file,loff_t fsize)
{
    unsigned char *buff;
    loff_t *pos = &(file->f_pos);
    buff = kmalloc(fsize+100,GFP_KERNEL);
    vfs_read(file,buff,fsize,pos);
    return buff;
}
  
/*
 * 内核文件写函数
 * 封装了vfs_write函数
 *
 */
static int kernel_file_write(struct file *file,unsigned char* buf,loff_t fsize)
{
    loff_t *pos = &(file->f_pos);
    vfs_write(file,buf,fsize,pos);
    return 0;
}
  
static int hello_init(void)
{
    printk(KERN_ALERT"hello alen's file-test in kernel module.\n");
    kernel_file_open(FILE_PATH_READ);
    /*
    kernel_file_size(file);
    old_fs = get_fs();
    set_fs(KERNEL_DS);//扩展内核空间到用户空间
    file_buf = kernel_file_read(file,fsize);
    filp_close(file,NULL);
    set_fs(old_fs);//恢复内核空间
  
    kernel_file_open(FILE_PATH_WRITE);
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    kernel_file_write(file,file_buf,fsize);
    filp_close(file,NULL);
    set_fs(old_fs);
    */
    return 0;
}
  
static void hello_exit(void)
{
    printk(KERN_ALERT"bye bye alen's kernel space..\n");
}
  
module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("Dual BSD/GPL");
