/*************************************************************************
	> File Name: hello.c
	> Author: 
	> Mail: 
	> Created Time: 2017年06月14日 星期三 15时01分41秒
 ************************************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fdtable.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

void **sys_call_table = (void **)0xffffffff81801400;
unsigned long *orig_unlinkAT = NULL;  //用来指向系统调用地址的
int (*orig_rename)(const char *oldname, const char *newname);
//long (*orig_open)(const char __user *filename, int flags, umode_t mode);
struct filename *(*orig_getname)(const char __user *filename);

static int hello_init(void)
{
    int error;
    struct filename *tmp;
    char *filename = "/home/tiany/paper/mod/mySdelNotEcrypt_success/aaa";
    printk(KERN_INFO "[init] Can you feel me?\n");
    orig_rename = sys_call_table[__NR_rename];
  //  orig_open = sys_call_table[__NR_open];
    //orig_getname = (void*)kallsyms_lookup_name("getname");

    /*
    mm_segment_t old_fs_value = get_fs();
    printk(KERN_INFO "get_fs is 0x%p\n",old_fs_value);

    set_fs(get_ds());
    printk(KERN_INFO "set_fs(KERNEL_DS) is 0x%p\n",get_fs());
    printk(KERN_INFO "getname address is 0x%p\n", orig_getname);
    tmp = orig_getname(filename);
    if(IS_ERR(tmp))
    {
        printk(KERN_INFO "getname is error  %p\n",tmp);
        return PTR_ERR(tmp);
    }
    */
    error = do_sys_open(AT_FDCWD, filename, O_RDWR, 0);
    if(error < 0)
        printk(KERN_INFO "orig_open is %d, -14 is bad address.\n",error);
    else
        printk(KERN_INFO "orig_open success is %d\n",error);
    
    //set_fs(old_fs_value);

    /*
    mm_segment_t old_fs_value = get_fs();
    set_fs(get_ds());
    error = orig_rename("/home/tiany/paper/mod/mySdelNotEcrypt_success/test", "aaa");
    if(error < 0)
        printk(KERN_INFO "orig_rename is %d, -14 is bad address.\n",error);
    else
        printk(KERN_INFO "orig_rename success is %d\n",error);
    set_fs(old_fs_value);
    */
    return 0;
}

static void hello_exit(void)
{
    printk(KERN_INFO "[exit] Yes.\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_AUTHOR("Tiany<@qq.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("A simple module");

