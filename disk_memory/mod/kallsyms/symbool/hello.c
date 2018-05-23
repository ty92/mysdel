/*************************************************************************
	> File Name: hello.c
	> Author: 
	> Mail: 
	> Created Time: 2017年06月14日 星期三 15时01分41秒
 ************************************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>

int my_ecryptfs_write_lower = NULL;
unsigned long *orig_ecryptfs_write_lower = NULL;

static int hello_init(void)
{
    unsigned long *my_ecryptfs_write_lower = NULL;
    unsigned long *orig_ecryptfs_write_lower = NULL;
    printk(KERN_INFO "[init] Can you feel me?\n");
    my_ecryptfs_write_lower = (void*)kallsyms_lookup_name("ecryptfs_write_lower");
    printk(KERN_INFO "do_rmdir address is 0x%p\n", my_ecryptfs_write_lower);
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

