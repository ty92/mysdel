/*************************************************************************
	> File Name: hello.c
	> Author: 
	> Mail: 
	> Created Time: 2017年06月14日 星期三 15时01分41秒
 ************************************************************************/

#include <linux/init.h>
#include <linux/module.h>

static int hello_init(void)
{
    printk(KERN_INFO "[init] Can you feel me?\n");
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

