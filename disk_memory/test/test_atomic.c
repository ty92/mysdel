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
#include <linux/types.h>
  
static int hello_init(void)
{
	printk(KERN_ALERT " insert kernel module.\n");
	atomic_t num;
	atomic_set(&num, -1);
	atomic_inc(&num);
	if(atomic_dec_and_test(&num)) {
		printk(KERN_INFO "atomic_dec_and_test(&num) is %d\n",atomic_dec_and_test(&num));
	} else {
		printk(KERN_INFO "if-else\n");
	}
    	return 0;
}
  
static void hello_exit(void)
{
    	printk(KERN_ALERT"bye bye alen's kernel space..\n");
}
  
module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("Dual BSD/GPL");
