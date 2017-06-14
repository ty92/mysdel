#include <linux/module.h>       /* Needed by all modules */
#include <linux/kernel.h>       /* Needed for log level */
#include <linux/init.h>         /* Needed for the macros */
//#include <linux/syscalls.h>         /* Needed for the macros */
 
MODULE_LICENSE("GPL");
MODULE_VERSION("Version-0.0.1");
 
long (*sys_getpid)(void) = (long*)0xffffffff81081410;
static int __init hello_start(void)
{
	printk(KERN_INFO "Loading module.....");
	printk(KERN_INFO "PID=%ld\n",sys_getpid());
return 0;
}
 
static void __exit hello_end(void)
{
printk(KERN_INFO "Goodbye, Jay.\n");
}
 
module_init(hello_start);
module_exit(hello_end);
