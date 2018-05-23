#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/fdtable.h>
#include <linux/syscalls.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/limits.h>

void **sys_call_table = (void **)0xffffffff81801400;
int (*orig_chdir)(const char __user *filename);

static int useruid;
module_param(useruid, int, 0644);

int make_rw(unsigned long address)
{
        unsigned int level;
        pte_t *pte = lookup_address(address, &level);//查找虚拟地址所在的页表地址
        //设置页表读写属性
        pte->pte |=  _PAGE_RW;

        return 0;
}

/*
 * make the page write protected 
 */
int make_ro(unsigned long address)
{
        unsigned int level;
        pte_t *pte = lookup_address(address, &level);
        pte->pte &= ~_PAGE_RW; //设置只读属性

        return 0;
}

int my_chdir(const char __user *filename)
{
	uid_t uid;
	int ret;

	uid = from_kuid_munged(current_user_ns(), current_euid());
	
	printk(KERN_INFO "user input uid is %d\n",useruid);

	if(useruid == uid) {
                printk(KERN_INFO "IF:::current uid is user input %d...\n",useruid);
        } else {
		printk(KERN_INFO "ELSE:::the current uid is not user input %d\n",uid);	
	}
	
        ret = orig_chdir(filename);
	return ret;
}

static int syscall_init_module(void)
{
	uid_t uid;
	uid = from_kuid_munged(current_user_ns(), current_euid());
	printk(KERN_INFO "the current uid is %d\n",uid);

	orig_chdir = sys_call_table[__NR_chdir];

        printk(KERN_INFO "insmod kernel module.\n");
        make_rw((unsigned long)sys_call_table); //修改页属性
        sys_call_table[__NR_chdir] = (unsigned long *)my_chdir; //设置新的系统调用地址
        make_ro((unsigned long)sys_call_table);

	return 0;
}

static void syscall_cleanup_module(void)
{
	printk(KERN_ALERT "Module syscall unloaded.\n");
	make_rw((unsigned long)sys_call_table);
        sys_call_table[__NR_chdir] = (unsigned long *)orig_chdir;
        make_ro((unsigned long)sys_call_table);
}

module_init(syscall_init_module);
module_exit(syscall_cleanup_module);

MODULE_LICENSE("GPL");
