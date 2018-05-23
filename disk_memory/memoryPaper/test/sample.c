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


static int pid;
static char *start;
module_param(pid, int, 0644);
module_param(start, charp, 0644);

void **sys_call_table = (void **)0xffffffff81801400;
void (*orig_exit_group)(int error_code);



int make_rw(unsigned long address)
{
        unsigned int level;
        pte_t *pte = lookup_address(address, &level);//查找虚拟地址所在的页表地址
        pte->pte |=  _PAGE_RW;

        return 0;
}

int make_ro(unsigned long address)
{
        unsigned int level;
        pte_t *pte = lookup_address(address, &level);
        pte->pte &= ~_PAGE_RW; //设置只读属性

        return 0;
}


asmlinkage void my_exit_group(int error_code)
{
        printk(KERN_ALERT "##############current->pid %d\n", current->pid);

        if(current->pid == pid)
                memcpy((unsigned long*)start,"ttttttttttttttttttttttttt",25);
}

static int syscall_init_module(void)
{
    printk(KERN_ALERT "###inside Module\n");

    orig_exit_group = sys_call_table[__NR_exit_group];


    make_rw((unsigned long)sys_call_table);
    sys_call_table[__NR_exit_group] = (unsigned long *)my_exit_group;
    make_ro((unsigned long)sys_call_table);
    return 0;
}

static void syscall_cleanup_module(void)
{
    printk(KERN_ALERT "Module syscall unloaded.\n");
    make_rw((unsigned long)sys_call_table);
    sys_call_table[__NR_exit_group] = (unsigned long *)orig_exit_group;
    make_ro((unsigned long)sys_call_table);
}

module_init(syscall_init_module);
module_exit(syscall_cleanup_module);

MODULE_LICENSE("GPL");
