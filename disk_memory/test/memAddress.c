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
module_param(pid, int, 0644);

static int syscall_init_module(void)
{
	struct task_struct *p;
	struct mm_struct *mm;
      	struct vm_area_struct *temp;

      	printk(KERN_INFO "The virtual memory areas(VMA) are:\n");
      	p = pid_task(find_vpid(pid), PIDTYPE_PID);
      	//temp = current->mm->mmap;

	mm = p->mm;
	printk(KERN_INFO "11 mm_users.counter is %d\n",mm->mm_users.counter);
        if(!atomic_dec_and_test(&mm->mm_users)) {
                printk(KERN_ERR "the mm_struct of current process is shared\n");
                return -1;
        }
	printk(KERN_INFO "22 mm_users.counter is %d\n",mm->mm_users.counter);
	printk(KERN_INFO "11 mm_count.counter is %d\n",mm->mm_count.counter);
        if(!atomic_dec_and_test(&mm->mm_count)) {
                printk(KERN_ERR "the mm_struct of current process is referenced\n");
                return -1;
        }
	printk(KERN_INFO "22 mm_count.counter is %d\n",mm->mm_count.counter);

/*
    	while(temp) {
        	printk(KERN_INFO "start:%lu\tend:%lu\n", temp->vm_start,temp->vm_end);
        	temp = temp->vm_next;
    	}
*/
	return 0;
}

static void syscall_cleanup_module(void)
{
    printk(KERN_ALERT "Module syscall unloaded.\n");
}

module_init(syscall_init_module);
module_exit(syscall_cleanup_module);

MODULE_LICENSE("GPL");
