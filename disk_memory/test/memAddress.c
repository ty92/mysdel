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

//static int pid;
//module_param(pid, int, 0644);

static int syscall_init_module(void)
{
    	//unsigned long start,end;
	//struct task_struct *p;
/*      	struct vm_area_struct *temp1;
	wait_queue_head_t timeout_wq;

      	printk(KERN_INFO "The virtual memory areas(VMA) are:\n");
      	//p = pid_task(find_vpid(pid), PIDTYPE_PID);
      	temp1 = current->mm->mmap;


    	while(temp1) {
        	printk(KERN_INFO "start:%lu\tend:%lu, cha: %lu\n", temp1->vm_start,temp1->vm_end, temp1->vm_end-temp1->vm_start);
        	temp1 = temp1->vm_next;
    	}

	printk(KERN_INFO "before.......\n");
	init_waitqueue_head(&timeout_wq); 
	sleep_on_timeout(&timeout_wq, 35000);
	printk(KERN_INFO "after.......\n");
*/
	memcpy((void*)0x7f8413567000,"qweqweqweqweqweqweqweqweeqwrfwergfwegfwefwegwegwrgwrgwrgwrgwrgwrgggggggggggggggggggggggwrgwrrrrgwrwrwrwrwrwrwrwrwrwrwrwrwrwrwrwrwrwrwrwrgwrg",1024);	
	return 0;
}

static void syscall_cleanup_module(void)
{
    printk(KERN_ALERT "Module syscall unloaded.\n");
}

module_init(syscall_init_module);
module_exit(syscall_cleanup_module);

MODULE_LICENSE("GPL");
