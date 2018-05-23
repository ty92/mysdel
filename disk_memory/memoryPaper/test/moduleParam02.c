/* 测试程序：成功
  在exit_group()时，不是很容易测试进程内存区域的覆写情况，保持用户程序不退出，
  则内核模块无法覆写；程序若退出，在内核模块覆写操作后，使得内核模块线程睡眠，
  则无法在用户态使用gdb获取进程内存数据，也无法读取/proc/pid/maps内容；  

  拦截chdir系统调用完成内存覆写测试，使得用户程序调用chdir()陷入内核，对传入
  内核模块中的pid参数进行匹配，若不是指定pid，则调用原始chdir()内核函数处理，
  匹配pid，则添加覆写操作；
  
  用户程序运行时，先打印pid，然后sleep()一段时间，之后调用chdir()函数，最后
  使用while(1)语句保证程序不退出(为了使用gdb获取进程内存区数据)，在睡眠的这
  段时间将内核模块加入内核；

  内核模块中，判断mm_struct没有被共享，依次判断VMA区域中的地址(去除文件映射区、
  不可写区等)，若pte存在且不为空，对应的page没有被共享，则可以覆写，使用简单
  字符少量的覆写， 可以更明显的使用gdb-dump-memory测试。
 */
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

#define BLOCKSIZE 4096
unsigned long bufsize = BLOCKSIZE;
char buf[BLOCKSIZE];

/* 不同机器，地址不同，需要注意,/proc/kallsyms */
void **sys_call_table = (void **)0xffffffff81801400;

int (*orig_chdir)(const char __user *filename);

static int pid;
module_param(pid, int, 0644);

static void fill_buf(void)
{
	int loop;

	for(loop=0; loop<bufsize-1; loop++) {
		buf[loop]='#';
	}
	//buf[bufsize-1] = '\0';
}

pte_t* dump_pagetable(unsigned long address)
{
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;

	pgd = pgd_offset(current->mm,address);
	printk("PGD %lx ", pgd_val(*pgd));
        if (!pgd_present(*pgd))
                goto out;

        pud = pud_offset(pgd, address);
	printk("PUD %lx ", pud_val(*pud));
        if (!pud_present(*pud) || pud_large(*pud))
                goto out;

        pmd = pmd_offset(pud, address);
	printk("PMD %lx ", pmd_val(*pmd));
        if (!pmd_present(*pmd) || pmd_large(*pmd))
                goto out;

        pte = pte_offset_kernel(pmd, address);
	printk("PTE %lx\n", pte_val(*pte));
        return pte;
out:
	printk(KERN_INFO "get pte error...\n");
        return NULL;
}

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
	struct mm_struct *mm;
        struct vm_area_struct *temp;
	pte_t *uppte;
        unsigned long start,end;
        struct page *page;
	int ret;

        printk(KERN_ALERT "###inside Module, the pid is %d\n", current->pid);

	if(pid != current->pid) {
		printk(KERN_INFO "chdir others...\n");
		ret = orig_chdir(filename);
		return ret;
	}

	/* 检查mm_struct是否被共享或者引用;
	   atomic_dec_and_test()宏原子减一，判断是否为0，此处直接用该宏判断mm_struct
	   是否被多进程共享，存在问题，会影响原本的mm_users、mm_count的值；
	   可直接对其值进行判断.
	 */
        mm = current->mm;
        if(mm->mm_users.counter > 1) {
                printk(KERN_ERR "the mm_struct of current process is shared\n");
                return -1;
        }
        if(mm->mm_count.counter > 1) {
                printk(KERN_ERR "the mm_struct of current process is referenced\n");
                return -1;
        }

	/* 测试使用简单的随机字符"#"，测试效果更加明显 */
        printk(KERN_INFO "construct range char...\n");
        fill_buf();

	temp = current->mm->mmap;
        while(temp) {
                printk(KERN_INFO "start: %p\t end: %p\n",(unsigned long*)temp->vm_start,(unsigned long*)temp->vm_end);
		if((temp->vm_flags & VM_WRITE) && (temp->vm_file == NULL)) {
			for(start=temp->vm_start,end=temp->vm_end; start < end; start=start+4096) {	
				printk(KERN_INFO "start address is: %p\n",(unsigned long*)start);

				/* 获取虚拟地址对应的页表pte信息，若获取失败，则跳过当前页，否则执行下一步 */
				uppte = dump_pagetable(start);
				if(uppte == NULL) {
                                	printk(KERN_INFO "the pte is NULL....\n");
                                	continue;
				} else {
					printk(KERN_INFO "get the pte....\n");
				}

				if(pte_present(*uppte) && !pte_none(*uppte)) {
                                        printk(KERN_INFO "pte has the physical memory page frame...\n");

					/* 利用pte获得page结构，判断page是否被多进程共享;
					   _mapcount初始值为-1，一个进程引用时加1值变为0，现在不知道有几个进程共享该page，
                                           使得_mapcount原子加1，只有一个进程时，调用atomic_dec_and_test()原子的减1后，结果
                                           为0，返回true;
					   判断页表对应的物理页框是否被共享,若共享，则跳过该页;atomic_dec_and_test()原子减1，
                                           只有当减一后的结果为0时，返回true，否则返回false
 					 */
                                        page = pte_page(*uppte);
                                        printk(KERN_INFO "page->_mapcount.counter is %d...\n",page->_mapcount.counter);
					atomic_inc(&page->_mapcount);
					if(!atomic_dec_and_test(&page->_mapcount))
                                                continue;

					printk(KERN_INFO "starting write....");
					/* 用户态程序要被覆写的数据大概有60个字符，此处覆写30个字符，不全覆写，可以更加明显的看出效果 */
                                        if((end-start) > 4096) {
                                                memcpy((unsigned long*)start,buf,30);
                                        } else {
						printk(KERN_INFO "end-start < 4096\n");
						if((end-start)>30)
                                                	memcpy((unsigned long*)start,buf,30);
						else
                                                	memcpy((unsigned long*)start,buf,end-start);
                                        }
                                }
			}
		} else {
			//printk(KERN_INFO "has not VM_WRITE, or is a file\n");
		}
                temp = temp->vm_next;
        }

	printk(KERN_INFO "is starting chdir ...\n");
	ret = orig_chdir(filename);
	printk(KERN_INFO "after chdir ...\n");
	return ret;
}

static int syscall_init_module(void)
{
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
