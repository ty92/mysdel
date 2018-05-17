/* 测试程序：失败
     调用exit_group系统调用就需要用户进程退出才会触发，用户进程退出了就无法使用
     gdb-dump查看指定内存区域中的数据，除非在用户进程退出前将虚拟地址转换为对应
     的物理地址，在内核模块中写操作执行结束，使得其睡眠，在这段时间利用技术手段
     获取到指定物理地址中的内存数据进行验证，该方法未进行验证。
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

static int pid;
module_param(pid, int, 0644);

//通过内核符号表查找到的sys_call_table的地址
void **sys_call_table = (void **)0xffffffff81801400;
void (*orig_exit_group)(int error_code);

unsigned char write_modes[27][3] = {
   {"\x55\x55\x55"}, {"\xaa\xaa\xaa"}, {"\x92\x49\x24"}, {"\x49\x24\x92"},
   {"\x24\x92\x49"}, {"\x00\x00\x00"}, {"\x11\x11\x11"}, {"\x22\x22\x22"},
   {"\x33\x33\x33"}, {"\x44\x44\x44"}, {"\x55\x55\x55"}, {"\x66\x66\x66"},
   {"\x77\x77\x77"}, {"\x88\x88\x88"}, {"\x99\x99\x99"}, {"\xaa\xaa\xaa"},
   {"\xbb\xbb\xbb"}, {"\xcc\xcc\xcc"}, {"\xdd\xdd\xdd"}, {"\xee\xee\xee"},
   {"\xff\xff\xff"}, {"\x92\x49\x24"}, {"\x49\x24\x92"}, {"\x24\x92\x49"},
   {"\x6d\xb6\xdb"}, {"\xb6\xdb\x6d"}, {"\xdb\x6d\xb6"}
};

unsigned char std_array[3] = "\xff\xff\xff";

static void fill_buf(char pattern[3])
{
    int loop;
    int where;

    for (loop = 0; loop < (bufsize / 3); loop++)
    {
        where = loop * 3;
        buf[where] = pattern[0];
        buf[where+1] = pattern[1];
        buf[where+2] = pattern[2];
    }
}

void __sdel_fill_buf(char pattern[3], unsigned long bufsize, char *buf) {
    int loop;
    int where;
    
    for (loop = 0; loop < (bufsize / 3); loop++) {
        where = loop * 3;
        *buf++ = pattern[0];
        *buf++ = pattern[1];
        *buf++ = pattern[2];
    }
}

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


/*
 * 根据虚拟地址计算页表项pte，并判断判断页面是否有对应的物理内存
   该函数从CR3寄存器中读取当前进程的物理基地址，只适用于当前进程current
   获取pte，若是要求指定pid进程的pte，则使用pgd_offset(mm,vaddr)获取pgd
 */
static pte_t* dump_pagetable(unsigned long address)
{
        pgd_t *base = __va(read_cr3() & PHYSICAL_PAGE_MASK);
        pgd_t *pgd = base + pgd_index(address);
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;

       // printk("PGD %lx ", pgd_val(*pgd));

        if (!pgd_present(*pgd))
                goto out;

        pud = pud_offset(pgd, address);

        //printk("PUD %lx ", pud_val(*pud));
        if (!pud_present(*pud) || pud_large(*pud))
                goto out;

        pmd = pmd_offset(pud, address);

        //printk("PMD %lx ", pmd_val(*pmd));
        if (!pmd_present(*pmd) || pmd_large(*pmd))
                goto out;

        pte = pte_offset_kernel(pmd, address);

        //printk("PTE %lx", pte_val(*pte));
        return pte;
out:
        return 0;
}

asmlinkage void my_exit_group(int error_code)
{
        struct mm_struct *mm;
        struct vm_area_struct *temp;
        pte_t *uppte;
        unsigned long start,end;
	struct page *page;
	wait_queue_head_t timeout_wq;

        printk(KERN_ALERT "##############EXIT_GROUP %d, current->pid %d\n", error_code,current->pid);
	/* 根据传递的参数pid，对退出的进程进行过滤。
	   是指定pid的进程，则进行覆写操作；否则调用原始exit_group()函数销毁进程
	 */
	if(pid != current->pid) {
		printk(KERN_INFO "pid is not compare，call original exit_group.\n");
		orig_exit_group(error_code);
		return;
	}

        /*
          检查mm_struct是否被共享或者引用,atomic_dec_and_test()检查存在问题，
	  会影响原本mm_users、mm_count的值，造成程序崩溃
        */
        mm = current->mm;
	if(!atomic_dec_and_test(&mm->mm_users)) {
		printk(KERN_ERR "the mm_struct of current process is shared\n");
		return; 
	}
	if(!atomic_dec_and_test(&mm->mm_count)) {
		printk(KERN_ERR "the mm_struct of current process is referenced\n");
		return;
	}

        temp = mm->mmap;	/* 获得mm_strcut中VMA链表*/
        while(temp) {
                printk(KERN_INFO "start: %p\t end: %p\n",(unsigned long*)temp->vm_start,(unsigned long*)temp->vm_end);
		/* 
		  需要判断当前VMA是否有可写权限VM_WRITE,有写权限才可以覆写; 
		  vm_file为NULL，去除文件映射的VMA区域(代码段、库文件映射等)
		 */
		if((temp->vm_flags & VM_WRITE) && (temp->vm_file == NULL)) {
                	/* start+4096(一页大小)，每次一页一页判断处理;
			   地址比较大小，如何做，注意10进制和16进制的运算区别,内存地址直接以unsigned long类型计算;
			   for循环值得初始化需要写在循环中，for(start=…,end=…;…;…),否则会报warning：statement with no effect [-Wunused-value]	 
			 */
                	for(start=temp->vm_start,end=temp->vm_end; start < end; start=start+4096) {
				printk(KERN_INFO "start address is: %p\n",(unsigned long*)start);

                	        uppte = dump_pagetable(start);
				if(uppte == NULL) {
                                        printk(KERN_INFO "the pte is NULL....\n");
                                        continue;
                                } else
                                        printk(KERN_INFO "get the pte....\n");

				/*
 				   页表pte存在P标志位，即就是有映射物理内存，并且页表内存不为空，进程访问过该页
				 */
                	        if(pte_present(*uppte) && !pte_none(*uppte)) {
					printk(KERN_INFO "pte has the physical memory page frame...\n");

					page = pte_page(*uppte);	/* 得到虚拟地址对应的page结构 */				
					printk(KERN_INFO "page->_mapcount.counter is %d\n...",page->_mapcount.counter);					

					/* _mapcount初始值为-1，一个进程引用时加1值变为0，现在不知道有几个进程共享该page，
					   使得_mapcount原子加1，只有一个进程时，调用atomic_dec_and_test()原子的减1后，结果
					   为0，返回true
					 */
					atomic_inc(&page->_mapcount);
	
					/* 判断页表对应的物理页框是否被共享,若共享，则跳过该页;atomic_dec_and_test()原子减1，
					   只有当减一后的结果为0时，返回true，否则返回false
					 */
					if(!atomic_dec_and_test(&page->_mapcount))
						continue;	

                        	        printk(KERN_INFO "construct range char...\n");
					fill_buf(write_modes[2]);	/* 构造随机字符 */
                        	        
					/* 
					  存在物理页面，覆写  
					  还需要判断end-start是否大于4096一个页的大小
					*/
					printk(KERN_INFO "starting write....");
                        	        if((end-start) > 4096) {
                        	                //memcpy() 覆写4096大小
                        	                memcpy((unsigned long*)start,buf,bufsize);
                        	        } else {
                                	        //覆写end-start大小
                                	        memcpy((unsigned long*)start,buf,end-start);
                                	}
                        	}
                	}
		}
                temp = temp->vm_next;
        }
	/*
          实验验证，在用户进程退出时，内核模块中执行完了覆写操作后，先不调用原始退出函数，
          而是使得当前进行睡眠一段时间，此时/proc/pid/maps查看全为vsyscall区域，用户态中
          无法使用gdb-dump-memory保存原有用户虚拟地址区间指定内存段中的内容。该法测试不通
        */
	init_waitqueue_head(&timeout_wq);
	sleep_on_timeout(&timeout_wq, 35000);
        //调用原始exit_group()函数退出
        orig_exit_group(error_code);
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
