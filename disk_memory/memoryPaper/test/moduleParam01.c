/* 测试程序：失败
   进程用户地址空间各自独立，使用传参的方式传入进程pid，
   得到其VMA起始地址，到这都是可以得，但是在内核模块中对从pid获得
   的虚拟地址，进行覆写操作，就会报错，就是因为，写操作只是对应当
   前进程地址空间中的地址，因而，从pid获得的其他进程的地址写操作，
   会报错：BUG: unable to handle kernel paging request at 00007f5713810000
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

unsigned char write_modes[27][3] = {
   {"\x55\x55\x55"}, {"\xaa\xaa\xaa"}, {"\x92\x49\x24"}, {"\x49\x24\x92"},
   {"\x24\x92\x49"}, {"\x00\x00\x00"}, {"\x11\x11\x11"}, {"\x22\x22\x22"},
   {"\x33\x33\x33"}, {"\x44\x44\x44"}, {"\x55\x55\x55"}, {"\x66\x66\x66"},
   {"\x77\x77\x77"}, {"\x88\x88\x88"}, {"\x99\x99\x99"}, {"\xaa\xaa\xaa"},
   {"\xbb\xbb\xbb"}, {"\xcc\xcc\xcc"}, {"\xdd\xdd\xdd"}, {"\xee\xee\xee"},
   {"\xff\xff\xff"}, {"\x92\x49\x24"}, {"\x49\x24\x92"}, {"\x24\x92\x49"},
   {"\x6d\xb6\xdb"}, {"\xb6\xdb\x6d"}, {"\xdb\x6d\xb6"}
};

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

static pte_t* dump_pagetable(struct mm_struct *mm,unsigned long address)
{
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;

	pgd = pgd_offset(mm, address);
        if (!pgd_present(*pgd))
                goto out;

        pud = pud_offset(pgd, address);

        if (!pud_present(*pud) || pud_large(*pud))
                goto out;

        pmd = pmd_offset(pud, address);

        if (!pmd_present(*pmd) || pmd_large(*pmd))
                goto out;

        pte = pte_offset_kernel(pmd, address);

        return pte;
out:
        return 0;
}

static int syscall_init_module(void)
{
        struct task_struct *p;
        struct vm_area_struct *temp;
	pte_t *uppte;
        unsigned long start,end;
        struct page *page;

        printk(KERN_ALERT "###inside Module\n");

        p = pid_task(find_vpid(pid), PIDTYPE_PID);
        temp = p->mm->mmap;
        printk(KERN_INFO "pid is %d\n",pid);

        while(temp) {
                printk(KERN_INFO "start: %p\t end: %p\n",(unsigned long*)temp->vm_start,(unsigned long*)temp->vm_end);
		
		if((temp->vm_flags & VM_WRITE) && (temp->vm_file == NULL)) {
                	for(start=temp->vm_start,end=temp->vm_end; start < end; start=start+4096) {
				printk(KERN_INFO "start address is: %p\n",(unsigned long*)start);

                	        uppte = dump_pagetable(p->mm, start);
				if(uppte == NULL) {
					printk(KERN_INFO "uppte is NULL...\n");
					continue;
				}
				printk(KERN_INFO "get the pte....\n");

                	        if(pte_present(*uppte) && !pte_none(*uppte)) {
					printk(KERN_INFO "pte has the physical memory page frame...\n");

					page = pte_page(*uppte);					
					printk(KERN_INFO "page->_mapcount.counter is %d\n...",page->_mapcount.counter);					
					atomic_inc(&page->_mapcount);
	
					if(!atomic_dec_and_test(&page->_mapcount))
						continue;	

                        	        printk(KERN_INFO "construct range char...\n");
					fill_buf(write_modes[2]);	// 构造随机字符
                        	        
					printk(KERN_INFO "starting write....");
                        	        if((end-start) > 4096) {
                        	                memcpy((unsigned long*)start,buf,100);
                        	        } else {
                                	        memcpy((unsigned long*)start,buf,end-start);
                                	}
                        	}
                	}
		}
                temp = temp->vm_next;
        }

	return 0;
}

static void syscall_cleanup_module(void)
{
    printk(KERN_ALERT "Module syscall unloaded.\n");
}

module_init(syscall_init_module);
module_exit(syscall_cleanup_module);

MODULE_LICENSE("GPL");
