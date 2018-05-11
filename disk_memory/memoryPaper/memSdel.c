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


void sdel_random_filename(char *filename) {
    int i;
    unsigned char rand;
    for (i = strlen(filename) - 1; (filename[i] != '/') && (i >= 0);i--)
        if (filename[i] != '.') { /* keep dots in the filename */
            get_random_bytes(&rand, 1);   //export kernel function
            filename[i] = 97 + (int) ((int) rand % 26);
        }
}

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

        return pte;
        //printk("PTE %lx", pte_val(*pte));

     /*   if(pte_present(*pte)){ //参数是值而不是地址
                printk(KERN_INFO "pte_present is %d\n",pte_present(*pte));
                return 0;
        }*/
out:
        return 0;
}

asmlinkage void my_exit_group(int error_code)
{
        struct mm_struct *mm;
        struct vm_area_struct *temp;
        pte_t *uppte;
        unsigned long start,end;

        printk(KERN_ALERT "##############EXIT_GROUP %d, current->pid %d\n", error_code,current->pid);
        /*
          进行覆写操作
        */
        mm = current->mm;
        //printk(KERN_INFO "mm_struct, start_code:%p end_code:%p\n",(unsigned long*)mm->start_code,(unsigned long*)mm->end_code);
        //printk(KERN_INFO "mm_struct, start_data:%p end_data:%p\n",(unsigned long*)mm->start_data,(unsigned long*)mm->end_data);
        //printk(KERN_INFO "mm_struct, start_brk:%p brk:%p\n",(unsigned long*)mm->start_brk,(unsigned long*)mm->brk);
        //printk(KERN_INFO "mm_struct, start_stack:%p\n",(unsigned long*)mm->start_stack);
/*
        temp = mm->mmap;
        while(temp) {
                start = temp->vm_start;
                end = temp->vm_end;
                printk(KERN_INFO "start: %p\t end: %p\n",(unsigned long*)temp->vm_start,(unsigned long*)temp->vm_end);

                //需要确定start+0x1010是正确的
                for(start; start < end; start+0x1010) { //还需要判断end-start是否大于4096一个页的大小
                        uppte = dump_pagetable(start);
                        if(pte_present(*uppte)) {
                                fill_buf(write_modes[2]);
                                //存在物理页面，覆写  
                                if((end-start) > 0x1010) {
                                        //memcpy() 覆写4096大小
                                        memcpy((unsigned long*)start,buf,bufsize);
                                } else {
                                        //覆写end-start大小
                                        memcpy((unsigned long*)start,buf,end-start);
                                }
                        }
                }
                temp = temp->vm_next;
        }
*/
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
