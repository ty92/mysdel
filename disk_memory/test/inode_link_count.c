#include <linux/version.h>

#if defined(MODVERSIONS)
#include <linux/modversions.h>
#endif
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <asm/unistd.h>
#include <linux/random.h>
#include <linux/syscalls.h>
#include <asm/syscalls.h>
#include <linux/errno.h>
#include <asm/uaccess.h>

void **sys_call_table = (void **)0xffffffff81801400;
unsigned long *orig_unlinkat = NULL;

int (*unlinkat_orig)(int dfd, const char *filename, int flags);
int (*lstat_orig)( const char *file_name, struct stat *buf );
int (*fstat_orig)(int filedes, struct stat __user *buf);
int (*open_orig)(const char *filename, int flags,umode_t mode);
int (*brk_orig)(unsigned long end_data_segment);
long (*unlink_orig)(const char *pathname);

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

unsigned long getUserMem(int length)
{
            unsigned long mmm = 0;
            int ret;

            mmm = current->mm->brk;
            ret = brk_orig(mmm+length);
            if(ret <0)
            {
                    printk(KERN_ERR "Can't allocate userspace mem\n");
                    return (-ENOMEM);
            }

            return mmm;
}


int My_unlinkat(int dfd, const char *filename,int flags) {
        struct stat *user_lstat;
        int fd,ret;
          printk("###unlink pathname: %s, dfd:%d, flag:%d\n", filename,dfd,flags);

        user_lstat = (void*)getUserMem(sizeof(struct stat)) + 2;


         if((fd = open_orig(filename, O_RDWR | O_SYNC, 0)) < 0)
         {
                 printk(KERN_INFO "open %s failed %d\n",filename, fd);
                 return fd;
         }

        printk(KERN_ERR "open after\n");
         if((ret = fstat_orig(fd, user_lstat)) < 0)
         {    printk(KERN_ERR "lstat %s error\n", filename);
              return (-ENOMEM);
         }else {
             printk(KERN_INFO "###%s link=%lu,size=%ld",filename, user_lstat->st_nlink,user_lstat->st_size);
         } 
        if(S_ISREG(user_lstat->st_mode)){
                printk(KERN_INFO "IS reg file\n");
        }

          return 0;
}  

int init_module(void) {
	printk(KERN_INFO "Loading sdel-mod...\n");

	lstat_orig	= sys_call_table[ __NR_lstat ];
	fstat_orig	= sys_call_table[ __NR_fstat ];
	open_orig	= sys_call_table[ __NR_open ];
	brk_orig	= sys_call_table[ __NR_brk ];
	unlink_orig = sys_call_table[ __NR_unlink ];

	orig_unlinkat = (unsigned long *)sys_call_table[ __NR_unlinkat ];
	make_rw((unsigned long)sys_call_table); //修改页属性
	sys_call_table[ __NR_unlinkat ] = (unsigned long *)My_unlinkat;
	make_ro((unsigned long)sys_call_table);

	printk(KERN_ERR "unlinkpointer syscalls ok\n");

	return 0;
}

void cleanup_module(void) {
	printk(KERN_INFO "Removing sdel-mod...\n");
	make_rw((unsigned long)sys_call_table);
	sys_call_table[__NR_unlinkat] = orig_unlinkat;
	make_ro((unsigned long)sys_call_table);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Mysyscall");
