/**
 * 实现功能：能够正常删除文件和非绝对路径的目录文件；
 *			对于相对目录文件，能够删除目录中的文件和子目录文件，对于目录本身不能同时删除，
 *			需要再次执行删除命令才会删除目录;绝对路径的删除正常
 *		对于使用unlink（删除一个文件）和rmdir（删除空目录）命令的删除操作不起作用
 *
 * **/
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
#include <linux/slab.h>
#include <asm/unistd.h>
#include <linux/random.h>
#include <linux/syscalls.h>
#include <asm/syscalls.h>
#include <linux/errno.h>
#include <asm/uaccess.h>

#define LOG(x,y) printk( KERN_DEBUG "sdel-mod: " x,y )

#ifndef AT_REMOVEDIR 
#define  AT_REMOVEDIR 0X200
#endif

#if !defined SEEK_SET
 #define SEEK_SET 0
#endif

void **sys_call_table = (void **)0xffffffff8164e400;

int (*unlinkat_orig)(int dfd, const char *filename, int flags);
int (*lstat_orig)( const char *file_name, struct stat *buf );
int (*fstat_orig)(int filedes, struct stat *buf);
int (*rename_orig)(const char *oldpath, const char *newpath);
int (*open_orig)(const char *filename, int flags);
int (*close_orig)(int fd);
ssize_t (*read_orig)(int fd, void *buf, size_t count);
ssize_t (*write_orig)(int fd, const void *buf, size_t count);
int (*sync_orig)(void);
int (*fsync_orig)(int fd);
off_t (*lseek_orig)(int fildes, off_t offset, int whence);
int (*setrlimit_orig)(int resource, const struct rlimit *rlim);
int (*brk_orig)(void *end_data_segment);
long (*rmdir_orig)(const char *pathname);
long (*unlink_orig)(const char *pathname);
long (*getcwd_orig)(char *buf, unsigned long size);
long (*fchdir_orig)(unsigned int fd);
long (*chdir_orig)(const char *filename);

void cleanup_module(void);

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

#define DIR_SEPERATOR	'/'
#define FLUSH		sync_orig()
#define BLOCKSIZE       32769

#ifndef O_SYNC
 #ifdef O_FSYNC
  #define O_SYNC O_FSYNC
 #else
  #define O_SYNC 0
 #endif
#endif

#define RAND_MAX        2147483647

unsigned long bufsize = BLOCKSIZE;
char buf[BLOCKSIZE];
int slow = O_SYNC;

void __sdel_random_filename(char *filename) {
    int i;
    unsigned char rand;
    for (i = strlen(filename) - 1;
         (filename[i] != '/') && (i >= 0);
         i--)
        if (filename[i] != '.') { /* keep dots in the filename */
            get_random_bytes(&rand, 1);   //export kernel function
            filename[i] = 97 + (int) ((int) rand % 26);
        }
}

/*
 * secure_unlink function parameters:
 * filename   : the file or directory to UNLINK
 *
 * returns 0 on success, -1 on errors.
 */
static int sdel_unlinkat(int dfd, const char *filename) {
   int turn = 0;
   int result,ret;
   char newname[strlen(filename) + 1]; // just in kernelspace
   char *ul_newname=0; // for memory in userspace, syscalls need all userspace 
   unsigned long mmm=0; // for storing old memory pointer
   struct stat filestat;

/* Generate random unique name, renaming and deleting of the file */
    strcpy(newname, filename); // not a buffer overflow as it has got the exact length

	printk(KERN_ERR "unlinkat is file %s\n",filename);

    do {
        __sdel_random_filename(newname);
        if ((result = lstat_orig(newname, &filestat)) >= 0)
            turn++;
    } while ((result >= 0) && (turn <= 100));
	printk(KERN_INFO "newname %s\n",newname);

    if (turn <= 100) {
       mmm = current->mm->brk;
       if( brk_orig((void*) mmm + strlen(filename) + 1 ) < 0) {
	       printk(KERN_INFO "Can't allocate userspace mem \n");
	       return (-ENOMEM);
       }
       ul_newname = (void*)(mmm + 2); // set variable to new allocates userspace mem
       if((ret = copy_to_user(ul_newname,newname,strlen(newname))) != 0)
		   return ret;
       result = rename_orig(filename, ul_newname);
       if (result != 0) {
          printk(KERN_INFO "Warning: Couldn't rename %s\n", filename);
          strcpy(newname, filename);
       }
    } else {
		printk(KERN_INFO "Warning: Couldn't find a free filename for %s\n",filename);
       strcpy(newname, filename);
    }

	printk(KERN_INFO "rename_orig ul_newname %s\n",ul_newname);
    result = unlinkat_orig(dfd, ul_newname, 0);
    if (result) {
        printk(KERN_INFO "Warning: Unable to unlink file %s\n", filename);
        (void) rename_orig(newname, filename);
    }
#if defined _DEBUG_
      else
        printk(KERN_INFO "Renamed and unlinked file %s\n", filename);
#endif

    if (result != 0)
        return -1;

    if( brk_orig((void*) mmm) < 0 )
	    return (-ENOMEM);
	printk(KERN_INFO "delete  it ok...... %s\n",filename);
    return 0;
}
/*
static int sdel_rmdir(const char *filename)
{
	printk(KERN_ERR "unlinkat is dir %s\n",filename);
	rmdir_orig(filename);
	return 0;
}
*/
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

static int random_buf(char* ul_buf) {
	int ret;

	get_random_bytes(buf, bufsize);
	if((ret = copy_to_user(ul_buf, buf, bufsize)) != 0)
		return ret;
	return 0;
}

static int smash_it(const char *ul_filename, const char*kl_filename, struct stat kl_filestat, int mode) {
	unsigned long writes;
	unsigned long small_wrte;
	unsigned long counter;
	unsigned long filesize;
	struct stat kl_controlstat;
	struct stat *tmp;
	int turn;
	int i, ret;
	int kl_file;

	unsigned long mmm;
	char *ul_buf = NULL;

#if defined _DEBUG_
	LOG("smashing with mode %d\n", mode);
#endif

/* if the blocksize on the filesystem is bigger than the on compiled with, enlarge! */
	if (kl_filestat.st_blksize > bufsize) {
		if (kl_filestat.st_blksize > ( BLOCKSIZE - 3 ))
			bufsize = BLOCKSIZE;
		else
			bufsize = (((kl_filestat.st_blksize / 3) + 1) * 3);
	}

/* open the file for writing in sync. mode */
	if ((kl_file = open_orig(ul_filename, O_RDWR | O_SYNC)) < 0) {
		printk(KERN_INFO "open failed %d\n", kl_file);
		return kl_file;
	}

//	LOG("open %s\n", "ok");

	mmm = current->mm->brk;
	if(brk_orig((void*) mmm + sizeof(struct stat)) < 0) {
		printk(KERN_INFO "brk %s\n", "failed");
		return (-ENOMEM);
	}

	tmp = (void*)(mmm +  2);
//	LOG( "brk %s\n","ok" );

	// do we need to check for races? hmmm
	if ((i = fstat_orig(kl_file, tmp)) < 0) {
		printk(KERN_INFO "fstat failed %d\n", i);
		if (brk_orig((void*) mmm) < 0)
			return (-ENOMEM);
		return i;
	}
//	LOG( "brk %s\n","ok" );

	if((ret = copy_from_user(&kl_controlstat, tmp, sizeof(struct stat))) != 0 )
		return ret;
	if (brk_orig((void*) mmm) < 0)
		return (-ENOMEM);

	if ((kl_filestat.st_dev != kl_controlstat.st_dev) || (kl_filestat.st_ino != kl_controlstat.st_ino) ||
	    (! S_ISREG(kl_controlstat.st_mode))) {
		printk(KERN_INFO "RACE - CONDITION %s\n"," " );
		return (-EIO);
	}

/* calculate the number of writes */
	filesize = kl_filestat.st_size;
	printk(KERN_INFO "filename %s size is %ld %ld\n",ul_filename,filesize,kl_controlstat.st_size);
	writes = (1 + (filesize / bufsize));
	small_wrte = filesize % bufsize;
	printk(KERN_INFO "start overwriting in mode %d\n", mode);

//	if (mode != 0) {
		fill_buf(std_array);

		mmm = current->mm->brk;
		if (brk_orig((void*) mmm + bufsize) < 0) {
			LOG("brk %s\n", "failed");
			return (-ENOMEM);
		}

		printk(KERN_INFO "278 ...........\n");
		ul_buf = (void*)(mmm + 2);
		if((ret = copy_to_user(ul_buf, buf, bufsize)) != 0)
			return ret;

		for (counter=1; counter<=writes && writes>1; counter++) {
			if ((i = write_orig(kl_file, ul_buf, bufsize)) < 0)
				LOG("write failure: %d\n", i);
		}
		printk(KERN_INFO "287 ...........\n");
		if ((i = write_orig(kl_file, ul_buf, small_wrte)) < 0)
			LOG("write failure: %d\n", i);

		if (fsync_orig(kl_file) < 0)
			FLUSH;
		printk(KERN_INFO "write over.........\n");
//	}

/* do the overwriting stuff */
    if (mode > 0) {
	for (turn=0; turn<=36; turn++) {

		if (lseek_orig(kl_file, SEEK_SET, 0) < 0)
			LOG( "lseek %s\n", "failed");

		if ((mode < 2) && (turn > 0))
			break;

		if ((turn>=5) && (turn<=31)) {
			fill_buf(write_modes[turn-5]);
			if((ret = copy_to_user(ul_buf, buf, bufsize)) != 0)
				return ret;
			for (counter=1; counter<=writes; counter++)
				write_orig(kl_file, ul_buf, bufsize);
		}
		else {
			for (counter=1; counter<=writes; counter++) {
				if(random_buf(ul_buf) == 0)
					write_orig(kl_file,ul_buf,bufsize);
			}
		}

		printk(KERN_INFO "inside mode > 0\n");
		if (fsync_orig(kl_file) < 0)
			FLUSH;
	}
    }

	if (brk_orig((void*) mmm) < 0)
		return (-ENOMEM);

	printk(KERN_INFO "335 write over.........\n");

/* Hard Flush -> Force cached data to be written to disk */
//	FLUSH;

	printk(KERN_INFO "341 write over.........\n");
  /*open + truncating the file, so an attacker doesn't know the diskblocks */
/*	if ((kl_file = open_orig(ul_filename, O_WRONLY | O_TRUNC | slow)) >= 0)
		close_orig(kl_file);
*/
	if (brk_orig((void*) mmm) < 0)
		return (-ENOMEM);

	printk(KERN_INFO "smash it ok...... %s\n",ul_filename);
	return 0;
}

char * get_path(struct task_struct *mytask, int fd)
{
		char *end;
		char *dirpath = NULL;
        struct file *myfile = NULL;
        struct files_struct *files = NULL;
        char path[100] = {'\0'};
        char *ppath = path;
        files = mytask->files;
        if (!files) {
                printk("files is null..\n");
                return NULL;
        }
        myfile = files->fdt->fd[fd];
        if (!myfile) {
                printk("myfile is null..\n");
                return NULL;
        }
        ppath = d_path(&(myfile->f_path), ppath, 100);
//		printk("path:%s\n", ppath);

		end = strrchr(ppath,'/');
  //    	printk("filename:%s\n", end);

      	dirpath = (char*)kmalloc(4096,GFP_KERNEL);
		memset(dirpath,0,4096);
      	strncpy(dirpath,ppath,strlen(ppath)-strlen(end));
//      	printk("dirpath:%s\n", dirpath);
//      	kfree(dirpath);


        return dirpath;
}


int wipefile(int dfd, const char *ul_filename,int flags) {
	int ret;
	struct filename *fn;
	struct stat *ul_fs;
	struct stat kl_filestat;
	const char *kl_filename;
	char *current_dir;
	char *cwd = 0;
	unsigned long mmm;

	struct filename* (*getname)(const char *filename) = (void *)0xffffffff811eefe0;
	void (*putname)(struct filename *name) = (void *)0xffffffff811eede0;
	static long (*do_rmdir)(int dfd, const char *pathname) = (void*)0xffffffff811ef240;

	try_module_get(THIS_MODULE); //用于增加模块使用计数，返回0，调用失败，希望使用的模块没有被加载或正在被卸载中

	fn = getname(ul_filename);
	kl_filename = fn->name;
	printk(KERN_INFO "FILE NAME=%s, ul_filename %s,dfd =%d\n",fn->name,ul_filename,dfd);

		if((flags & ~AT_REMOVEDIR) != 0)
				return -EINVAL;
		if(flags & AT_REMOVEDIR)
		{
			printk(KERN_ERR "has a AT_REMOVEDIR falgs %s\n",ul_filename);
			
			current_dir = get_path(current,dfd);
			printk(KERN_INFO "current_dir %s\n",current_dir);			

			ret = do_rmdir(dfd,ul_filename);
			printk("do_rmdir ret %d\n",ret);
		}else {
				current_dir = get_path(current,dfd);
				printk(KERN_INFO "current_dir %s\n",current_dir);			

				ret =fchdir_orig(dfd);   //切换到打开的工作目录中，需要保存当前工作目录，在操作完后切换回来，没有切换，不能删除第一级目录
				printk(KERN_INFO "fchdir ret %d\n",ret);

				mmm = current->mm->brk;
				ret = brk_orig((void*) mmm + sizeof(struct stat));
		        ul_fs = (void*)(mmm + 2);
				if ((ret = (*lstat_orig)(ul_filename, ul_fs)) < 0) {
	                 printk(KERN_ERR "fstat_orig %s\n", ul_filename);
				if (brk_orig((void*) mmm) < 0)
	                return (-ENOMEM);
		        } else {
                    printk(KERN_ERR "no AT_REMOVEDIR falgs %s\n",ul_filename);
                    if((ret = copy_from_user(&kl_filestat, ul_fs, sizeof(struct stat))) != 0)
                        return ret;
                    if (brk_orig((void*) mmm ) < 0)
                        return (-ENOMEM);

                    if (S_ISREG(kl_filestat.st_mode) && ret >= 0 && kl_filestat.st_nlink == 1 && kl_filestat.st_size > 0){
						  printk(KERN_INFO "wipefile filename %s size is %ld\n",ul_filename,kl_filestat.st_size);
                //          ret = smash_it(ul_filename, kl_filename, kl_filestat, 0);
                    }

				ret = sdel_unlinkat(dfd,ul_filename);
/*
				mmm = current->mm->brk;
                if(brk_orig((void*)mmm + strlen(current_dir)) < 0) {
                    printk(KERN_INFO "Can't allocate userspace mem \n");
                    return (-ENOMEM);
                }
                cwd = (void*)(mmm + 2); 
                if((ret = copy_to_user(cwd,current_dir,strlen(current_dir))) != 0)
                    printk(KERN_INFO "copy to user current_dir failed");

				chdir_orig(cwd);
*/
			}	
	}

	kfree(current_dir);
	putname(fn);
	module_put(THIS_MODULE);  //减少模块使用计数，2.6内核后

	return ret;
}

/* make the page writable */
int make_rw(unsigned long address)
{
        unsigned int level;
        pte_t *pte = lookup_address(address, &level);//查找虚拟地址所在的页表地址
    //设置页表读写属性
        pte->pte |=  _PAGE_RW;

        return 0;
}
/* make the page write protected */
int make_ro(unsigned long address)
{
        unsigned int level;
        pte_t *pte = lookup_address(address, &level);
        pte->pte &= ~_PAGE_RW; //设置只读属性

        return 0;
}

int init_module(void) {
        MODULE_LICENSE("GPL");

	printk(KERN_INFO "Loading sdel-mod...\n");

	lstat_orig	= sys_call_table[ __NR_lstat ];
	fstat_orig	= sys_call_table[ __NR_fstat ];
	rename_orig	= sys_call_table[ __NR_rename ];
	open_orig	= sys_call_table[ __NR_open ];
	close_orig	= sys_call_table[ __NR_close ];
	read_orig	= sys_call_table[ __NR_read ];
	write_orig	= sys_call_table[ __NR_write ];
	sync_orig	= sys_call_table[ __NR_sync ];
	fsync_orig	= sys_call_table[ __NR_fsync ];
	lseek_orig	= sys_call_table[ __NR_lseek ];
	setrlimit_orig	= sys_call_table[ __NR_setrlimit ];
	brk_orig	= sys_call_table[ __NR_brk ];
	getcwd_orig	= sys_call_table[ __NR_getcwd ];
	rmdir_orig = sys_call_table[ __NR_rmdir ];
	unlink_orig = sys_call_table[ __NR_unlink ];
	getcwd_orig = sys_call_table[ __NR_getcwd ];
	fchdir_orig = sys_call_table[ __NR_fchdir ];
	chdir_orig = sys_call_table[ __NR_chdir ];

/*#if defined _DEBUG_
	LOG( "syscalls %s\n","ok" );
#endif
*/
	printk(KERN_ERR "syscalls ok\n");
	unlinkat_orig = sys_call_table[ __NR_unlinkat ];
	make_rw((unsigned long)sys_call_table); //修改页属性
	sys_call_table[ __NR_unlinkat ] = (void *)wipefile;
	make_ro((unsigned long)sys_call_table);
#if defined _DEBUG_
	LOG( "unlinkpointer %s\n","ok" );
#endif

	printk(KERN_ERR "unlinkpointer syscalls ok\n");

	return 0;
}

void cleanup_module(void) {
	printk(KERN_INFO "Removing sdel-mod...\n");
	make_rw((unsigned long)sys_call_table);
	sys_call_table[ __NR_unlinkat ] = unlinkat_orig;
	make_ro((unsigned long)sys_call_table);
}
