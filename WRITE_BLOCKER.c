#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/module.h>
#include<linux/printk.h>
#include<linux/security.h>
#include<linux/path.h>
#include<linux/errno.h>
#include<linux/lsm_hooks.h>
#include<linux/fs.h>
#include<linux/sched.h>
#include<uaccess.h>
#include<uapi/linux/lsm_id.h>

static int my_file_permission(struct file *file,int mask)
{
conts char *filename;
char path_buff[265];
if(!(mask&MAY_WRITE))
{
return 0;
}
filename=d_path(&file->f_path,path_buff,sizeof(path_buff));
if(IS_ERR(filename))
{
return 0;
}
if(strcmp(filename,"/else/others.c")==0)
{
pr_info("WRITING TO %s BLOCKED BY %d",filename,current->pid);
return -EACCES;
}
return 0;

}

static struct security_hook_list my_hooks[]={LSM_HOOK_INIT(file_permission,my_file_permission),};
static struct lsm_id my_lsm_id={
	.name="my_wb_lsm",
	.id=LSM_ID_UNDEF,
};
static int __init my_wb_init(void)
{

pr_info("WRITE BLOCKER LOADED");
security_add_hooks(my_hooks,ARRAY_SIZE(my_hooks),&my_lsm_id);
return 0;

}
DEFINE_LSM(simple_lsm)={
 .name="wb_lsm",
 .init=my_wb_init,
};
