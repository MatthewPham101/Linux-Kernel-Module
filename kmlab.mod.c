#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x591299b, "module_layout" },
	{ 0x42160169, "flush_workqueue" },
	{ 0x97934ecf, "del_timer_sync" },
	{ 0x9b08d3e8, "remove_proc_entry" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0x49cd25ed, "alloc_workqueue" },
	{ 0xc6f46339, "init_timer_key" },
	{ 0x1aea54f1, "proc_create" },
	{ 0xf1b09875, "proc_mkdir" },
	{ 0x92997ed8, "_printk" },
	{ 0x6cbbfc54, "__arch_copy_to_user" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xdcb764ad, "memset" },
	{ 0x856092f6, "cpu_hwcaps" },
	{ 0xbcab6ee6, "sscanf" },
	{ 0x12a4e128, "__arch_copy_from_user" },
	{ 0xb788fb30, "gic_pmr_sync" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x89b1d954, "kmem_cache_alloc_trace" },
	{ 0x8b496508, "kmalloc_caches" },
	{ 0x37a0cba, "kfree" },
	{ 0x9c1e5bf5, "queued_spin_lock_slowpath" },
	{ 0xc38c83b8, "mod_timer" },
	{ 0x15ba50a6, "jiffies" },
	{ 0x2d5f69b3, "rcu_read_unlock_strict" },
	{ 0xf1d4f8ae, "pid_task" },
	{ 0xbd4efdcb, "find_vpid" },
	{ 0xc3fa40cc, "cpu_hwcap_keys" },
	{ 0x14b89635, "arm64_const_caps_ready" },
	{ 0x4b0a3f52, "gic_nonsecure_priorities" },
	{ 0xc5b6f236, "queue_work_on" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "7A90B7125EFBD95DE6ABDAB");
