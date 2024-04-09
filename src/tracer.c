#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include "tracer.h"

MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("LAZAROIU LUCAS <lucas.lazaroiu@stud.acs.upb.ro");
MODULE_LICENSE("GPL v2");

// static int kmalloc_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
// 	return 0;
// }

// static int kmalloc_probe_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
//     struct process_data *pdata;
//     size_t size = regs_return_value(regs);
//     pid_t pid = current->pid;

//     //mutex_lock(&process_table_lock);
//     hash_for_each_possible(process_table, pdata, hlist, pid) {
//         if (pdata->pid == pid) {
//             pdata->kmalloc_count++;
//             pdata->kmalloc_mem_total += size;
//             break;
//         }
//     }
//     //mutex_unlock(&process_table_lock);
//     return 0;
// }

// static int kfree_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
//     return 0;
// }

// static int kfree_probe_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
//     struct process_data *pdata;
//     void *addr = (void*)regs->di;
//     size_t size = regs->di;

//     //mutex_lock(&process_table_lock);
//     hash_for_each_possible(process_table, pdata, hlist, current->pid) {
//         if (pdata->pid == current->pid) {
//             pdata->kfree_count++;
//             pdata->kfree_mem_total += size;
//             break;
//         }
//     }
//     //mutex_unlock(&process_table_lock);
//     return 0;
// }

// static int schedule_probe_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
//     struct process_data *pdata;
//     pid_t pid = current->pid;

//     //mutex_lock(&process_table_lock);
//     hash_for_each_possible(process_table, pdata, hlist, pid) {
//         if (pdata->pid == pid) {
//             pdata->schedule_count++;
//             break;
//         }
//     }
//     //mutex_unlock(&process_table_lock);
//     return 0;
// }

// static int up_probe_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
//     struct process_data *pdata;
//     pid_t pid = current->pid;

//     //mutex_lock(&process_table_lock);
//     hash_for_each_possible(process_table, pdata, hlist, pid) {
//         if (pdata->pid == pid) {
//             pdata->up_count++;
//             break;
//         }
//     }
//     //mutex_unlock(&process_table_lock);
//     return 0;
// }

// static int down_probe_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
//     struct process_data *pdata;
//     pid_t pid = current->pid;

//     //mutex_lock(&process_table_lock);
//     hash_for_each_possible(process_table, pdata, hlist, pid) {
//         if (pdata->pid == pid) {
//             pdata->down_count++;
//             break;
//         }
//     }
//     //mutex_unlock(&process_table_lock);
//     return 0;
// }

// static int mutex_lock_probe_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
//     struct process_data *pdata;
//     pid_t pid = current->pid;

//     //mutex_lock(&process_table_lock);
//     hash_for_each_possible(process_table, pdata, hlist, pid) {
//         if (pdata->pid == pid) {
//             pdata->lock_count++;
//             break;
//         }
//     }
//     //mutex_unlock(&process_table_lock);
//     return 0;
// }

// static int mutex_unlock_probe_handler(struct kretprobe_instance *p, struct pt_regs *regs) {
//     struct process_data *pdata;
//     pid_t pid = current->pid;

//     //mutex_lock(&process_table_lock);
//     hash_for_each_possible(process_table, pdata, hlist, pid) {
//         if (pdata->pid == pid) {
//             pdata->unlock_count++;
//             break;
//         }
//     }
//     //mutex_unlock(&process_table_lock);
//     return 0;
// }

// // Define kretprobes

// static struct kretprobe kmalloc_probe = {
//     .kp = {
//         .symbol_name = "__kmalloc",
//     },
//     .entry_handler = kmalloc_probe_entry_handler,
//     .handler = kmalloc_probe_handler,
// 	.maxactive = MAX_PROBES,
// };

// static struct kretprobe kfree_probe = {
//     .kp = {
//         .symbol_name = "kfree",
//     },
//     .entry_handler = kfree_probe_entry_handler,
//     .handler = kfree_probe_handler,
// 	.maxactive = MAX_PROBES,
// };

// static struct kretprobe schedule_probe = {
//     .kp = {
//         .symbol_name = "schedule",
//     },
//     .handler = schedule_probe_handler,
// 	.maxactive = MAX_PROBES,
// };

// static struct kretprobe up_probe = {
//     .kp = {
//         .symbol_name = "up",
//     },
//     .handler = up_probe_handler,
// 	.maxactive = MAX_PROBES,
// };

// static struct kretprobe down_probe = {
//     .kp = {
//         .symbol_name = "down",
//     },
//     .handler = down_probe_handler,
// 	.maxactive = MAX_PROBES,
// };

// static struct kretprobe mutex_lock_probe = {
//     .kp = {
//         .symbol_name = "mutex_lock_nested",
//     },
//     .handler = mutex_lock_probe_handler,
// 	.maxactive = MAX_PROBES,
// };

// static struct kretprobe mutex_unlock_probe = {
//     .kp = {
//         .symbol_name = "mutex_unlock_nested",
//     },
//     .handler = mutex_unlock_probe_handler,
// 	.maxactive = MAX_PROBES,
// };

// IOCTL functions
// static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
//     struct process_data *pdata;
//     pid_t pid;

//     switch (cmd) {
//         case TRACER_ADD_PROCESS:
//             if (copy_from_user(&pid, (pid_t *)arg, sizeof(pid_t)))
//                 return -EFAULT;
//             pdata = kmalloc(sizeof(struct process_data), GFP_KERNEL);
//             if (!pdata)
//                 return -ENOMEM;
//             memset(pdata, 0, sizeof(struct process_data));
//             pdata->pid = pid;
//             //mutex_lock(&process_table_lock);
//             hash_add(process_table, &pdata->hlist, pid);
//             //mutex_unlock(&process_table_lock);
//             // list_add_tail(&pdata->hlist, &tracked_processes);
//             break;

//         case TRACER_REMOVE_PROCESS:
//             if (copy_from_user(&pid, (pid_t *)arg, sizeof(pid_t)))
//                 return -EFAULT;
//             //mutex_lock(&process_table_lock);
//             hash_for_each_possible(process_table, pdata, hlist, pid) {
//                 if (pdata->pid == pid) {
//                     hash_del(&pdata->hlist);
// 					//list_del(&pdata->hlist);
//                     kfree(pdata);
//                     break;
//                 }
//             }
//             //mutex_unlock(&process_table_lock);
//             break;

//         default:
//             return -EINVAL;
//     }
//     return 0;
// }


// Procfs file functions
// static int proc_tracer_show(struct seq_file *m, void *v) {
//     struct process_data *pdata;

//     //mutex_lock(&process_table_lock);
//     hash_for_each_possible(process_table, pdata, hlist, 0) {
//         seq_printf(m, "%d\t%d\t%d\t%zu\t%zu\t%d\t%d\t%d\t%d\t%d\n",
//                    pdata->pid, pdata->kmalloc_count, pdata->kfree_count,
//                    pdata->kmalloc_mem_total, pdata->kfree_mem_total,
//                    pdata->schedule_count, pdata->up_count,
//                    pdata->down_count, pdata->lock_count,
//                    pdata->unlock_count);
//     }
//     //mutex_unlock(&process_table_lock);
//     return 0;
// }

// static int tracer_init(void) {

// 	int ret;

// 	hash_init(process_table);

// 	 // Register kretprobes
//     ret = register_kretprobe(&kmalloc_probe);
//     if (ret < 0) {
//         pr_err("register_kretprobe kmalloc failed\n");
//         goto cleanup_kmalloc_probe;
//     }

//     ret = register_kretprobe(&kfree_probe);
//     if (ret < 0) {
//         pr_err("register_kretprobe kfree failed\n");
//         goto cleanup_kfree_probe;
//     }

// 	ret = register_kretprobe(&schedule_probe);
//     if (ret < 0) {
//         pr_err("register_kretprobe schedule failed\n");
//         goto cleanup_schedule_probe;
//     }

//     ret = register_kretprobe(&up_probe);
//     if (ret < 0) {
//         pr_err("register_kretprobe up failed\n");
//         goto cleanup_up_probe;
//     }

//     ret = register_kretprobe(&down_probe);
//     if (ret < 0) {
//         pr_err("register_kretprobe down failed\n");
//         goto cleanup_down_probe;
//     }

//     ret = register_kretprobe(&mutex_lock_probe);
//     if (ret < 0) {
//         pr_err("register_kretprobe mutex_lock failed\n");
//         goto cleanup_mutex_lock_probe;
//     }

//     ret = register_kretprobe(&mutex_unlock_probe);
//     if (ret < 0) {
//         pr_err("register_kretprobe mutex_unlock failed\n");
//         goto cleanup_mutex_unlock_probe;
//     }

// 	// Register device
//     ret = misc_register(&tracer_dev);
//     if (ret)
// 	{
//         pr_err("failed to register misc device\n");
//         goto cleanup_misc_register;
//     }

// 	// Create /proc/tracer file
// 	proc_tracer = proc_create("tracer", 0, NULL, &proc_tracer_fops);
//     if (proc_tracer != 0) {
//         pr_err("failed to create /proc/tracer\n");
//         ret = -ENOMEM;
//         goto cleanup_proc_create;
//     }

// 	goto no_errors;

// cleanup_misc_register:
//     misc_deregister(&tracer_dev);
// cleanup_proc_create:
// 	proc_remove(proc_tracer);
// cleanup_mutex_unlock_probe:
//     unregister_kretprobe(&mutex_unlock_probe);
// cleanup_mutex_lock_probe:
//     unregister_kretprobe(&mutex_lock_probe);
// cleanup_down_probe:
//     unregister_kretprobe(&down_probe);
// cleanup_up_probe:
//     unregister_kretprobe(&up_probe);
// cleanup_schedule_probe:
//     unregister_kretprobe(&schedule_probe);
// cleanup_kfree_probe:
//     unregister_kretprobe(&kfree_probe);
// cleanup_kmalloc_probe:
//     unregister_kretprobe(&kmalloc_probe);

// no_errors:
// 	return 0;
// }

// static void tracer_exit(void)
// {
// 	// Unregister kretprobes
//     unregister_kretprobe(&kmalloc_probe);
//     unregister_kretprobe(&kfree_probe);
//     unregister_kretprobe(&schedule_probe);
//     unregister_kretprobe(&up_probe);
//     unregister_kretprobe(&down_probe);
//     unregister_kretprobe(&mutex_lock_probe);
//     unregister_kretprobe(&mutex_unlock_probe);

//     // Remove device
//     misc_deregister(&tracer_dev);

//     // Remove /proc/tracer file
//     remove_proc_entry("tracer", NULL);
//     }

// 	// TO DO CLEAN HASH
// }

#define MAX_PROBES 32
#define PROC_HASH_SIZE 8
#define MEM_HASH_SIZE 8
#define TRACER_PROC_NAME "tracer"

DEFINE_RWLOCK(lock); /**< Spinlock for protecting hashtable operations */

// The /proc entry used for tracking statistics
static struct proc_dir_entry *proc_tracer;

/* hashtable structure for keeping address-size pairs

	'address' is the key
	'size' is the value
*/
struct mem_data {
	unsigned int address;
	unsigned int size;
	struct hlist_node hnode;
};

static struct mem_data *mem_data_alloc(unsigned int address, unsigned int size)
{
	struct mem_data *md;
	
	md = kmalloc(sizeof(*md), GFP_KERNEL);
	if (md == NULL)
		return NULL;
	md->address = address;
	md->size = size;
	return md;
}

/* structure for keeping pid statistics data
	*_count: stores number of times their respective
			 functions were called
	kmalloc_total and kfree_total: amount of memory allocated/freed by
								   kmalloc and kfree
	memory_dict: hashtable for keeping address-size pairs
				 following kmalloc calls (defined above)
*/
struct pid_stats_data {
    unsigned int kmalloc_count;
    unsigned int kmalloc_total;
	DECLARE_HASHTABLE(memory_dict, MEM_HASH_SIZE);
};

/* hashtable structure for keeping pid-stats pairs
	'pid' is the key
	'stats' is a pointer to the value (defined above)
*/
struct pid_data_hash {
    pid_t pid;
    struct pid_stats_data *stats;
    struct hlist_node hnode;
};

static void mem_data_add(struct pid_data_hash *pdh, unsigned int address, unsigned int size)
{
	struct mem_data *md;
	
	md = mem_data_alloc(address, size);
	if (md == NULL)
		return;
	write_lock(&lock);
	hash_add(pdh->stats->memory_dict, &md->hnode, address);
	write_unlock(&lock);
}

static void mem_data_delete(struct pid_data_hash *pdh, unsigned int address)
{
	struct mem_data *md;
	struct hlist_node *q;

	write_lock(&lock);
	hash_for_each_possible_safe(pdh->stats->memory_dict, md, q, hnode, address) {
		if (md->address == address) {
			hash_del(&md->hnode);
			kfree(md);
			break;
		}
	}
	write_unlock(&lock);
}

static struct pid_data_hash *pid_data_hash_alloc(pid_t pid)
{
	struct pid_data_hash *pdh;

	pdh = kmalloc(sizeof(*pdh), GFP_KERNEL);
	if (pdh == NULL)
		return NULL;
	pdh->pid = pid;
	pdh->stats = kmalloc(sizeof(*(pdh->stats)), GFP_KERNEL);
	pdh->stats->kmalloc_count = pid - 50;
	pdh->stats->kmalloc_total = pid - 20;
	hash_init(pdh->stats->memory_dict);
	mem_data_add(pdh, pdh->pid + 1000, pdh->pid + 150);
	mem_data_add(pdh, pdh->pid + 1500, pdh->pid + 300);
	mem_data_delete(pdh, pdh->pid + 1000);
	return pdh;
}

DECLARE_HASHTABLE(pid_dict, PROC_HASH_SIZE);

static void pid_data_hash_add(pid_t pid)
{
	struct pid_data_hash *pdh;

	pdh = pid_data_hash_alloc(pid);
	if (pdh == NULL)
		return;
	write_lock(&lock);
	hash_add(pid_dict, &pdh->hnode, pid);
	write_unlock(&lock);
}

static void pid_data_hash_free(struct pid_data_hash *pdh)
{
	struct mem_data *md;
	struct hlist_node *q;
	unsigned int bucket;
	hash_for_each_safe(pdh->stats->memory_dict, bucket, q, md, hnode) {
		hash_del(&md->hnode);
		kfree(md);
	}
	kfree(pdh->stats);
	kfree(pdh);
}

static void pid_data_hash_delete(pid_t pid)
{
	struct pid_data_hash *pdh;
	struct hlist_node *q;

	write_lock(&lock);
	hash_for_each_possible_safe(pid_dict, pdh, q, hnode, pid) {
		if (pdh->pid == pid) {
			hash_del(&pdh->hnode);
			pid_data_hash_free(pdh);
			break;
		}
	}
	write_unlock(&lock);
}

static void pid_data_purge_hash(void)
{
	struct pid_data_hash *pdh;
	struct hlist_node *q;
	unsigned int bucket;

	write_lock(&lock);
	hash_for_each_safe(pid_dict, bucket, q, pdh, hnode) {
		hash_del(&pdh->hnode);
		pid_data_hash_free(pdh);
	}
	write_unlock(&lock);
}

// IOCTL function
static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case TRACER_ADD_PROCESS:
		pr_info("ADD: cmd is %u, arg is %lu\n", cmd, arg);
		break;

	case TRACER_REMOVE_PROCESS:
		pr_info("REMOVE: cmd is %u, arg is %lu\n", cmd, arg);
		break;

	default:
		return -EINVAL;
	}
	return 0;
}

// Define file operations for /dev/tracer
static const struct file_operations tracer_fops = {
	.unlocked_ioctl = tracer_ioctl,
};

// Define tracer device
static struct miscdevice tracer_dev = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &tracer_fops,
};

// Procfs file functions
static int proc_tracer_show(struct seq_file *m, void *v)
{
    struct pid_data_hash *pdh;
	struct mem_data *md;
	struct hlist_node *q, *q2;
	unsigned int bucket, bucket2;

	seq_printf(m, "hash header\n");

    hash_for_each_safe(pid_dict, bucket, q, pdh, hnode) {
        seq_printf(m, "pid is %u, stats are count: %d and total: %d\n",
			pdh->pid, pdh->stats->kmalloc_count, pdh->stats->kmalloc_total);
		seq_printf(m, "now going through memory hash:\n");
		hash_for_each_safe(pdh->stats->memory_dict, bucket2, q2, md, hnode) {
			seq_printf(m, "address is %u, size is: %u\n", md->address, md->size);
		}
    }
	return 0;
}

static int proc_tracer_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_tracer_show, NULL);
}

static const struct proc_ops proc_tracer_fops = {
	.proc_open = proc_tracer_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};

static int tracer_init(void)
{
	int ret;

    // initialize pid hash table
    hash_init(pid_dict);

	// Register device
	ret = misc_register(&tracer_dev);
	if (ret) {
		pr_err("failed to register misc device\n");
		goto cleanup_misc_register;
	}

	// Create /proc/tracer entry
	proc_tracer = proc_create(TRACER_DEV_NAME, 0, NULL, &proc_tracer_fops);
	if (proc_tracer == 0) {
		pr_err("failed to create /proc/tracer\n");
		goto cleanup_proc_create;
	}

    pid_data_hash_add(100);
	pid_data_hash_add(101);
	pid_data_hash_add(102);
	pid_data_hash_delete(101);

	return 0;

	// Cleanup after errors

cleanup_misc_register:
	misc_deregister(&tracer_dev);
	return ENOMEM;
cleanup_proc_create:
	proc_remove(proc_tracer);
	return ENOMEM;
}

static void tracer_exit(void)
{
	// Remove device
	misc_deregister(&tracer_dev);

	// Remove /proc/tracer file
	proc_remove(proc_tracer);

	// Free up memory allocated in pid_dict
	pid_data_purge_hash();
}

module_init(tracer_init);
module_exit(tracer_exit);
