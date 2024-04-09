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

// Structures to store surveillance data
// struct process_data {
//     pid_t pid;
//     unsigned int kmalloc_count;
//     unsigned int kfree_count;
//     size_t kmalloc_mem_total;
//     size_t kfree_mem_total;
//     unsigned int schedule_count;
//     unsigned int up_count;
//     unsigned int down_count;
//     unsigned int lock_count;
//     unsigned int unlock_count;
//     struct hlist_node hlist;
// };

// DEFINE_HASHTABLE(process_table, 8);
// static DEFINE_MUTEX(process_table_lock);
// static LIST_HEAD(tracked_processes);

// static struct proc_dir_entry *proc_tracer;

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

// Define file operations for /dev/tracer
// static const struct file_operations tracer_fops = {
//     .unlocked_ioctl = tracer_ioctl,
// };

// Define tracer device
// static struct miscdevice tracer_dev = {
//     .minor = TRACER_DEV_MINOR,
//     .name = TRACER_DEV_NAME,
//     .fops = &tracer_fops,
// };

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

// static int proc_tracer_open(struct inode *inode, struct file *file) {
//     return single_open(file, proc_tracer_show, NULL);
// }

// static const struct proc_ops proc_tracer_fops = {
//     .proc_open = proc_tracer_open,
//     .proc_read = seq_read,
//     .proc_release = single_release,
// };

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

// 	// Cleanup tracked processes
// 	// struct process_data *pdata, *tmp;
//     // list_for_each_entry_safe(pdata, tmp, &tracked_processes, hlist) {
//     //     list_del(&pdata->hlist);
//     //     kfree(pdata);
//     // }

// 	// TO DO CLEAN HASH
// }

// /proc entry used for tracking statistics
static struct proc_dir_entry *proc_tracer;

// structure for keeping pid statistics data

struct pid_stats_data {
    unsigned int kmalloc_count;
    unsigned int kmalloc_data;
};

struct pid_data_hash {
    pid_t pid;
    // struct pid_stats_data stats;
    int value;
    struct hlist_node hnode;
};

DECLARE_HASHTABLE(pid_dict, MAX_PROBED_PROCESSES);

// list for keeping tracked pids
struct pid_data_list {
	pid_t pid;
	struct list_head list;
};

static struct list_head head; /**< Head of the linked list */

DEFINE_RWLOCK(lock); /**< Spinlock for protecting list/hashtable operations */

// allocate memory for apid_data_list structure
static struct pid_data_list *pid_data_list_alloc(pid_t pid)
{
	struct pid_data_list *pdl;

	pdl = kmalloc(sizeof(*pdl), GFP_KERNEL);
	if (pdl == NULL)
		return NULL;
	pdl->pid = pid;
	return pdl;
}

// add a pid to the list (at the start)
static void pid_data_list_add(pid_t pid)
{
	struct pid_data_list *pdl;

	pdl = pid_data_list_alloc(pid);
	if (pdl == NULL)
		return;
	write_lock(&lock);
	list_add(&pdl->list, &head);
	write_unlock(&lock);
}

// delete a pid from the list (all instances)
static void pid_data_list_delete(pid_t pid)
{
	struct list_head *p, *q;
	struct pid_data_list *pdl;

	write_lock(&lock);
	list_for_each_safe (p, q, &head) {
		pdl = list_entry(p, struct pid_data_list, list);
		if (pdl->pid == pid) {
			list_del(p);
			kfree(pdl);
		}
	}
	write_unlock(&lock);
}

static void pid_data_list_purge(void)
{
	struct list_head *p, *q;
	struct pid_data_list *pdl;

	write_lock(&lock);
	list_for_each_safe (p, q, &head) {
		pdl = list_entry(p, struct pid_data_list, list);
		list_del(p);
		kfree(pdl);
	}
	write_unlock(&lock);
}

static void pid_data_hash_add(pid_t key, int value)
{
    struct pid_data_hash *pdh, *new_entry;
    struct hlist_node *q;

    unsigned int hash = hash_32(key, 32);

    hash_for_each_possible_safe(pid_dict, pdh, q, hnode, hash) {
        if (pdh->pid == key) {
            pdh->value += value;
            return;
        }
    }
    new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
    if (new_entry == NULL) {
        return;
    }
    new_entry->pid = key;
    new_entry->value = value;
    hash_add(pid_dict, &new_entry->hnode, hash);
}

// IOCTL function
static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case TRACER_ADD_PROCESS:
		pr_info("ADD: cmd is %u, arg is %lu\n", cmd, arg);
        pid_data_list_add((pid_t)arg);

		break;

	case TRACER_REMOVE_PROCESS:
		pr_info("REMOVE: cmd is %u, arg is %lu\n", cmd, arg);
        pid_data_list_delete((pid_t)arg);
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
    int bucket;
    struct pid_data_hash *pdh;

	seq_printf(m, "hash header\n");

    for (bucket = 0; bucket < ARRAY_SIZE(pid_dict); ++bucket) {
        hash_for_each_possible(pid_dict, pdh, hnode, bucket) {
            seq_printf(m, "pid is %u, value is %d\n", pdh->pid, pdh->value);
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

    // initialize pid list
    INIT_LIST_HEAD(&head);

    // initialize hash table
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

    pid_data_hash_add(100, 3);
    pid_data_hash_add(101, 4);
    pid_data_hash_add(102, 5);
    pid_data_hash_add(100, 2);
    pid_data_hash_add(102, 2);

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

    // Free memory used for pid list
    pid_data_list_purge();
}

module_init(tracer_init);
module_exit(tracer_exit);
