// SPDX-License-Identifier: GPL-2.0+

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

#define MAX_PROBES 64
#define PROC_HASH_SIZE 12
#define MEM_HASH_SIZE 12
#define TRACER_PROC_NAME "tracer"

/* The header used for displaying the /proc/tracer file with process statistics.
 *
 * This header string defines the column formatting for the /proc/tracer file,
 * which shows statistics for various system calls and activities related to memory
 * management, scheduling, and synchronization.
 *
 * The columns represent:
 *   - PID: Process ID
 *   - kmalloc: Number of kmalloc calls
 *   - kfree: Number of kfree calls
 *   - kmalloc_mem: Total memory allocated with kmalloc
 *   - kfree_mem: Total memory freed with kfree
 *   - sched: Number of scheduling events
 *   - up: Number of times a process transitioned from unrunnable to runnable state
 *   - down: Number of times a process transitioned from runnable to unrunnable state
 *   - lock: Number of lock acquisition attempts
 *   - unlock: Number of lock release operations
 */
static char *hash_header =
	"PID   kmalloc kfree kmalloc_mem kfree_mem  sched   up     down  lock   unlock\n";

DEFINE_RWLOCK(pid_lock); /**< Spinlock for protecting pid hashtable operations */
DEFINE_RWLOCK(mem_lock); /**< Spinlock for protecting mem hashtable operations */
static struct proc_dir_entry
	*proc_tracer; /**< The /proc entry used for tracking statistics */

/**
 * Used by handlers in order to not enter recursive traps
 * - Initialized in tracer_ioctl
 */
static pid_t current_module_pid;

/**
 * struct mem_data - Structure for storing address-size pairs in a hash table
 *
 * This structure is usually stored as an entry within the 'stats->memory_dict'
 * field (which is a hashtable) of a struct_pid_data_hash (see definition below)
 */
struct mem_data {
	unsigned int address; /**< The memory address (key) */
	unsigned int size; /**< The size of the memory block (value) */
	struct hlist_node hnode;
};

/**
 * @brief Allocates memory for a new mem_data structure.
 *
 * @param address The memory address for which to create a mem_data entry.
 * @param size The size of the memory block associated with the address.
 *
 * @return A pointer to the newly allocated mem_data structure on success,
 *         NULL on failure.
 */
static struct mem_data *mem_data_alloc(unsigned int address, unsigned int size)
{
	struct mem_data *md;

	/**
	 * Usually called from a kretprobe handler routine, which runs with interrupts
	 * disabled. Therefore, we use the GFP_ATOMIC flag in order to not yield the
	 * CPU, sacrificing performance for safety
	 */
	md = kmalloc(sizeof(*md), GFP_ATOMIC);
	if (md == NULL)
		// Allocation failed, return NULL
		return NULL;

	md->address = address;
	md->size = size;

	return md;
}

/**
 * struct pid_stats_data - Structure for keeping process statistics data
 *
 * These statistics include:
 *
 * - Function call counts
 * - Memory allocation/deallocation totals
 * - Memory usage information
 */
struct pid_stats_data {
	unsigned int kmalloc_count; /** < Number of times kmalloc was called */
	unsigned int kmalloc_total; /** < Total memory allocated by kmalloc */
	unsigned int kfree_count; /** < Number of times kfree was called */
	unsigned int kfree_total; /** < Total memory freed by kfree */
	unsigned int sched_count; /** < Number of scheduling events */
	unsigned int up_count; /** < Number of semaphore release operations */
	unsigned int down_count; /** < Number of semaphore acquisition attempts */
	unsigned int lock_count; /** < Number of lock acquisition attempts */
	unsigned int unlock_count; /** < Number of lock release operations */
	DECLARE_HASHTABLE(memory_dict, MEM_HASH_SIZE);
	/** Hash table for memory usage (key: address, value: struct mem_data) */
};

/**
 * struct pid_data_hash - Structure for storing process ID (pid) and statistics pairs
 *
 * This structure is used to efficiently manage a hash table that maps process IDs (pids)
 * to corresponding `pid_stats_data` structures. Each entry in the hash table is of this type.
 */
struct pid_data_hash {
	pid_t pid; /** < The process ID (key) used for lookup in the hash table */
	struct pid_stats_data *stats; /** Pointer to a 'struct pid_stats_data` */
	struct hlist_node hnode;
};

/**
 * @brief Adds a new mem_data entry to the process's memory usage hash table.
 *
 * @param pdh Pointer to the pid_data_hash entry for the process.
 * @param address The memory address for the new entry.
 * @param size The size of the memory block at the given address.
 */
static void mem_data_add(struct pid_data_hash *pdh, unsigned int address,
			 unsigned int size)
{
	struct mem_data *md;

	md = mem_data_alloc(address, size);
	if (md == NULL)
		// Allocation failed, return NULL
		return;
	write_lock(&mem_lock);
	hash_add(pdh->stats->memory_dict, &md->hnode, address);
	write_unlock(&mem_lock);
}

/**
 * @brief Deletes a mem_data entry from the process's memory usage hash table.
 *
 * @param pdh Pointer to the pid_data_hash entry for the process.
 * @param address The memory address of the entry to be deleted.
 *
 * @return Returns the size of the deleted memory block, or 0 if not found.
 */
static unsigned int mem_data_delete(struct pid_data_hash *pdh,
				    unsigned int address)
{
	struct mem_data *md;
	struct hlist_node *q;
	unsigned int size = 0;

	write_lock(&mem_lock);
	hash_for_each_possible_safe(pdh->stats->memory_dict, md, q, hnode,
				     address) {
		if (md->address == address) {
			hash_del(&md->hnode);
			size = md->size;
			kfree(md);
			break;
		}
	}
	write_unlock(&mem_lock);
	return size;
}

/**
 * @brief Allocates and initializes a new pid_data_hash entry.
 *
 * @param pid The process ID (pid) for which to create the entry.
 *
 * @return Returns a pointer to the newly allocated pid_data_hash structure
 *  on success, NULL on failure.
 */
static struct pid_data_hash *pid_data_hash_alloc(pid_t pid)
{
	struct pid_data_hash *pdh;

	pdh = kmalloc(sizeof(*pdh), GFP_KERNEL);
	if (pdh == NULL)
		// Allocation failed, return NULL
		return NULL;
	pdh->pid = pid;
	pdh->stats = kmalloc(sizeof(*(pdh->stats)), GFP_KERNEL);
	if (pdh->stats == NULL)
		// Allocation failed, return NULL
		return NULL;

	// Initialize all integer fields in stats to 0
	memset(pdh->stats, 0, sizeof(*(pdh->stats)));

	// Initialize internal memory hashtable
	hash_init(pdh->stats->memory_dict);

	return pdh;
}

DECLARE_HASHTABLE(pid_dict, PROC_HASH_SIZE);
/** Hash table for process statistics (key: pid, value: *struct pid_stats_data) */

/**
 * @brief Adds a new pid_data_hash entry for the specified process ID.
 *
 * @param pid The process ID (pid) for which to create a new entry.
 */
static void pid_data_hash_add(pid_t pid)
{
	struct pid_data_hash *pdh;

	pdh = pid_data_hash_alloc(pid);
	if (pdh == NULL)
		return;
	write_lock(&pid_lock);
	hash_add(pid_dict, &pdh->hnode, pid);
	write_unlock(&pid_lock);
}

/**
 * @brief Frees the memory associated with a pid_data_hash entry.
 *
 * @param pdh Pointer to the pid_data_hash entry to be freed.
 */
static void pid_data_hash_free(struct pid_data_hash *pdh)
{
	struct mem_data *md;
	struct hlist_node *q;
	unsigned int bucket;

	// First, free the memory used by the internal hashtable in 'stats'
	write_lock(&mem_lock);
	hash_for_each_safe(pdh->stats->memory_dict, bucket, q, md, hnode) {
		hash_del(&md->hnode);
		kfree(md);
	}
	write_unlock(&mem_lock);
	// Free the 'stats' field
	kfree(pdh->stats);

	// Free the actual entry
	kfree(pdh);
}

/**
 * @brief Deletes a pid_data_hash entry for the specified process ID.
 *
 * @param pid The process ID (pid) of the entry to be deleted.
 */
static void pid_data_hash_delete(pid_t pid)
{
	struct pid_data_hash *pdh;
	struct hlist_node *q;

	write_lock(&pid_lock);
	hash_for_each_possible_safe(pid_dict, pdh, q, hnode, pid) {
		if (pdh->pid == pid) {
			hash_del(&pdh->hnode);
			pid_data_hash_free(pdh);
			break;
		}
	}
	write_unlock(&pid_lock);
}

/**
 * @brief Searches for a pid_data_hash entry for the specified process ID.
 *
 * @param pid The process ID (pid) of the entry to be searched.
 *
 * @return A pointer to the found pid_data_hash entry on success, NULL if not found.
 */
static struct pid_data_hash *pid_data_hash_search(pid_t pid)
{
	struct pid_data_hash *pdh;
	struct hlist_node *q;

	read_lock(&pid_lock);
	hash_for_each_possible_safe(pid_dict, pdh, q, hnode, pid) {
		if (pdh->pid == pid) {
			read_unlock(&pid_lock);
			return pdh;
		}
	}
	read_unlock(&pid_lock);
	return NULL;
}

#pragma GCC diagnostic ignored "-Wunused-function"
/**
 * @brief Prints information about memory allocations for a given pid_data_hash entry.
 *
 * @param pdh Pointer to the pid_data_hash entry for which to print memory information.
 */
static void print_pid_mem(struct pid_data_hash *pdh)
{
	unsigned int bucket;
	struct hlist_node *q;
	struct mem_data *md;

	pr_info("for PID %u:\n", pdh->pid);

	read_lock(&mem_lock);
	hash_for_each_safe(pdh->stats->memory_dict, bucket, q, md, hnode)
		pr_info("At address %u, a block of size %u has been allocated\n",
			md->address, md->size);
	read_unlock(&mem_lock);

	pr_info("\n");
}

/**
 * @brief Purges all entries from the pid_data_hash table.
 */
static void pid_data_purge_hash(void)
{
	struct pid_data_hash *pdh;
	struct hlist_node *q;
	unsigned int bucket;

	write_lock(&pid_lock);
	hash_for_each_safe(pid_dict, bucket, q, pdh, hnode) {
		hash_del(&pdh->hnode);
		pid_data_hash_free(pdh);
	}
	write_unlock(&pid_lock);
}

/**
 * struct reg_data: acts as a data interface between handlers
 *
 * Data is added to the appropriate fields in the entry_handler
 * Data is extracted back in the regular handler
 *
 * This is done by casting the data field of the kprobe instance
 * to this structure
 */
struct reg_data {
	struct pid_data_hash *pdh; /**< hashtable entry for current pid */
	unsigned int size; /**< used by the kmalloc handlers */
};

// Handler functions for kretprobes

static int kmalloc_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct reg_data *data = (struct reg_data *)p->data;
	struct pid_data_hash *pdh;

	// Blacklist the probe handler as we don't want recursive instrumentation
	if (current->pid == current_module_pid) {
		data->size = 0;
		return 0;
	}

	pdh = pid_data_hash_search(current->pid);
	if (pdh == NULL) {
		// Don't instrument anything, we are not tracking this process
		data->size = 0;
		return 0;
	}

	// Data to be passed to the regular handler
	data->size = regs->ax; /** The argument received by kmalloc */
	data->pdh = pdh;
	return 0;
}

static int kmalloc_probe_handler(struct kretprobe_instance *p, struct pt_regs *regs)
{
	unsigned int address;
	struct reg_data *data = (struct reg_data *)p->data;

	if (data->size == 0)
		// entry_handler told us not to instrument this process
		return 0;

	// Increase the call count and total memory
	++data->pdh->stats->kmalloc_count;
	data->pdh->stats->kmalloc_total += data->size;

	// Add an entry to the address-size memory hashtable
	address = regs_return_value(regs);
	mem_data_add(data->pdh, address, data->size);
	pr_info("Allocating %u at address %u\n", data->size, address);
	return 0;
}

static int kfree_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct pid_data_hash *pdh;
	unsigned int address, size;

	// Blacklist the probe handler as we don't want recursive instrumentation
	if (current->pid == current_module_pid)
		return 0;

	pdh = pid_data_hash_search(current->pid);
	if (pdh == NULL)
		// Don't instrument anything, we are not tracking this process
		return 0;

	// Increase the kfree call count
	++pdh->stats->kfree_count;

	address = regs->ax;
	/* Remove the address-size entry in the pid's
	 * memory hashtable (as it's been freed)
	 */
	size = mem_data_delete(pdh, address);
	// Increase the amount of freed memory for current pid
	pdh->stats->kfree_total += size;
	return 0;
}

static int schedule_probe_handler(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct pid_data_hash *pdh;

	// Blacklist the probe handler as we don't want recursive instrumentation
	if (current->pid == current_module_pid)
		return 0;

	pdh = pid_data_hash_search(current->pid);
	if (pdh == NULL)
		// Don't instrument anything, we are not tracking this process
		return 0;

	// Increase the schedule call count
	++pdh->stats->sched_count;

	return 0;
}

static int up_probe_handler(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct pid_data_hash *pdh;

	// Blacklist the probe handler as we don't want recursive instrumentation
	if (current->pid == current_module_pid)
		return 0;

	pdh = pid_data_hash_search(current->pid);
	if (pdh == NULL)
		// Don't instrument anything, we are not tracking this process
		return 0;

	// Increase the up call count
	++pdh->stats->up_count;

	return 0;
}

static int down_probe_handler(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct pid_data_hash *pdh;

	// Blacklist the probe handler as we don't want recursive instrumentation
	if (current->pid == current_module_pid)
		return 0;

	pdh = pid_data_hash_search(current->pid);
	if (pdh == NULL)
		// Don't instrument anything, we are not tracking this process
		return 0;

	// Increase the down call count
	++pdh->stats->down_count;

	return 0;
}

static int mutex_lock_probe_handler(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct pid_data_hash *pdh;

	// Blacklist the probe handler as we don't want recursive instrumentation
	if (current->pid == current_module_pid)
		return 0;

	pdh = pid_data_hash_search(current->pid);
	if (pdh == NULL)
		// Don't instrument anything, we are not tracking this process
		return 0;

	// Increase the lock call count
	++pdh->stats->lock_count;

	return 0;
}

static int mutex_unlock_probe_handler(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct pid_data_hash *pdh;

	// Blacklist the probe handler as we don't want recursive instrumentation
	if (current->pid == current_module_pid)
		return 0;

	pdh = pid_data_hash_search(current->pid);
	if (pdh == NULL)
		// Don't instrument anything, we are not tracking this process
		return 0;

	// Increase the unlock call count
	++pdh->stats->unlock_count;

	return 0;
}

// Blacklist the handlers so we don't run into recursive traps
NOKPROBE_SYMBOL(kmalloc_probe_entry_handler);
NOKPROBE_SYMBOL(kmalloc_probe_handler);
NOKPROBE_SYMBOL(kfree_probe_entry_handler);
NOKPROBE_SYMBOL(schedule_probe_handler);
NOKPROBE_SYMBOL(up_probe_handler);
NOKPROBE_SYMBOL(down_probe_handler);
NOKPROBE_SYMBOL(mutex_lock_probe_handler);
NOKPROBE_SYMBOL(mutex_unlock_probe_handler);

// Define kretprobes
static struct kretprobe kmalloc_probe = {
	.kp = {
		.symbol_name = "__kmalloc",
	},
	.entry_handler = kmalloc_probe_entry_handler,
	.handler = kmalloc_probe_handler,
	.data_size = sizeof(struct reg_data),
	.maxactive = MAX_PROBES,
};

static struct kretprobe kfree_probe = {
	.kp = {
		.symbol_name = "kfree",
	},
	.entry_handler = kfree_probe_entry_handler,
	.maxactive = MAX_PROBES,
};

static struct kretprobe schedule_probe = {
	.kp = {
		.symbol_name = "schedule",
	},
	.handler = schedule_probe_handler,
	.maxactive = MAX_PROBES,
};

static struct kretprobe up_probe = {
	.kp = {
		.symbol_name = "up",
	},
	.handler = up_probe_handler,
	.maxactive = MAX_PROBES,
};

static struct kretprobe down_probe = {
	.kp = {
		.symbol_name = "down_interruptible",
	},
	.handler = down_probe_handler,
	.maxactive = MAX_PROBES,
};

static struct kretprobe mutex_lock_probe = {
	.kp = {
		.symbol_name = "mutex_lock_nested",
	},
	.handler = mutex_lock_probe_handler,
	.maxactive = MAX_PROBES,
};

static struct kretprobe mutex_unlock_probe = {
	.kp = {
		.symbol_name = "mutex_unlock",
	},
	.handler = mutex_unlock_probe_handler,
	.maxactive = MAX_PROBES,
};

/**
 * @brief IOCTL function
 *
 * @param cmd The type of request made to the monitoring subsystem
 * @param arg The PID of the process to be traced/untraced
 *
 * @return 0 on success, -EINVAL for invalid arguments
 */
static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	current_module_pid = current->pid;
	switch (cmd) {
	case TRACER_ADD_PROCESS:
		pid_data_hash_add((pid_t)arg);
		break;

	case TRACER_REMOVE_PROCESS:
		pid_data_hash_delete((pid_t)arg);
		break;

	default:
		return -EINVAL;
	}
	return 0;
}

// Define file operations for /dev/tracer
static const struct file_operations tracer_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = tracer_ioctl,
};

// Define tracer device
static struct miscdevice tracer_dev = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &tracer_fops,
};

/**
 * @brief Prints data to the /proc/tracer file
 *
 * @param m The file to print in
 */
static int proc_tracer_show(struct seq_file *m, void *v)
{
	struct pid_data_hash *pdh;
	struct hlist_node *q;
	unsigned int bucket;

	seq_printf(m, "%s", hash_header);
	read_lock(&pid_lock);
	hash_for_each_safe(pid_dict, bucket, q, pdh, hnode) {
		// we make sure the data sits nicely and is alligned in its column
		seq_printf(
			m,
			"%-5u %-7u %-5u %-11u %-10u %-7u %-6u %-5u %-6u %-6u\n",
			pdh->pid, pdh->stats->kmalloc_count,
			pdh->stats->kfree_count, pdh->stats->kmalloc_total,
			pdh->stats->kfree_total, pdh->stats->sched_count,
			pdh->stats->up_count, pdh->stats->down_count,
			pdh->stats->lock_count, pdh->stats->unlock_count);
	}
	read_unlock(&pid_lock);
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

	// Initialize pid hashtable
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

	// Register kretprobes

	ret = register_kretprobe(&kmalloc_probe);
	if (ret) {
		pr_err("register_kretprobe kmalloc failed\n");
		goto cleanup_kmalloc_probe;
	}

	ret = register_kretprobe(&kfree_probe);
	if (ret) {
		pr_err("register_kretprobe kfree failed\n");
		goto cleanup_kfree_probe;
	}

	ret = register_kretprobe(&schedule_probe);
	if (ret) {
		pr_err("register_kretprobe schedule failed\n");
		goto cleanup_schedule_probe;
	}

	ret = register_kretprobe(&up_probe);
	if (ret) {
		pr_err("register_kretprobe up failed\n");
		goto cleanup_up_probe;
	}

	ret = register_kretprobe(&down_probe);
	if (ret) {
		pr_err("register_kretprobe down failed\n");
		goto cleanup_down_probe;
	}

	ret = register_kretprobe(&mutex_lock_probe);
	if (ret) {
		pr_err("register_kretprobe mutex_lock failed\n");
		goto cleanup_mutex_lock_probe;
	}

	ret = register_kretprobe(&mutex_unlock_probe);
	if (ret) {
		pr_err("register_kretprobe mutex_unlock failed\n");
		goto cleanup_mutex_unlock_probe;
	}

	return 0;

// Cleanup after errors
cleanup_misc_register:
	misc_deregister(&tracer_dev);
	return -ENOMEM;
cleanup_proc_create:
	proc_remove(proc_tracer);
	return -ENOMEM;
cleanup_kmalloc_probe:
	unregister_kretprobe(&kmalloc_probe);
	return -ENOMEM;
cleanup_kfree_probe:
	unregister_kretprobe(&kfree_probe);
	return -ENOMEM;
cleanup_schedule_probe:
	unregister_kretprobe(&schedule_probe);
	return -ENOMEM;
cleanup_up_probe:
	unregister_kretprobe(&up_probe);
	return -ENOMEM;
cleanup_down_probe:
	unregister_kretprobe(&down_probe);
	return -ENOMEM;
cleanup_mutex_lock_probe:
	unregister_kretprobe(&mutex_lock_probe);
	return -ENOMEM;
cleanup_mutex_unlock_probe:
	unregister_kretprobe(&mutex_unlock_probe);
	return -ENOMEM;
}

static void tracer_exit(void)
{
	// Remove device
	misc_deregister(&tracer_dev);

	// Remove /proc/tracer file
	proc_remove(proc_tracer);

	// Free up memory allocated in pid_dict
	pid_data_purge_hash();

	// Unregister probes
	unregister_kretprobe(&kmalloc_probe);
	unregister_kretprobe(&kfree_probe);
	unregister_kretprobe(&schedule_probe);
	unregister_kretprobe(&up_probe);
	unregister_kretprobe(&down_probe);
	unregister_kretprobe(&mutex_lock_probe);
	unregister_kretprobe(&mutex_unlock_probe);
}

module_init(tracer_init);
module_exit(tracer_exit);
