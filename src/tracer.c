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
#define PROC_HASH_SIZE 8
#define MEM_HASH_SIZE 8
#define TRACER_PROC_NAME "tracer"

static char *hash_header = 
	"PID   kmalloc kfree kmalloc_mem kfree_mem  sched   up     down  lock   unlock\n";

DEFINE_RWLOCK(lock); /**< Spinlock for protecting hashtable operations */

// The /proc entry used for tracking statistics
static struct proc_dir_entry *proc_tracer;
static pid_t current_module_pid;

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
	
	/* This will be called from a kprobe handler, which run with interrupts disabled,
	so GFK_KERNEL may lead to sleeping, which may lead to DEADLOCK. Therefore, we use
	the GFP_ATOMIC flag (sacrifice performance for safety).
	*/
	md = kmalloc(sizeof(*md), GFP_ATOMIC);
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
	unsigned int kfree_count;
	unsigned int kfree_total;
	unsigned int sched_count;
	unsigned int up_count;
	unsigned int down_count;
	unsigned int lock_count;
	unsigned int unlock_count;
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
	pdh->stats->kmalloc_count = 0;
	pdh->stats->kmalloc_total = 0;
	pdh->stats->kfree_total = 0;
	pdh->stats->kfree_count = 0;
	pdh->stats->sched_count = 0;
	pdh->stats->up_count = 0;
	pdh->stats->down_count = 0;
	pdh->stats->lock_count = 0;
	pdh->stats->unlock_count = 0;
	hash_init(pdh->stats->memory_dict);
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

static struct pid_data_hash *pid_data_hash_search(pid_t pid)
{
	struct pid_data_hash *pdh;
	struct hlist_node *q;

	read_lock(&lock);
	hash_for_each_possible_safe(pid_dict, pdh, q, hnode, pid) {
		if (pdh->pid == pid) {
			read_unlock(&lock);
			return pdh;
		}
	}
	read_unlock(&lock);
	return NULL;
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

/* structure that acts as a data interface between 
the entry and regular handler */
struct reg_data {
	struct pid_data_hash *pdh;
	unsigned int size;
};

// Handler functions for kretprobes

static int kmalloc_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs)
{	
	struct reg_data *data = (struct reg_data *)p->data;
	struct pid_data_hash *pdh;
	
	// blacklist the probe handler
	if (current->pid == current_module_pid) {
		data->size = -1;
		return 0;
	}

	pdh = pid_data_hash_search(current->pid);
	if (pdh == NULL) {
		// don't instrument anything, we are not tracking this process
		data->size = -1;
		return 0;
	}
	data->size = regs->ax;
	data->pdh = pdh;
	return 0;
}

static int kmalloc_probe_handler(struct kretprobe_instance *p, struct pt_regs *regs)
{	
	unsigned int address;
	struct reg_data *data = (struct reg_data *)p->data;

	if (data->size == -1)
		// entry_handler told us not to instrument this process
		return 0;

	// increase the call count and total memory
	++data->pdh->stats->kmalloc_count;
	data->pdh->stats->kmalloc_total += data->size;

	// add an entry to the address-size dictionary 
	address = regs_return_value(regs);
	// we are in atomic context and should be careful when we allocate memory
	mem_data_add(data->pdh, address, data->size);

	return 0;
}

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

// IOCTL function
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
	.unlocked_ioctl = tracer_ioctl,
};

// Define tracer device
static struct miscdevice tracer_dev = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &tracer_fops,
};

// Procfs file function
static int proc_tracer_show(struct seq_file *m, void *v)
{
    struct pid_data_hash *pdh;
	struct hlist_node *q;
	unsigned int bucket;
	
	seq_printf(m, "%s", hash_header);
	read_lock(&lock);
    hash_for_each_safe(pid_dict, bucket, q, pdh, hnode) {
		// we make sure the data sits nicely and is alligned in its column
        seq_printf(m, "%-5u %-7u %-5u %-11u %-10u %-7u %-6u %-5u %-6u %-6u\n",
			pdh->pid,
			pdh->stats->kmalloc_count,
			pdh->stats->kfree_count,
			pdh->stats->kmalloc_total,
			pdh->stats->kfree_total,
			pdh->stats->sched_count,
			pdh->stats->up_count,
			pdh->stats->down_count,
			pdh->stats->lock_count,
			pdh->stats->unlock_count
		);
	}
	read_unlock(&lock);
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
	// register kretprobes

	ret = register_kretprobe(&kmalloc_probe);
    if (ret) {
        pr_err("register_kretprobe kmalloc failed\n");
        goto cleanup_kmalloc_probe;
    }

	return 0;

// Cleanup after errors
cleanup_misc_register:
	misc_deregister(&tracer_dev);
	return ENOMEM;
cleanup_proc_create:
	proc_remove(proc_tracer);
	return ENOMEM;
cleanup_kmalloc_probe:
	unregister_kretprobe(&kmalloc_probe);
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

	// Unregister probes
	unregister_kretprobe(&kmalloc_probe);
}

module_init(tracer_init);
module_exit(tracer_exit);
