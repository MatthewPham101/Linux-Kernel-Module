#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include "kmlab_given.h"
// Include headers as needed ...

#include <linux/fs.h>

#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pham"); // Change with your lastname
MODULE_DESCRIPTION("CPTS360 Lab 4");

#define DEBUG 1

// Global variables as needed ...
#define FILENAME  "status"
#define DIRECTORY "kmlab"

typedef struct {
    struct list_head list;
    unsigned int pid;
    unsigned long cpu_time;
} proc_list;


static struct workqueue_struct *the_workqueue;
static spinlock_t the_lock;
static struct work_struct *the_work;
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_entry;
LIST_HEAD(theProcList);
static struct timer_list kmlab_timer;


/// @brief This function will read the process information from theProcList and copies it to the user
///space 
/// @param file 
/// @param buffer 
/// @param buffer_size 
/// @param file_offset 
/// @return 
static ssize_t kmlab_read(struct file *file, char __user *buffer, size_t buffer_size, loff_t *file_offset)
{
    char *theBuffer;
    size_t buf_size = 0;
    int error = 0;
    proc_list *entry;

    // Allocate memory for the buffer
    theBuffer = kmalloc(buffer_size, GFP_KERNEL);
    if (theBuffer == NULL) {
        return -ENOMEM;
    }

    if (*file_offset > 0) {
        return 0;
    }

    // Enter critical section
    spin_lock(&the_lock);

    // Iterate over each entry in the theProcList
    list_for_each_entry(entry, &theProcList, list) {
        int len;
        
        // Check remaining theBufferfer space
        if (buf_size >= buffer_size) {
            break;
        }

        // Write the PID and CPU time to the buffer
        len = snprintf(theBuffer + buf_size, buffer_size - buf_size, "%u: CPU TIME: %lu\n", entry->pid,  entry->cpu_time);

        // Check for buffer overflow because of using snprintf
        if (len < 0 || buf_size + len > buffer_size) {
            error = -EINVAL;
            break;
        }
        buf_size += len;
    }

    // Exit critical section
    spin_unlock(&the_lock);

    // Handle error or copy buffer to user space
    if (!error) {
        if (copy_to_user(buffer, theBuffer, buf_size)) {
            error = -EFAULT;
        } else {
            *file_offset += buf_size; // Update the read offset
        }
    }

    kfree(theBuffer);
    return error ? error : buf_size;
}

/// @brief THis function writes new process information to the theProcList
/// @param file 
/// @param buffer 
/// @param buffer_size 
/// @param file_offset 
/// @return 
static ssize_t kmlab_write(struct file *file, const char __user *buffer, size_t buffer_size, loff_t *file_offset)
{
    proc_list *new_entry;
    char *kernel_buf;
    int file_user = 0;

    // Allocate memory for the new process 
    new_entry = kmalloc(sizeof(proc_list), GFP_KERNEL);
    if (!new_entry) {
        return -ENOMEM;
    }
    INIT_LIST_HEAD(&new_entry->list);

    // Allocate a buffer
    kernel_buf = kmalloc(buffer_size + 1, GFP_KERNEL);
    if (!kernel_buf) {
        kfree(new_entry);
        return -ENOMEM;
    }

    // Copy from user space to kernel space
    if (copy_from_user(kernel_buf, buffer, buffer_size)) {
        file_user = -EFAULT;
    } 
    else 
    {
        kernel_buf[buffer_size] = '\0'; 
        // Parse the PID from the buffer and set it in the new list entry
        if (sscanf(kernel_buf, "%u", &new_entry->pid) != 1) 
        {
            file_user = -EINVAL;
        } 
        else {
            // Initialize the cpu_time 
            new_entry->cpu_time = 0;

            // Add the new process list entry to the list
            spin_lock(&the_lock);
            list_add(&new_entry->list, &theProcList);
            spin_unlock(&the_lock);
        }
    }

    // Free the buffer memory
    kfree(kernel_buf);

    if (file_user) {
        kfree(new_entry);
        return file_user;
    }


    return buffer_size;
}


static const struct proc_ops kmlab_proc_ops = {
    .proc_read = kmlab_read,
    .proc_write = kmlab_write,
};
/// @brief callback the timer 
/// @param timer 
void timer_callback_function(struct timer_list *timer)
{
    queue_work(the_workqueue, the_work);
    
}
/// @brief This function will execute by the workqueue itterates over the proc list and updates or deletes entries and reset the timer for the next work
/// @param work 
static void workFunction(struct work_struct *work)
{
    proc_list *currentWork, *nextWork;
    // Enter 
    spin_lock(&the_lock);

    // Iterate over each entry in the theProcList safely
    list_for_each_entry_safe(currentWork, nextWork, &theProcList, list) {
        // Unregister the process from theProcList if the process does not exist
        int cpu_status = get_cpu_use(currentWork->pid, &currentWork->cpu_time);
        if (cpu_status == -1) {
            list_del(&currentWork->list);
            kfree(currentWork); // Freeing the memory for the removed process entry
        }
        // if the cpu status is 0
        else
        {
            continue;
        }
    }
    // Exit
    spin_unlock(&the_lock);

    // Restart the timer
    mod_timer(&kmlab_timer, jiffies + msecs_to_jiffies(5000));
}



// kmlab_init - Called when module is loaded
int __init kmlab_init(void)
{
   #ifdef DEBUG
   pr_info("KMLAB MODULE LOADING\n");
   #endif
   // Insert your code here ...

    // Create /proc/kmlab directory and /proc/kmlab/status file
    proc_dir = proc_mkdir(DIRECTORY, NULL);
    if (proc_dir) 
    {
        // the 0666 jjust setting the permission like 4 is read and 2 is write thus it's 6
        proc_entry = proc_create(FILENAME, 0666, proc_dir, &kmlab_proc_ops);
    }

    
    // initialize and start the timer
    timer_setup(&kmlab_timer, timer_callback_function, 0);
    mod_timer(&kmlab_timer, jiffies + msecs_to_jiffies(5000));

    do {
        // Initialize workqueue
        the_workqueue = create_workqueue("the_workqueue");
        if (!the_workqueue) {
            pr_err("Failed to create workqueue\n");
            break;
        }

        // Initialize work
        the_work = kmalloc(sizeof(*the_work), GFP_KERNEL);
        if (!the_work) {
            pr_err("Failed to allocate memory for work structure\n");
            destroy_workqueue(the_workqueue);
            break;
        }
        INIT_WORK(the_work, workFunction);

        // Initialize lock
        spin_lock_init(&the_lock);

        pr_info("KMLAB MODULE LOADED\n");
        return 0; 
    } while (0);

    // Cleanup in case of failure
    if (proc_entry)
    {
        remove_proc_entry(FILENAME, proc_dir);
    }
       
    if (proc_dir)
    {
        remove_proc_entry(DIRECTORY, NULL);
    }
        
   
   
   pr_info("KMLAB MODULE LOADED\n");
   return 0;   
}

// kmlab_exit - Called when module is unloaded
void __exit kmlab_exit(void)
{
   proc_list *current_entry; 
   proc_list *next_entry;
    #ifdef DEBUG
    pr_info("KMLAB MODULE UNLOADING\n");
    #endif
    // Insert your code here ...
    
    remove_proc_entry(FILENAME, proc_dir);
    remove_proc_entry(DIRECTORY, NULL);

    // free  the list
    list_for_each_entry_safe(current_entry, next_entry, &theProcList, list) 
    {
        list_del(&current_entry->list);
        kfree(current_entry);
    }
    // destroy work and workqueue
    del_timer_sync(&kmlab_timer);
    flush_workqueue(the_workqueue);
    destroy_workqueue(the_workqueue);
    kfree(the_work);

    pr_info("KMLAB MODULE UNLOADED\n");

}

// Register init and exit funtions
module_init(kmlab_init);
module_exit(kmlab_exit);
