/*
 * wdm_host_main.c - WDM Host kernel module initialization and control device
 *
 * This is the main entry point for the wdm_host kernel module, which provides
 * Windows Driver Model (WDM) emulation inside the Linux kernel. It allows
 * Windows .sys driver binaries to be loaded, initialized, and dispatched
 * through a Linux character device interface.
 *
 * The module creates:
 *   /dev/wdm_host    - Misc device for userspace control ioctls
 *   /proc/wdm_host   - Proc entry showing loaded drivers and devices
 *
 * Userspace tools communicate with this module through ioctls to load/unload
 * drivers, start them (invoke DriverEntry), list loaded drivers, and send
 * IRP requests to emulated devices.
 */

#include "wdm_host_internal.h"

#include <linux/atomic.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>

/* ============================================================================
 * Module metadata
 * ============================================================================ */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("WDM Host Project");
MODULE_DESCRIPTION("Windows Driver Model host - loads and runs Windows .sys drivers");
MODULE_VERSION("0.1.0");

/* ============================================================================
 * Module parameters
 * ============================================================================ */

static int wdm_debug;
module_param(wdm_debug, int, 0644);
MODULE_PARM_DESC(wdm_debug, "Debug verbosity level (0=off, 1=info, 2=verbose, 3=trace)");

/* ============================================================================
 * Logging macros (respecting wdm_debug level)
 * ============================================================================ */

#define wdm_err(fmt, ...)   pr_err("wdm_host: " fmt "\n", ##__VA_ARGS__)
#define wdm_warn(fmt, ...)  pr_warn("wdm_host: " fmt "\n", ##__VA_ARGS__)
#define wdm_info(fmt, ...)  do { if (wdm_debug >= 1) pr_info("wdm_host: " fmt "\n", ##__VA_ARGS__); } while (0)
#define wdm_dbg(fmt, ...)   do { if (wdm_debug >= 2) pr_debug("wdm_host: " fmt "\n", ##__VA_ARGS__); } while (0)
#define wdm_trace(fmt, ...) do { if (wdm_debug >= 3) pr_debug("wdm_host: [trace] " fmt "\n", ##__VA_ARGS__); } while (0)

/* ============================================================================
 * Global state
 * ============================================================================ */

/* Global driver list and its protecting mutex */
LIST_HEAD(wdm_driver_list);
DEFINE_MUTEX(wdm_driver_lock);
EXPORT_SYMBOL_GPL(wdm_driver_list);
EXPORT_SYMBOL_GPL(wdm_driver_lock);

/* Global device list and its protecting mutex */
LIST_HEAD(wdm_device_list);
DEFINE_MUTEX(wdm_device_lock);
EXPORT_SYMBOL_GPL(wdm_device_list);
EXPORT_SYMBOL_GPL(wdm_device_lock);

/* Reference count for the control device open/close */
static atomic_t wdm_host_refcount = ATOMIC_INIT(0);

/* Proc filesystem entry */
static struct proc_dir_entry *wdm_proc_entry;

/* ============================================================================
 * Internal helper: find a driver by name (caller must hold wdm_driver_lock)
 * ============================================================================ */

static struct wdm_driver *wdm_find_driver_locked(const char *name)
{
	struct wdm_driver *drv;

	list_for_each_entry(drv, &wdm_driver_list, list) {
		if (strncmp(drv->name, name, sizeof(drv->name)) == 0)
			return drv;
	}
	return NULL;
}

/* ============================================================================
 * Internal helper: count devices owned by a driver
 * ============================================================================ */

static int wdm_count_driver_devices(struct wdm_driver *drv)
{
	struct wdm_device *dev;
	int count = 0;

	list_for_each_entry(dev, &drv->devices, driver_list)
		count++;

	return count;
}

/* ============================================================================
 * /dev/wdm_host file operations
 * ============================================================================ */

/*
 * wdm_host_open - Called when userspace opens /dev/wdm_host
 *
 * Increments the reference count to track active users of the control device.
 */
static int wdm_host_open(struct inode *inode, struct file *filp)
{
	atomic_inc(&wdm_host_refcount);
	wdm_info("control device opened (refcount=%d)",
		 atomic_read(&wdm_host_refcount));
	return 0;
}

/*
 * wdm_host_release - Called when userspace closes /dev/wdm_host
 *
 * Decrements the reference count.
 */
static int wdm_host_release(struct inode *inode, struct file *filp)
{
	atomic_dec(&wdm_host_refcount);
	wdm_info("control device closed (refcount=%d)",
		 atomic_read(&wdm_host_refcount));
	return 0;
}

/*
 * wdm_host_ioctl - Dispatch control ioctls from userspace
 *
 * This is the primary control interface. Userspace tools send ioctl commands
 * to load/unload drivers, start them, list them, or send IRPs to devices.
 */
static long wdm_host_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	int ret;

	wdm_trace("ioctl cmd=0x%x arg=0x%lx", cmd, arg);

	switch (cmd) {

	/* ----------------------------------------------------------------
	 * WDM_IOCTL_LOAD_DRIVER: Load a .sys driver image into kernel memory
	 * ---------------------------------------------------------------- */
	case WDM_IOCTL_LOAD_DRIVER: {
		struct wdm_load_request req;

		if (copy_from_user(&req, uarg, sizeof(req)))
			return -EFAULT;

		/* Ensure strings are null-terminated */
		req.path[sizeof(req.path) - 1] = '\0';
		req.name[sizeof(req.name) - 1] = '\0';

		wdm_info("LOAD_DRIVER: name='%s' path='%s'", req.name, req.path);

		ret = wdm_load_driver(req.path, req.name);
		if (ret < 0) {
			wdm_err("failed to load driver '%s': %d", req.name, ret);
			return ret;
		}

		wdm_info("driver '%s' loaded successfully", req.name);
		return 0;
	}

	/* ----------------------------------------------------------------
	 * WDM_IOCTL_UNLOAD_DRIVER: Unload a previously loaded driver
	 * ---------------------------------------------------------------- */
	case WDM_IOCTL_UNLOAD_DRIVER: {
		char name[256];

		if (copy_from_user(name, uarg, sizeof(name)))
			return -EFAULT;
		name[sizeof(name) - 1] = '\0';

		wdm_info("UNLOAD_DRIVER: name='%s'", name);

		ret = wdm_unload_driver(name);
		if (ret < 0) {
			wdm_err("failed to unload driver '%s': %d", name, ret);
			return ret;
		}

		wdm_info("driver '%s' unloaded successfully", name);
		return 0;
	}

	/* ----------------------------------------------------------------
	 * WDM_IOCTL_START_DRIVER: Invoke the driver's DriverEntry function
	 * ---------------------------------------------------------------- */
	case WDM_IOCTL_START_DRIVER: {
		char name[256];
		struct wdm_driver *drv;
		typedef int (*driver_entry_fn)(void *driver_obj, void *registry_path);
		driver_entry_fn entry;
		int nt_status;

		if (copy_from_user(name, uarg, sizeof(name)))
			return -EFAULT;
		name[sizeof(name) - 1] = '\0';

		wdm_info("START_DRIVER: name='%s'", name);

		mutex_lock(&wdm_driver_lock);
		drv = wdm_find_driver_locked(name);
		if (!drv) {
			mutex_unlock(&wdm_driver_lock);
			wdm_err("start: driver '%s' not found", name);
			return -ENOENT;
		}

		if (drv->state != WDM_STATE_LOADED) {
			mutex_unlock(&wdm_driver_lock);
			wdm_err("start: driver '%s' in wrong state (%d)",
				name, drv->state);
			return -EINVAL;
		}

		if (!drv->entry_point) {
			mutex_unlock(&wdm_driver_lock);
			wdm_err("start: driver '%s' has no entry point", name);
			return -EINVAL;
		}

		/*
		 * Call the driver's DriverEntry function.
		 * In a full implementation, we would construct a proper
		 * DRIVER_OBJECT and UNICODE_STRING registry path here.
		 * For now we pass the driver struct as the "driver object"
		 * and NULL for the registry path.
		 */
		entry = (driver_entry_fn)drv->entry_point;
		mutex_unlock(&wdm_driver_lock);

		wdm_info("invoking DriverEntry for '%s' at %pK", name, entry);
		nt_status = entry(drv, NULL);

		mutex_lock(&wdm_driver_lock);
		if (nt_status >= 0) {
			/* NT_SUCCESS: NTSTATUS >= 0 means success */
			drv->state = WDM_STATE_STARTED;
			wdm_info("driver '%s' started (NTSTATUS=0x%08x)",
				 name, nt_status);
		} else {
			drv->state = WDM_STATE_ERROR;
			wdm_err("driver '%s' DriverEntry failed (NTSTATUS=0x%08x)",
				name, nt_status);
		}
		mutex_unlock(&wdm_driver_lock);

		return (nt_status >= 0) ? 0 : -EIO;
	}

	/* ----------------------------------------------------------------
	 * WDM_IOCTL_LIST_DRIVERS: Return array of wdm_driver_info to user
	 * ---------------------------------------------------------------- */
	case WDM_IOCTL_LIST_DRIVERS: {
		struct wdm_driver_info *info_array;
		struct wdm_driver *drv;
		int count = 0;
		int i = 0;

		mutex_lock(&wdm_driver_lock);

		/* Count drivers */
		list_for_each_entry(drv, &wdm_driver_list, list)
			count++;

		if (count == 0) {
			mutex_unlock(&wdm_driver_lock);
			return 0;
		}

		info_array = kvmalloc_array(count, sizeof(*info_array),
					    GFP_KERNEL | __GFP_ZERO);
		if (!info_array) {
			mutex_unlock(&wdm_driver_lock);
			wdm_err("list: failed to allocate info array for %d drivers",
				count);
			return -ENOMEM;
		}

		/* Fill the info array */
		list_for_each_entry(drv, &wdm_driver_list, list) {
			if (i >= count)
				break;
			strscpy(info_array[i].name, drv->name,
				sizeof(info_array[i].name));
			info_array[i].state = drv->state;
			info_array[i].device_count = wdm_count_driver_devices(drv);
			i++;
		}
		mutex_unlock(&wdm_driver_lock);

		/* Copy the array to userspace */
		if (copy_to_user(uarg, info_array,
				 (size_t)i * sizeof(*info_array))) {
			kvfree(info_array);
			return -EFAULT;
		}

		kvfree(info_array);
		wdm_info("LIST_DRIVERS: returned %d driver(s)", i);
		return i;
	}

	/* ----------------------------------------------------------------
	 * WDM_IOCTL_SEND_IRP: Dispatch an IRP to a device
	 * ---------------------------------------------------------------- */
	case WDM_IOCTL_SEND_IRP: {
		struct wdm_irp_request req;
		struct wdm_device *dev;
		struct wdm_irp irp;

		if (copy_from_user(&req, uarg, sizeof(req)))
			return -EFAULT;
		req.device_name[sizeof(req.device_name) - 1] = '\0';

		wdm_dbg("SEND_IRP: device='%s' major=%u ioctl=0x%x",
			 req.device_name, req.major, req.ioctl_code);

		/* Find the target device */
		dev = wdm_find_device(req.device_name);
		if (!dev) {
			wdm_err("send_irp: device '%s' not found",
				req.device_name);
			return -ENODEV;
		}

		/* Build the internal IRP structure */
		memset(&irp, 0, sizeof(irp));
		irp.major_function = req.major;
		irp.minor_function = 0;
		irp.ioctl_code = req.ioctl_code;
		irp.output_length = req.out_len;

		/*
		 * Copy input data from userspace into a kernel buffer.
		 * The dispatch function will handle output copying.
		 */
		if (req.in_buf && req.in_len > 0) {
			irp.system_buffer = kvmalloc(req.in_len,
						     GFP_KERNEL);
			if (!irp.system_buffer)
				return -ENOMEM;

			if (copy_from_user(irp.system_buffer,
					   req.in_buf, req.in_len)) {
				kvfree(irp.system_buffer);
				return -EFAULT;
			}
			irp.buffer_length = req.in_len;
		}

		/* Allocate output buffer if needed */
		if (req.out_buf && req.out_len > 0) {
			irp.user_buffer = kvzalloc(req.out_len, GFP_KERNEL);
			if (!irp.user_buffer) {
				kvfree(irp.system_buffer);
				return -ENOMEM;
			}
		}

		/* Dispatch the IRP to the driver */
		ret = wdm_dispatch_irp(dev, &irp);

		/*
		 * Copy output data back to userspace.
		 * irp.information holds the number of bytes the driver wrote.
		 */
		if (req.out_buf && irp.information > 0) {
			size_t copy_len = min(irp.information, req.out_len);
			if (copy_to_user(req.out_buf, irp.user_buffer,
					 copy_len)) {
				kvfree(irp.system_buffer);
				kvfree(irp.user_buffer);
				return -EFAULT;
			}
		}

		/*
		 * Write back the NTSTATUS and information fields so
		 * userspace can inspect the result.
		 */
		req.out_len = irp.information;
		if (copy_to_user(uarg, &req, sizeof(req))) {
			kvfree(irp.system_buffer);
			kvfree(irp.user_buffer);
			return -EFAULT;
		}

		kvfree(irp.system_buffer);
		kvfree(irp.user_buffer);

		wdm_dbg("SEND_IRP: completed status=0x%08x info=%zu",
			 irp.status, irp.information);
		return ret;
	}

	default:
		wdm_warn("unknown ioctl cmd=0x%x", cmd);
		return -ENOTTY;
	}
}

/* File operations for the /dev/wdm_host control device */
static const struct file_operations wdm_host_fops = {
	.owner          = THIS_MODULE,
	.open           = wdm_host_open,
	.release        = wdm_host_release,
	.unlocked_ioctl = wdm_host_ioctl,
	.compat_ioctl   = wdm_host_ioctl,
};

/* Misc device structure for /dev/wdm_host */
static struct miscdevice wdm_host_miscdev = {
	.minor  = MISC_DYNAMIC_MINOR,
	.name   = "wdm_host",
	.fops   = &wdm_host_fops,
	.mode   = 0660,
};

/* ============================================================================
 * /proc/wdm_host - Proc filesystem entry using seq_file
 *
 * Provides a human-readable status dump of all loaded drivers and their
 * devices, useful for debugging and monitoring.
 * ============================================================================ */

static int wdm_proc_show(struct seq_file *m, void *v)
{
	struct wdm_driver *drv;
	struct wdm_device *dev;
	int drv_count = 0;
	int dev_count = 0;

	seq_puts(m, "WDM Host Module Status\n");
	seq_puts(m, "======================\n\n");

	seq_printf(m, "Debug level: %d\n", wdm_debug);
	seq_printf(m, "Control device refcount: %d\n\n",
		   atomic_read(&wdm_host_refcount));

	/* --- Loaded drivers --- */
	seq_puts(m, "Loaded Drivers:\n");
	seq_puts(m, "---------------\n");

	mutex_lock(&wdm_driver_lock);
	list_for_each_entry(drv, &wdm_driver_list, list) {
		const char *state_str;
		int ndev;

		switch (drv->state) {
		case WDM_STATE_UNLOADED: state_str = "unloaded"; break;
		case WDM_STATE_LOADED:   state_str = "loaded";   break;
		case WDM_STATE_STARTED:  state_str = "started";  break;
		case WDM_STATE_ERROR:    state_str = "error";    break;
		default:                 state_str = "unknown";  break;
		}

		ndev = wdm_count_driver_devices(drv);

		seq_printf(m, "  [%d] %-32s state=%-10s image=%pK size=%zu devices=%d\n",
			   drv_count, drv->name, state_str,
			   drv->image_base, drv->image_size, ndev);

		/* List devices belonging to this driver */
		list_for_each_entry(dev, &drv->devices, driver_list) {
			seq_printf(m, "      -> %-40s type=0x%04x flags=0x%08x ext=%zu\n",
				   dev->device_name, dev->device_type,
				   dev->flags, dev->extension_size);
		}

		drv_count++;
	}
	mutex_unlock(&wdm_driver_lock);

	if (drv_count == 0)
		seq_puts(m, "  (none)\n");

	seq_putc(m, '\n');

	/* --- All devices (global list) --- */
	seq_puts(m, "All Devices:\n");
	seq_puts(m, "------------\n");

	mutex_lock(&wdm_device_lock);
	list_for_each_entry(dev, &wdm_device_list, global_list) {
		seq_printf(m, "  [%d] %-40s driver=%-20s symlink=%s\n",
			   dev_count, dev->device_name,
			   dev->driver ? dev->driver->name : "(orphan)",
			   dev->symlink_name[0] ? dev->symlink_name : "(none)");
		dev_count++;
	}
	mutex_unlock(&wdm_device_lock);

	if (dev_count == 0)
		seq_puts(m, "  (none)\n");

	seq_printf(m, "\nTotal: %d driver(s), %d device(s)\n",
		   drv_count, dev_count);

	return 0;
}

static int wdm_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, wdm_proc_show, NULL);
}

static const struct proc_ops wdm_proc_ops = {
	.proc_open    = wdm_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ============================================================================
 * Module initialization
 * ============================================================================ */

/*
 * wdm_host_init - Module entry point
 *
 * Registers the misc control device, creates the proc entry, initializes
 * all global state, and calls each subsystem's init function.
 */
static int __init wdm_host_init(void)
{
	int ret;

	pr_info("wdm_host: initializing WDM host module v0.1.0\n");

	/* Register the /dev/wdm_host misc device */
	ret = misc_register(&wdm_host_miscdev);
	if (ret) {
		pr_err("wdm_host: failed to register misc device: %d\n", ret);
		return ret;
	}

	/* Create /proc/wdm_host */
	wdm_proc_entry = proc_create("wdm_host", 0444, NULL, &wdm_proc_ops);
	if (!wdm_proc_entry) {
		pr_warn("wdm_host: failed to create /proc/wdm_host entry\n");
		/* Non-fatal: continue without proc entry */
	}

	/* Initialize subsystems */
	ret = wdm_host_loader_init();
	if (ret) {
		pr_err("wdm_host: loader init failed: %d\n", ret);
		goto err_loader;
	}

	ret = wdm_irp_init();
	if (ret) {
		pr_err("wdm_host: IRP subsystem init failed: %d\n", ret);
		goto err_irp;
	}

	ret = wdm_thunk_init();
	if (ret) {
		pr_err("wdm_host: ABI thunk init failed: %d\n", ret);
		goto err_thunk;
	}

	ret = wdm_device_init();
	if (ret) {
		pr_err("wdm_host: device subsystem init failed: %d\n", ret);
		goto err_device;
	}

	ret = wdm_dma_init();
	if (ret) {
		pr_err("wdm_host: DMA subsystem init failed: %d\n", ret);
		goto err_dma;
	}

	ret = wdm_pnp_init();
	if (ret) {
		pr_err("wdm_host: PnP subsystem init failed: %d\n", ret);
		goto err_pnp;
	}

	ret = wdm_registry_init();
	if (ret) {
		pr_err("wdm_host: registry subsystem init failed: %d\n", ret);
		goto err_registry;
	}

	pr_info("wdm_host: module loaded successfully (debug=%d)\n", wdm_debug);
	return 0;

	/* Unwind initialization in reverse order on failure */
err_registry:
	wdm_pnp_exit();
err_pnp:
	wdm_dma_exit();
err_dma:
	wdm_device_exit();
err_device:
	wdm_thunk_exit();
err_thunk:
	wdm_irp_exit();
err_irp:
	wdm_host_loader_exit();
err_loader:
	if (wdm_proc_entry)
		proc_remove(wdm_proc_entry);
	misc_deregister(&wdm_host_miscdev);
	return ret;
}

/* ============================================================================
 * Module cleanup
 * ============================================================================ */

/*
 * wdm_host_exit - Module exit point
 *
 * Unloads all drivers (calling their DriverUnload if available), destroys
 * all devices, tears down subsystems, removes the proc entry, and
 * deregisters the misc device.
 */
static void __exit wdm_host_exit(void)
{
	struct wdm_driver *drv, *drv_tmp;

	pr_info("wdm_host: unloading module\n");

	/*
	 * Phase 1: Unload all drivers.
	 * Call each driver's DriverUnload function (if set), free the mapped
	 * image, and remove the driver tracking structure.
	 */
	mutex_lock(&wdm_driver_lock);
	list_for_each_entry_safe(drv, drv_tmp, &wdm_driver_list, list) {
		pr_info("wdm_host: unloading driver '%s' (state=%d)\n",
			drv->name, drv->state);

		/* Invoke DriverUnload if the driver was started and has one */
		if (drv->state == WDM_STATE_STARTED && drv->unload_func) {
			typedef void (*unload_fn)(void *);
			unload_fn unload = (unload_fn)drv->unload_func;

			pr_info("wdm_host: calling DriverUnload for '%s'\n",
				drv->name);
			unload(drv);
		}

		/* Free the mapped driver image */
		if (drv->image_base) {
			vfree(drv->image_base);
			drv->image_base = NULL;
		}

		list_del(&drv->list);
		kfree(drv);
	}
	mutex_unlock(&wdm_driver_lock);

	/* Phase 2: Shut down subsystems in reverse order
	 * wdm_device_exit() properly destroys all remaining devices
	 * (cdev_del, device_destroy, kfree). */
	wdm_registry_exit();
	wdm_pnp_exit();
	wdm_dma_exit();
	wdm_device_exit();
	wdm_thunk_exit();
	wdm_irp_exit();
	wdm_host_loader_exit();

	/* Phase 3: Remove proc entry and deregister misc device */
	if (wdm_proc_entry)
		proc_remove(wdm_proc_entry);

	misc_deregister(&wdm_host_miscdev);

	pr_info("wdm_host: module unloaded\n");
}

module_init(wdm_host_init);
module_exit(wdm_host_exit);
