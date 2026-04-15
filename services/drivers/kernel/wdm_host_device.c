/*
 * wdm_host_device.c - IoCreateDevice/IoDeleteDevice emulation
 *
 * Implements Windows WDM device object creation and deletion on top of Linux
 * character devices.  Each wdm_device created by a loaded .sys driver is
 * backed by a real Linux cdev so that userspace can open /dev/wdm_X and
 * issue ioctls, reads, and writes that are translated into IRP dispatches
 * against the Windows driver.
 *
 * Copyright (c) 2026  WDM Host Project
 * SPDX-License-Identifier: GPL-2.0
 */

#include "wdm_host_internal.h"

/* ============================================================================
 * IRP major function codes used locally (from wdm_types.h, redefined for
 * kernel-side code that does not include the userspace header).
 * ============================================================================ */

#define WDM_IRP_MJ_CREATE              0x00
#define WDM_IRP_MJ_CLOSE               0x02
#define WDM_IRP_MJ_READ                0x03
#define WDM_IRP_MJ_WRITE               0x04
#define WDM_IRP_MJ_DEVICE_CONTROL      0x0E

/* ============================================================================
 * Module-level state
 * ============================================================================ */

static dev_t             wdm_dev_base;
static struct class     *wdm_dev_class;
static int               wdm_dev_next_minor;

/*
 * Minor-number-to-device lookup table.
 * Indexed by minor number; used by file_operations.open to resolve the
 * wdm_device from the opened inode.
 */
static struct wdm_device *wdm_devices[WDM_HOST_MAX_DEVICES];

/* Protects wdm_devices[] and wdm_dev_next_minor */
static DEFINE_MUTEX(wdm_dev_table_lock);

/* ============================================================================
 * Forward declarations for file_operations callbacks
 * ============================================================================ */

static int     wdm_dev_open(struct inode *inode, struct file *filp);
static int     wdm_dev_release(struct inode *inode, struct file *filp);
static long    wdm_dev_ioctl(struct file *filp, unsigned int cmd,
			     unsigned long arg);
static ssize_t wdm_dev_read(struct file *filp, char __user *buf,
			    size_t count, loff_t *ppos);
static ssize_t wdm_dev_write(struct file *filp, const char __user *buf,
			     size_t count, loff_t *ppos);

/* ============================================================================
 * File operations structure exposed by every /dev/wdm_X character device
 * ============================================================================ */

static const struct file_operations wdm_dev_fops = {
	.owner          = THIS_MODULE,
	.open           = wdm_dev_open,
	.release        = wdm_dev_release,
	.unlocked_ioctl = wdm_dev_ioctl,
	.read           = wdm_dev_read,
	.write          = wdm_dev_write,
};

/* ============================================================================
 * File operations implementation
 * ============================================================================ */

/*
 * wdm_dev_open - Called when userspace opens /dev/wdm_X.
 *
 * Looks up the wdm_device by the inode minor number, stores it in
 * file->private_data for subsequent operations, and dispatches an
 * IRP_MJ_CREATE stub to the Windows driver (if a handler is registered).
 */
static int wdm_dev_open(struct inode *inode, struct file *filp)
{
	unsigned int minor = iminor(inode);
	struct wdm_device *dev;
	struct wdm_irp irp;

	if (minor >= WDM_HOST_MAX_DEVICES)
		return -ENODEV;

	mutex_lock(&wdm_dev_table_lock);
	dev = wdm_devices[minor];
	mutex_unlock(&wdm_dev_table_lock);

	if (!dev)
		return -ENODEV;

	filp->private_data = dev;

	/* Dispatch IRP_MJ_CREATE stub to the Windows driver */
	memset(&irp, 0, sizeof(irp));
	irp.major_function = WDM_IRP_MJ_CREATE;
	wdm_dispatch_irp(dev, &irp);

	pr_info("wdm_host: device '%s' opened (minor %u)\n",
		dev->device_name, minor);
	return 0;
}

/*
 * wdm_dev_release - Called when userspace closes the last fd to /dev/wdm_X.
 *
 * Dispatches an IRP_MJ_CLOSE stub to the Windows driver.
 */
static int wdm_dev_release(struct inode *inode, struct file *filp)
{
	struct wdm_device *dev = filp->private_data;
	struct wdm_irp irp;

	if (!dev)
		return 0;

	memset(&irp, 0, sizeof(irp));
	irp.major_function = WDM_IRP_MJ_CLOSE;
	wdm_dispatch_irp(dev, &irp);

	pr_info("wdm_host: device '%s' closed\n", dev->device_name);
	return 0;
}

/*
 * wdm_dev_ioctl - Handle DeviceIoControl from userspace.
 *
 * The ioctl code is treated as a raw Windows IOCTL code.  A system buffer is
 * allocated, input data is copied from userspace, the IRP is dispatched to
 * the loaded driver, and the result is copied back.
 */
static long wdm_dev_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg)
{
	struct wdm_device *dev = filp->private_data;
	struct wdm_irp irp;
	void __user *uarg = (void __user *)arg;
	struct wdm_irp_request req;
	void *in_buf  = NULL;
	void *out_buf = NULL;
	int ret;

	if (!dev)
		return -ENODEV;

	/* Copy the IRP request descriptor from userspace */
	if (copy_from_user(&req, uarg, sizeof(req)))
		return -EFAULT;

	/*
	 * METHOD_BUFFERED semantics: allocate ONE system buffer large enough
	 * for max(in_len, out_len). Input is copied in; driver writes output
	 * to the same buffer; we copy out on the way back.
	 */
	{
		size_t sysbuf_len = req.in_len;
		void *sysbuf = NULL;

		if (req.out_len > sysbuf_len)
			sysbuf_len = req.out_len;

		/* Cap userspace-specified buffer size to prevent DoS via
		 * arbitrary kernel allocation. 16 MiB matches roughly the
		 * per-IRP limit used in the read/write paths. */
		if (sysbuf_len > (16UL << 20)) {
			pr_warn("wdm_host: ioctl buffer size %zu too large, rejecting\n",
				sysbuf_len);
			return -EINVAL;
		}

		if (sysbuf_len > 0) {
			sysbuf = kzalloc(sysbuf_len, GFP_KERNEL);
			if (!sysbuf)
				return -ENOMEM;
			if (req.in_len > 0 && req.in_buf &&
			    copy_from_user(sysbuf, req.in_buf, req.in_len)) {
				kfree(sysbuf);
				return -EFAULT;
			}
		}

		in_buf = sysbuf;
		out_buf = sysbuf;  /* Same buffer for METHOD_BUFFERED output */
	}

	/* Build the kernel-side IRP */
	memset(&irp, 0, sizeof(irp));
	irp.major_function = WDM_IRP_MJ_DEVICE_CONTROL;
	irp.ioctl_code     = req.ioctl_code;
	irp.system_buffer  = in_buf;
	irp.buffer_length  = req.in_len;
	irp.user_buffer    = out_buf;
	irp.output_length  = req.out_len;

	ret = wdm_dispatch_irp(dev, &irp);

	/* Copy output data back to userspace */
	if (ret == 0 && out_buf && req.out_buf && irp.information > 0) {
		size_t copy_len = irp.information;

		if (copy_len > req.out_len)
			copy_len = req.out_len;
		if (copy_to_user(req.out_buf, out_buf, copy_len))
			ret = -EFAULT;
	}

	/* in_buf and out_buf alias the same allocation in METHOD_BUFFERED */
	kfree(in_buf);
	return ret;
}

/*
 * wdm_dev_read - Dispatch IRP_MJ_READ to the Windows driver.
 *
 * Allocates a kernel buffer, dispatches IRP_MJ_READ through the driver's
 * dispatch table via the ABI thunk, and copies data back to userspace.
 */
static ssize_t wdm_dev_read(struct file *filp, char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct wdm_device *dev = filp->private_data;
	struct wdm_irp irp;
	void *kbuf;
	int ret;

	if (!dev)
		return -ENODEV;

	if (count == 0)
		return 0;

	if (count > (1 << 20))  /* 1 MB limit */
		count = 1 << 20;

	kbuf = kzalloc(count, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	memset(&irp, 0, sizeof(irp));
	irp.major_function = WDM_IRP_MJ_READ;
	irp.system_buffer  = kbuf;
	irp.buffer_length  = count;
	irp.user_buffer    = kbuf;
	irp.output_length  = count;

	ret = wdm_dispatch_irp(dev, &irp);
	if (ret < 0) {
		kfree(kbuf);
		return ret;
	}

	/* Check NTSTATUS for failure */
	if (irp.status < 0) {
		pr_debug("wdm_host: read on '%s' failed (NTSTATUS=0x%08X)\n",
			 dev->device_name, irp.status);
		kfree(kbuf);
		return -EIO;
	}

	/* Copy whatever the driver produced to userspace */
	if (irp.information > 0) {
		size_t to_copy = irp.information;

		if (to_copy > count)
			to_copy = count;
		if (copy_to_user(buf, kbuf, to_copy)) {
			kfree(kbuf);
			return -EFAULT;
		}
		*ppos += to_copy;
		kfree(kbuf);
		return to_copy;
	}

	kfree(kbuf);
	return 0;
}

/*
 * wdm_dev_write - Dispatch IRP_MJ_WRITE to the Windows driver.
 *
 * Copies data from userspace into a kernel buffer, then dispatches
 * IRP_MJ_WRITE through the driver's dispatch table via the ABI thunk.
 */
static ssize_t wdm_dev_write(struct file *filp, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct wdm_device *dev = filp->private_data;
	struct wdm_irp irp;
	void *kbuf;
	int ret;

	if (!dev)
		return -ENODEV;

	if (count == 0)
		return 0;

	if (count > (1 << 20))  /* 1 MB limit */
		count = 1 << 20;

	kbuf = kmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, buf, count)) {
		kfree(kbuf);
		return -EFAULT;
	}

	memset(&irp, 0, sizeof(irp));
	irp.major_function = WDM_IRP_MJ_WRITE;
	irp.system_buffer  = kbuf;
	irp.buffer_length  = count;
	irp.user_buffer    = kbuf;

	ret = wdm_dispatch_irp(dev, &irp);
	kfree(kbuf);

	if (ret < 0)
		return ret;

	/* Check NTSTATUS for failure */
	if (irp.status < 0) {
		pr_debug("wdm_host: write on '%s' failed (NTSTATUS=0x%08X)\n",
			 dev->device_name, irp.status);
		return -EIO;
	}

	/* Return bytes the driver reported as written */
	if (irp.information > 0) {
		*ppos += irp.information;
		return irp.information;
	}

	/* If the driver didn't report, assume all bytes were consumed */
	*ppos += count;
	return count;
}

/* ============================================================================
 * Device creation / deletion / lookup
 * ============================================================================ */

/*
 * wdm_create_device - Create a WDM device backed by a Linux char device.
 *
 * 1.  Allocates a struct wdm_device with kzalloc.
 * 2.  Copies name, symlink, driver pointer, type, and flags.
 * 3.  Allocates device extension memory if ext_size > 0.
 * 4.  Assigns the next available minor number.
 * 5.  Initialises and adds a cdev with wdm_dev_fops.
 * 6.  Creates /dev/wdm_X via device_create with the wdm_host class.
 * 7.  Adds the device to the driver's device list and the global list.
 * 8.  Logs the creation.
 * 9.  Returns 0 on success, negative errno on failure.
 */
int wdm_create_device(struct wdm_driver *drv, const char *name,
		       const char *symlink, uint32_t type,
		       size_t ext_size, uint32_t flags)
{
	struct wdm_device *dev;
	int minor;
	int ret;

	if (!drv || !name)
		return -EINVAL;

	/* Allocate the device structure */
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	/* Populate basic fields */
	strscpy(dev->device_name, name, sizeof(dev->device_name));
	if (symlink)
		strscpy(dev->symlink_name, symlink, sizeof(dev->symlink_name));
	dev->driver      = drv;
	dev->device_type = type;
	dev->flags       = flags;

	/* Allocate device extension if requested */
	if (ext_size > 0) {
		dev->device_extension = kzalloc(ext_size, GFP_KERNEL);
		if (!dev->device_extension) {
			ret = -ENOMEM;
			goto err_free_dev;
		}
		dev->extension_size = ext_size;
	}

	/* Assign next minor number */
	mutex_lock(&wdm_dev_table_lock);
	if (wdm_dev_next_minor >= WDM_HOST_MAX_DEVICES) {
		mutex_unlock(&wdm_dev_table_lock);
		pr_err("wdm_host: no free minor numbers\n");
		ret = -ENOSPC;
		goto err_free_ext;
	}
	minor = wdm_dev_next_minor++;
	dev->devno = MKDEV(MAJOR(wdm_dev_base), minor);
	wdm_devices[minor] = dev;
	mutex_unlock(&wdm_dev_table_lock);

	/* Initialise and add the character device */
	cdev_init(&dev->cdev, &wdm_dev_fops);
	dev->cdev.owner = THIS_MODULE;
	ret = cdev_add(&dev->cdev, dev->devno, 1);
	if (ret) {
		pr_err("wdm_host: cdev_add failed for '%s' (err %d)\n",
		       name, ret);
		goto err_clear_slot;
	}

	/* Create the /dev/wdm_X device node visible to userspace */
	if (IS_ERR(device_create(wdm_dev_class, NULL, dev->devno, NULL,
				 "wdm_%d", minor))) {
		pr_err("wdm_host: device_create failed for '%s'\n", name);
		ret = -ENODEV;
		goto err_cdev_del;
	}

	/* Add to the driver's per-driver device list */
	mutex_lock(&wdm_device_lock);
	list_add_tail(&dev->driver_list, &drv->devices);
	list_add_tail(&dev->global_list, &wdm_device_list);
	mutex_unlock(&wdm_device_lock);

	pr_info("wdm_host: created device '%s' -> /dev/wdm_%d "
		"(type=0x%x, ext=%zu, flags=0x%x)\n",
		name, minor, type, ext_size, flags);
	return 0;

err_cdev_del:
	cdev_del(&dev->cdev);
err_clear_slot:
	mutex_lock(&wdm_dev_table_lock);
	wdm_devices[minor] = NULL;
	mutex_unlock(&wdm_dev_table_lock);
err_free_ext:
	kfree(dev->device_extension);
err_free_dev:
	kfree(dev);
	return ret;
}

/*
 * wdm_delete_device - Tear down and free a WDM device.
 *
 * Removes the device from all lists, destroys the /dev node, deletes the
 * cdev, and frees associated memory.
 */
void wdm_delete_device(struct wdm_device *dev)
{
	unsigned int minor;

	if (!dev)
		return;

	minor = MINOR(dev->devno);

	pr_info("wdm_host: deleting device '%s' (minor %u)\n",
		dev->device_name, minor);

	/* Remove from driver and global lists */
	mutex_lock(&wdm_device_lock);
	list_del(&dev->driver_list);
	list_del(&dev->global_list);
	mutex_unlock(&wdm_device_lock);

	/* Destroy the sysfs/devtmpfs node and the cdev */
	device_destroy(wdm_dev_class, dev->devno);
	cdev_del(&dev->cdev);

	/* Clear the minor-number slot */
	mutex_lock(&wdm_dev_table_lock);
	if (minor < WDM_HOST_MAX_DEVICES)
		wdm_devices[minor] = NULL;
	mutex_unlock(&wdm_dev_table_lock);

	/* Free extension and device structure */
	kfree(dev->device_extension);
	kfree(dev);
}

/*
 * wdm_find_device - Look up a WDM device by its NT device name.
 *
 * Scans the global device list (protected by wdm_device_lock) and returns
 * the first device whose device_name matches.  Returns NULL if not found.
 */
struct wdm_device *wdm_find_device(const char *name)
{
	struct wdm_device *dev;

	if (!name)
		return NULL;

	mutex_lock(&wdm_device_lock);
	list_for_each_entry(dev, &wdm_device_list, global_list) {
		if (strcmp(dev->device_name, name) == 0) {
			mutex_unlock(&wdm_device_lock);
			return dev;
		}
	}
	mutex_unlock(&wdm_device_lock);

	return NULL;
}

/* ============================================================================
 * Subsystem init / exit
 * ============================================================================ */

/*
 * wdm_device_init - Allocate a char device region and create the device class.
 *
 * Called during module initialisation.
 */
int wdm_device_init(void)
{
	int ret;

	wdm_dev_next_minor = 0;
	memset(wdm_devices, 0, sizeof(wdm_devices));

	ret = alloc_chrdev_region(&wdm_dev_base, 0, WDM_HOST_MAX_DEVICES,
				  "wdm_dev");
	if (ret) {
		pr_err("wdm_host: alloc_chrdev_region failed: %d\n", ret);
		return ret;
	}

	wdm_dev_class = class_create("wdm_host");
	if (IS_ERR(wdm_dev_class)) {
		pr_err("wdm_host: class_create failed\n");
		unregister_chrdev_region(wdm_dev_base, WDM_HOST_MAX_DEVICES);
		return PTR_ERR(wdm_dev_class);
	}

	pr_info("wdm_host: device subsystem initialised "
		"(major %d, up to %d devices)\n",
		MAJOR(wdm_dev_base), WDM_HOST_MAX_DEVICES);
	return 0;
}

/*
 * wdm_device_exit - Destroy all devices, unregister the region, destroy class.
 *
 * Called during module teardown.
 */
void wdm_device_exit(void)
{
	int i;
	struct wdm_device *dev;

	/* Destroy any devices that were not explicitly deleted */
	mutex_lock(&wdm_dev_table_lock);
	for (i = 0; i < WDM_HOST_MAX_DEVICES; i++) {
		dev = wdm_devices[i];
		if (dev) {
			wdm_devices[i] = NULL;
			mutex_unlock(&wdm_dev_table_lock);

			/*
			 * Remove from lists; we do not hold wdm_dev_table_lock
			 * while deleting because wdm_delete_device takes its
			 * own locks.  Re-acquire after the call.
			 */
			mutex_lock(&wdm_device_lock);
			list_del(&dev->driver_list);
			list_del(&dev->global_list);
			mutex_unlock(&wdm_device_lock);

			device_destroy(wdm_dev_class, dev->devno);
			cdev_del(&dev->cdev);
			kfree(dev->device_extension);
			kfree(dev);

			mutex_lock(&wdm_dev_table_lock);
		}
	}
	mutex_unlock(&wdm_dev_table_lock);

	class_destroy(wdm_dev_class);
	unregister_chrdev_region(wdm_dev_base, WDM_HOST_MAX_DEVICES);

	pr_info("wdm_host: device subsystem exited\n");
}
