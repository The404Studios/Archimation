/*
 * wdm_host_internal.h - Shared internal header for the wdm_host kernel module
 *
 * Defines all internal data structures, ioctl commands, and function
 * declarations shared between the wdm_host kernel module source files.
 * This module provides WDM (Windows Driver Model) emulation inside the
 * Linux kernel, allowing Windows .sys driver binaries to be loaded and
 * hosted as part of a driver compatibility layer.
 *
 * This header is NOT for userspace - it depends on Linux kernel headers.
 */

#ifndef WDM_HOST_INTERNAL_H
#define WDM_HOST_INTERNAL_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

/* ============================================================================
 * Limits
 * ============================================================================ */

#define WDM_HOST_MAX_DRIVERS    64      /* Maximum number of loaded drivers */
#define WDM_HOST_MAX_DEVICES    256     /* Maximum number of created devices */

/* ============================================================================
 * Driver state constants
 * ============================================================================ */

#define WDM_STATE_UNLOADED      0
#define WDM_STATE_LOADED        1
#define WDM_STATE_STARTED       2
#define WDM_STATE_ERROR         3

/* ============================================================================
 * IRP major function code count (matches IRP_MJ_MAXIMUM_FUNCTION + 1)
 * ============================================================================ */

#define WDM_IRP_MJ_COUNT        28      /* IRP_MJ_MAXIMUM_FUNCTION (0x1B) + 1 */

/* ============================================================================
 * struct wdm_driver - Represents a loaded Windows .sys driver
 *
 * Each loaded driver image is tracked by one of these structures.
 * The image is mapped into kernel virtual memory and its DriverEntry
 * function pointer is resolved from the PE headers.
 * ============================================================================ */

struct wdm_driver {
	char name[256];                         /* Driver display name */
	void *image_base;                       /* Mapped driver image in kernel memory */
	size_t image_size;                      /* Size of the mapped image in bytes */
	void *entry_point;                      /* DriverEntry function pointer */
	void *unload_func;                      /* DriverUnload function pointer */
	void *dispatch_table[WDM_IRP_MJ_COUNT]; /* MajorFunction dispatch table */
	void *device_extension;                 /* Driver-level extension memory */
	int state;                              /* WDM_STATE_* constants */
	struct list_head devices;               /* List of devices created by this driver */
	struct list_head list;                  /* Linkage in global wdm_driver_list */
};

/* ============================================================================
 * struct wdm_device - Represents a device created by a Windows driver
 *
 * Maps a Windows NT device object to a Linux character device so that
 * userspace processes can open and ioctl the emulated device.
 * ============================================================================ */

struct wdm_device {
	char device_name[256];                  /* NT device name (e.g. \Device\MyDevice) */
	char symlink_name[256];                 /* Symbolic link (e.g. \DosDevices\MyDevice) */
	struct wdm_driver *driver;              /* Owning driver */
	void *device_extension;                 /* Per-device extension memory */
	size_t extension_size;                  /* Size of device extension in bytes */
	uint32_t device_type;                   /* FILE_DEVICE_* type code */
	uint32_t flags;                         /* Device flags (DO_BUFFERED_IO, etc.) */
	struct list_head driver_list;           /* Linkage in driver's device list */
	struct list_head global_list;           /* Linkage in global wdm_device_list */
	dev_t devno;                            /* Linux device number */
	struct cdev cdev;                       /* Linux character device */
};

/* ============================================================================
 * struct wdm_irp - Simplified kernel-side IRP for dispatch
 *
 * This is a reduced representation of a Windows I/O Request Packet used
 * internally by the wdm_host module to marshal IRP data between the
 * Linux ioctl interface and the loaded Windows driver dispatch routines.
 * ============================================================================ */

struct wdm_irp {
	uint8_t major_function;                 /* IRP_MJ_* major function code */
	uint8_t minor_function;                 /* IRP_MN_* minor function code */
	void *system_buffer;                    /* Buffered I/O system buffer */
	size_t buffer_length;                   /* Length of system_buffer */
	uint32_t ioctl_code;                    /* DeviceIoControl control code */
	void *user_buffer;                      /* Direct I/O user buffer pointer */
	size_t output_length;                   /* Expected output buffer length */
	int32_t status;                         /* NTSTATUS result code */
	size_t information;                     /* Bytes transferred (IoStatus.Information) */
};

/* ============================================================================
 * IOCTL command definitions
 *
 * All control commands go through the /dev/wdm_host misc device.
 * Magic number 'W' (0x57) is used for the ioctl type field.
 * ============================================================================ */

#define WDM_IOCTL_MAGIC         'W'

#define WDM_IOCTL_LOAD_DRIVER   _IOW(WDM_IOCTL_MAGIC,  0x01, struct wdm_load_request)
#define WDM_IOCTL_UNLOAD_DRIVER _IOW(WDM_IOCTL_MAGIC,  0x02, char[256])
#define WDM_IOCTL_START_DRIVER  _IOW(WDM_IOCTL_MAGIC,  0x03, char[256])
#define WDM_IOCTL_LIST_DRIVERS  _IOR(WDM_IOCTL_MAGIC,  0x04, struct wdm_driver_info)
#define WDM_IOCTL_SEND_IRP      _IOWR(WDM_IOCTL_MAGIC, 0x05, struct wdm_irp_request)

/* ============================================================================
 * IOCTL request/response structures
 *
 * These structures define the userspace ABI for the /dev/wdm_host ioctls.
 * They are designed to be passed via copy_from_user / copy_to_user.
 * ============================================================================ */

/*
 * struct wdm_load_request - Passed with WDM_IOCTL_LOAD_DRIVER
 *
 * @path:  Filesystem path to the .sys driver binary
 * @name:  Human-readable name to register the driver under
 */
struct wdm_load_request {
	char path[4096];                        /* Path to the .sys file */
	char name[256];                         /* Driver name for registration */
};

/*
 * struct wdm_driver_info - Returned by WDM_IOCTL_LIST_DRIVERS
 *
 * @name:          Driver name
 * @state:         Current driver state (WDM_STATE_*)
 * @device_count:  Number of devices created by this driver
 */
struct wdm_driver_info {
	char name[256];                         /* Driver name */
	int state;                              /* WDM_STATE_* value */
	int device_count;                       /* Number of devices owned */
};

/*
 * struct wdm_irp_request - Passed with WDM_IOCTL_SEND_IRP
 *
 * @device_name:  Target NT device name (e.g. \Device\MyDevice)
 * @major:        IRP major function code
 * @ioctl_code:   DeviceIoControl code (for IRP_MJ_DEVICE_CONTROL)
 * @in_buf:       Userspace pointer to input data
 * @in_len:       Length of input data
 * @out_buf:      Userspace pointer to output buffer
 * @out_len:      Length of output buffer
 */
struct wdm_irp_request {
	char device_name[256];                  /* Target device NT name */
	uint8_t major;                          /* IRP major function code */
	uint32_t ioctl_code;                    /* IOCTL code for DeviceIoControl */
	void __user *in_buf;                    /* Userspace input buffer */
	size_t in_len;                          /* Input buffer length */
	void __user *out_buf;                   /* Userspace output buffer */
	size_t out_len;                         /* Output buffer length */
};

/* ============================================================================
 * Global variables (defined in wdm_host_main.c)
 * ============================================================================ */

extern struct list_head wdm_driver_list;    /* Global list of loaded drivers */
extern struct mutex wdm_driver_lock;        /* Protects wdm_driver_list */
extern struct list_head wdm_device_list;    /* Global list of created devices */
extern struct mutex wdm_device_lock;        /* Protects wdm_device_list */

/* ============================================================================
 * Subsystem function declarations
 *
 * Each subsystem (loader, irp, device, dma, pnp, registry) provides init
 * and exit functions called during module load/unload, plus operational
 * functions called at runtime.
 * ============================================================================ */

/* --- wdm_host_loader.c: Driver image loading and unloading --- */
int  wdm_host_loader_init(void);
void wdm_host_loader_exit(void);
int  wdm_load_driver(const char *path, const char *name);
int  wdm_unload_driver(const char *name);

/* --- wdm_host_irp.c: IRP construction and dispatch --- */
int  wdm_irp_init(void);
void wdm_irp_exit(void);
int  wdm_dispatch_irp(struct wdm_device *dev, struct wdm_irp *irp);

/* --- wdm_host_device.c: Device creation and lookup --- */
int  wdm_device_init(void);
void wdm_device_exit(void);
int  wdm_create_device(struct wdm_driver *drv, const char *name,
			const char *symlink, uint32_t type,
			size_t ext_size, uint32_t flags);
void wdm_delete_device(struct wdm_device *dev);
struct wdm_device *wdm_find_device(const char *name);

/* --- wdm_host_dma.c: DMA buffer management --- */
int  wdm_dma_init(void);
void wdm_dma_exit(void);
void *wdm_dma_alloc(size_t size, dma_addr_t *dma_handle);
void wdm_dma_free(size_t size, void *vaddr, dma_addr_t dma_handle);

/* --- wdm_host_pnp.c: Plug and Play manager emulation --- */
int  wdm_pnp_init(void);
void wdm_pnp_exit(void);
int  wdm_pnp_start_device(struct wdm_device *dev);
int  wdm_pnp_remove_device(struct wdm_device *dev);

/* --- wdm_host_thunk.c: Windows x64 ABI calling convention bridge --- */
int  wdm_thunk_init(void);
void wdm_thunk_exit(void);
int  wdm_thunk_dispatch(struct wdm_device *dev, struct wdm_irp *irp);

/* --- wdm_host_registry.c: Windows registry emulation --- */
int  wdm_registry_init(void);
void wdm_registry_exit(void);
int  wdm_registry_query(const char *key, const char *value_name,
			 void *data, size_t *data_len);
int  wdm_registry_set(const char *key, const char *value_name,
		       const void *data, size_t data_len);

#endif /* WDM_HOST_INTERNAL_H */
