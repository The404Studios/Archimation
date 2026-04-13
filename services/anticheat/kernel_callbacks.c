/*
 * kernel_callbacks.c - Windows kernel callback emulation
 *
 * Anti-cheat kernel drivers register various Windows kernel callbacks
 * to monitor system activity. This module emulates those callback
 * mechanisms in userspace, maintaining callback lists and invoking
 * them at appropriate times.
 *
 * Emulated kernel callbacks:
 *   - PsSetCreateProcessNotifyRoutine    - process creation/termination
 *   - PsSetCreateThreadNotifyRoutine     - thread creation notifications
 *   - PsSetLoadImageNotifyRoutine        - module/image load notifications
 *   - ObRegisterCallbacks                - object access callbacks
 *   - CmRegisterCallback                 - registry access callbacks
 *
 * These are userspace implementations. Real kernel callbacks would require
 * a kernel module (see drivers/kernel/wdm_host.ko). This module provides
 * the callback infrastructure for userspace anti-cheat shims that need
 * to register for and receive these notifications.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>

#define KCB_LOG_PREFIX  "[anticheat/kcb] "
#define MAX_CALLBACKS   64
#define MAX_PATH_LEN    4096

/* NTSTATUS values */
#define STATUS_SUCCESS              0x00000000
#define STATUS_UNSUCCESSFUL         0xC0000001
#define STATUS_INSUFFICIENT_RESOURCES 0xC000009A
#define STATUS_INVALID_PARAMETER    0xC000000D

/* Callback types */
typedef enum {
    KCB_TYPE_PROCESS_NOTIFY     = 0,
    KCB_TYPE_THREAD_NOTIFY      = 1,
    KCB_TYPE_IMAGE_NOTIFY       = 2,
    KCB_TYPE_OB_CALLBACK        = 3,
    KCB_TYPE_REGISTRY_CALLBACK  = 4,
    KCB_TYPE_COUNT              = 5
} kcb_type_t;

/* Process notification info (matches PS_CREATE_NOTIFY_INFO subset) */
typedef struct {
    int     process_id;
    int     parent_process_id;
    char    image_name[MAX_PATH_LEN];
    int     is_create;      /* 1 = creation, 0 = termination */
} kcb_process_info_t;

/* Thread notification info */
typedef struct {
    int     process_id;
    int     thread_id;
    int     is_create;      /* 1 = creation, 0 = termination */
} kcb_thread_info_t;

/* Image load notification info (matches IMAGE_INFO subset) */
typedef struct {
    int     process_id;
    char    image_name[MAX_PATH_LEN];
    void   *image_base;
    size_t  image_size;
    int     system_mode_image;  /* 1 if loaded in kernel space */
} kcb_image_info_t;

/* Object callback info (matches OB_PRE_OPERATION_INFORMATION subset) */
typedef enum {
    OB_OPERATION_HANDLE_CREATE      = 1,
    OB_OPERATION_HANDLE_DUPLICATE   = 2
} ob_operation_t;

typedef struct {
    ob_operation_t  operation;
    int             process_id;       /* Target process */
    int             requesting_pid;   /* Process performing the operation */
    unsigned int    desired_access;
    unsigned int    granted_access;   /* Can be modified by callback */
} kcb_ob_info_t;

/* Registry callback info (matches REG_NOTIFY_CLASS subset) */
typedef enum {
    REG_NOTIFY_PRE_CREATE_KEY       = 0,
    REG_NOTIFY_PRE_OPEN_KEY         = 1,
    REG_NOTIFY_PRE_DELETE_KEY       = 2,
    REG_NOTIFY_PRE_SET_VALUE        = 3,
    REG_NOTIFY_PRE_DELETE_VALUE     = 4,
    REG_NOTIFY_PRE_QUERY_VALUE      = 5,
    REG_NOTIFY_POST_CREATE_KEY      = 10,
    REG_NOTIFY_POST_OPEN_KEY        = 11
} reg_notify_class_t;

typedef struct {
    reg_notify_class_t  notify_class;
    char                key_path[MAX_PATH_LEN];
    char                value_name[256];
    int                 process_id;
} kcb_registry_info_t;

/* Callback function pointer types */
typedef void (*process_notify_fn)(kcb_process_info_t *info);
typedef void (*thread_notify_fn)(kcb_thread_info_t *info);
typedef void (*image_notify_fn)(kcb_image_info_t *info);
typedef int  (*ob_callback_fn)(kcb_ob_info_t *info);       /* Returns status */
typedef int  (*registry_callback_fn)(kcb_registry_info_t *info); /* Returns status */

/* Generic callback entry */
typedef struct {
    kcb_type_t  type;
    void       *callback;       /* Function pointer (cast to appropriate type) */
    void       *context;        /* Opaque context passed to callback */
    int         active;         /* 1 if registered, 0 if removed */
    int         id;             /* Unique callback ID */
    char        owner[256];     /* Name of registering module */
} kcb_entry_t;

/* Callback manager state */
typedef struct {
    int             initialized;
    kcb_entry_t     callbacks[MAX_CALLBACKS];
    int             num_callbacks;
    int             next_id;
    pthread_mutex_t lock;

    /* Statistics */
    unsigned long   process_notifications;
    unsigned long   thread_notifications;
    unsigned long   image_notifications;
    unsigned long   ob_callbacks_invoked;
    unsigned long   registry_callbacks_invoked;
} kcb_state_t;

static kcb_state_t g_kcb = {0};

/* Forward declarations */
static int find_callback_by_id(int id);
static const char *kcb_type_name(kcb_type_t type);

/* --- Internal helpers --- */

static const char *kcb_type_name(kcb_type_t type)
{
    switch (type) {
    case KCB_TYPE_PROCESS_NOTIFY:   return "ProcessNotify";
    case KCB_TYPE_THREAD_NOTIFY:    return "ThreadNotify";
    case KCB_TYPE_IMAGE_NOTIFY:     return "ImageNotify";
    case KCB_TYPE_OB_CALLBACK:      return "ObCallback";
    case KCB_TYPE_REGISTRY_CALLBACK: return "RegistryCallback";
    default:                        return "Unknown";
    }
}

static int find_callback_by_id(int id)
{
    for (int i = 0; i < g_kcb.num_callbacks; i++) {
        if (g_kcb.callbacks[i].id == id && g_kcb.callbacks[i].active)
            return i;
    }
    return -1;
}

/*
 * Register a callback of a given type.
 * Returns a callback ID on success, or -1 on error.
 */
static int register_callback(kcb_type_t type, void *callback, void *context,
                               const char *owner)
{
    if (!g_kcb.initialized) {
        fprintf(stderr, KCB_LOG_PREFIX "register_callback: not initialized\n");
        return -1;
    }

    if (!callback) {
        fprintf(stderr, KCB_LOG_PREFIX "register_callback: null callback\n");
        return -1;
    }

    pthread_mutex_lock(&g_kcb.lock);

    if (g_kcb.num_callbacks >= MAX_CALLBACKS) {
        fprintf(stderr, KCB_LOG_PREFIX "register_callback: callback table full\n");
        pthread_mutex_unlock(&g_kcb.lock);
        return -1;
    }

    kcb_entry_t *entry = &g_kcb.callbacks[g_kcb.num_callbacks];
    entry->type = type;
    entry->callback = callback;
    entry->context = context;
    entry->active = 1;
    entry->id = g_kcb.next_id++;
    if (g_kcb.next_id < 0)
        g_kcb.next_id = 1;  /* Wrap around, skip 0 */

    if (owner)
        strncpy(entry->owner, owner, sizeof(entry->owner) - 1);
    else
        strncpy(entry->owner, "unknown", sizeof(entry->owner) - 1);

    g_kcb.num_callbacks++;

    fprintf(stderr, KCB_LOG_PREFIX "Registered %s callback #%d (owner: %s)\n",
            kcb_type_name(type), entry->id, entry->owner);

    pthread_mutex_unlock(&g_kcb.lock);
    return entry->id;
}

/*
 * Unregister a callback by ID.
 * Returns 0 on success, -1 if not found.
 */
static int unregister_callback(int id)
{
    pthread_mutex_lock(&g_kcb.lock);

    int idx = find_callback_by_id(id);
    if (idx < 0) {
        fprintf(stderr, KCB_LOG_PREFIX "unregister_callback: ID %d not found\n", id);
        pthread_mutex_unlock(&g_kcb.lock);
        return -1;
    }

    g_kcb.callbacks[idx].active = 0;
    fprintf(stderr, KCB_LOG_PREFIX "Unregistered %s callback #%d (owner: %s)\n",
            kcb_type_name(g_kcb.callbacks[idx].type),
            id, g_kcb.callbacks[idx].owner);

    pthread_mutex_unlock(&g_kcb.lock);
    return 0;
}

/* --- Public API --- */

/*
 * kernel_cb_init - Initialize the kernel callback emulation system
 *
 * Sets up the callback tables and synchronization primitives.
 * Must be called before registering any callbacks.
 *
 * Returns 0 on success.
 */
int kernel_cb_init(void)
{
    if (g_kcb.initialized) {
        fprintf(stderr, KCB_LOG_PREFIX "Already initialized\n");
        return 0;
    }

    fprintf(stderr, KCB_LOG_PREFIX "Initializing kernel callback emulation\n");

    memset(&g_kcb, 0, sizeof(g_kcb));
    pthread_mutex_init(&g_kcb.lock, NULL);
    g_kcb.next_id = 1;
    g_kcb.initialized = 1;

    fprintf(stderr, KCB_LOG_PREFIX "Kernel callback system ready "
            "(max %d callbacks)\n", MAX_CALLBACKS);

    return 0;
}

/*
 * kernel_cb_register_process_notify - Register a process creation/termination callback
 *
 * Emulates PsSetCreateProcessNotifyRoutine / PsSetCreateProcessNotifyRoutineEx.
 *
 * @callback: Function called on process create/terminate events
 * @context:  Opaque pointer passed to callback
 * @owner:    Name of the registering module (for logging)
 *
 * Returns callback ID on success, -1 on error.
 */
int kernel_cb_register_process_notify(process_notify_fn callback, void *context,
                                       const char *owner)
{
    fprintf(stderr, KCB_LOG_PREFIX "PsSetCreateProcessNotifyRoutine from %s\n",
            owner ? owner : "unknown");
    return register_callback(KCB_TYPE_PROCESS_NOTIFY, (void *)callback,
                              context, owner);
}

/*
 * kernel_cb_register_thread_notify - Register a thread creation callback
 *
 * Emulates PsSetCreateThreadNotifyRoutine.
 *
 * @callback: Function called on thread create/terminate events
 * @context:  Opaque pointer passed to callback
 * @owner:    Name of the registering module
 *
 * Returns callback ID on success, -1 on error.
 */
int kernel_cb_register_thread_notify(thread_notify_fn callback, void *context,
                                      const char *owner)
{
    fprintf(stderr, KCB_LOG_PREFIX "PsSetCreateThreadNotifyRoutine from %s\n",
            owner ? owner : "unknown");
    return register_callback(KCB_TYPE_THREAD_NOTIFY, (void *)callback,
                              context, owner);
}

/*
 * kernel_cb_register_image_notify - Register a module/image load callback
 *
 * Emulates PsSetLoadImageNotifyRoutine.
 *
 * @callback: Function called when an image (DLL/EXE) is loaded
 * @context:  Opaque pointer passed to callback
 * @owner:    Name of the registering module
 *
 * Returns callback ID on success, -1 on error.
 */
int kernel_cb_register_image_notify(image_notify_fn callback, void *context,
                                     const char *owner)
{
    fprintf(stderr, KCB_LOG_PREFIX "PsSetLoadImageNotifyRoutine from %s\n",
            owner ? owner : "unknown");
    return register_callback(KCB_TYPE_IMAGE_NOTIFY, (void *)callback,
                              context, owner);
}

/*
 * kernel_cb_register_ob_callback - Register an object access callback
 *
 * Emulates ObRegisterCallbacks. In Windows, this allows kernel drivers
 * to intercept handle creation/duplication for processes and threads.
 * Anti-cheat drivers use this to prevent other processes from opening
 * handles to the game process with debug or write access.
 *
 * @callback: Function called on handle operations
 * @context:  Opaque pointer passed to callback
 * @owner:    Name of the registering module
 *
 * Returns callback ID on success, -1 on error.
 */
int kernel_cb_register_ob_callback(ob_callback_fn callback, void *context,
                                    const char *owner)
{
    fprintf(stderr, KCB_LOG_PREFIX "ObRegisterCallbacks from %s\n",
            owner ? owner : "unknown");
    return register_callback(KCB_TYPE_OB_CALLBACK, (void *)callback,
                              context, owner);
}

/*
 * kernel_cb_register_registry_callback - Register a registry access callback
 *
 * Emulates CmRegisterCallback / CmRegisterCallbackEx.
 * Anti-cheat drivers monitor registry access to detect tampering with
 * their service configuration or to log suspicious access patterns.
 *
 * @callback: Function called on registry operations
 * @context:  Opaque pointer passed to callback
 * @owner:    Name of the registering module
 *
 * Returns callback ID on success, -1 on error.
 */
int kernel_cb_register_registry_callback(registry_callback_fn callback, void *context,
                                          const char *owner)
{
    fprintf(stderr, KCB_LOG_PREFIX "CmRegisterCallback from %s\n",
            owner ? owner : "unknown");
    return register_callback(KCB_TYPE_REGISTRY_CALLBACK, (void *)callback,
                              context, owner);
}

/*
 * kernel_cb_unregister - Unregister a previously registered callback
 *
 * @callback_id: ID returned from a register function
 *
 * Returns 0 on success, -1 if callback not found.
 */
int kernel_cb_unregister(int callback_id)
{
    fprintf(stderr, KCB_LOG_PREFIX "Unregistering callback #%d\n", callback_id);
    return unregister_callback(callback_id);
}

/*
 * kernel_cb_notify_process_create - Fire process creation/termination notifications
 *
 * Invokes all registered PsSetCreateProcessNotifyRoutine callbacks.
 *
 * @pid:         Process ID
 * @parent_pid:  Parent process ID
 * @image_name:  Process image name (e.g., "game.exe")
 * @is_create:   1 for creation, 0 for termination
 *
 * Returns the number of callbacks invoked.
 */
int kernel_cb_notify_process_create(int pid, int parent_pid,
                                     const char *image_name, int is_create)
{
    if (!g_kcb.initialized)
        return 0;

    kcb_process_info_t info;
    memset(&info, 0, sizeof(info));
    info.process_id = pid;
    info.parent_process_id = parent_pid;
    info.is_create = is_create;
    if (image_name)
        strncpy(info.image_name, image_name, sizeof(info.image_name) - 1);

    fprintf(stderr, KCB_LOG_PREFIX "Process %s: PID=%d, Parent=%d, Image=%s\n",
            is_create ? "CREATE" : "TERMINATE",
            pid, parent_pid, image_name ? image_name : "(null)");

    int count = 0;
    pthread_mutex_lock(&g_kcb.lock);

    for (int i = 0; i < g_kcb.num_callbacks; i++) {
        if (g_kcb.callbacks[i].type == KCB_TYPE_PROCESS_NOTIFY &&
            g_kcb.callbacks[i].active && g_kcb.callbacks[i].callback) {
            process_notify_fn fn = (process_notify_fn)g_kcb.callbacks[i].callback;
            fprintf(stderr, KCB_LOG_PREFIX "  Invoking callback #%d (owner: %s)\n",
                    g_kcb.callbacks[i].id, g_kcb.callbacks[i].owner);
            fn(&info);
            count++;
        }
    }

    g_kcb.process_notifications++;
    pthread_mutex_unlock(&g_kcb.lock);

    fprintf(stderr, KCB_LOG_PREFIX "  %d process callbacks invoked\n", count);
    return count;
}

/*
 * kernel_cb_notify_thread_create - Fire thread creation/termination notifications
 *
 * @pid:        Process ID owning the thread
 * @tid:        Thread ID
 * @is_create:  1 for creation, 0 for termination
 *
 * Returns the number of callbacks invoked.
 */
int kernel_cb_notify_thread_create(int pid, int tid, int is_create)
{
    if (!g_kcb.initialized)
        return 0;

    kcb_thread_info_t info;
    memset(&info, 0, sizeof(info));
    info.process_id = pid;
    info.thread_id = tid;
    info.is_create = is_create;

    fprintf(stderr, KCB_LOG_PREFIX "Thread %s: PID=%d, TID=%d\n",
            is_create ? "CREATE" : "TERMINATE", pid, tid);

    int count = 0;
    pthread_mutex_lock(&g_kcb.lock);

    for (int i = 0; i < g_kcb.num_callbacks; i++) {
        if (g_kcb.callbacks[i].type == KCB_TYPE_THREAD_NOTIFY &&
            g_kcb.callbacks[i].active && g_kcb.callbacks[i].callback) {
            thread_notify_fn fn = (thread_notify_fn)g_kcb.callbacks[i].callback;
            fn(&info);
            count++;
        }
    }

    g_kcb.thread_notifications++;
    pthread_mutex_unlock(&g_kcb.lock);

    return count;
}

/*
 * kernel_cb_notify_image_load - Fire image/module load notifications
 *
 * @pid:         Process ID loading the image
 * @image_name:  Image file name
 * @image_base:  Base address where image is loaded
 * @image_size:  Size of the loaded image
 * @system_mode: 1 if loaded in kernel space, 0 for userspace
 *
 * Returns the number of callbacks invoked.
 */
int kernel_cb_notify_image_load(int pid, const char *image_name,
                                 void *image_base, size_t image_size,
                                 int system_mode)
{
    if (!g_kcb.initialized)
        return 0;

    kcb_image_info_t info;
    memset(&info, 0, sizeof(info));
    info.process_id = pid;
    info.image_base = image_base;
    info.image_size = image_size;
    info.system_mode_image = system_mode;
    if (image_name)
        strncpy(info.image_name, image_name, sizeof(info.image_name) - 1);

    fprintf(stderr, KCB_LOG_PREFIX "Image LOAD: PID=%d, Image=%s, "
            "Base=%p, Size=0x%zx, Kernel=%d\n",
            pid, image_name ? image_name : "(null)",
            image_base, image_size, system_mode);

    int count = 0;
    pthread_mutex_lock(&g_kcb.lock);

    for (int i = 0; i < g_kcb.num_callbacks; i++) {
        if (g_kcb.callbacks[i].type == KCB_TYPE_IMAGE_NOTIFY &&
            g_kcb.callbacks[i].active && g_kcb.callbacks[i].callback) {
            image_notify_fn fn = (image_notify_fn)g_kcb.callbacks[i].callback;
            fn(&info);
            count++;
        }
    }

    g_kcb.image_notifications++;
    pthread_mutex_unlock(&g_kcb.lock);

    return count;
}

/*
 * kernel_cb_notify_ob_operation - Fire object access callbacks
 *
 * Invokes registered ObRegisterCallbacks handlers. Anti-cheat drivers
 * use these to strip PROCESS_VM_WRITE, PROCESS_VM_READ, and debug
 * access rights from handles opened to the game process.
 *
 * @operation:      OB_OPERATION_HANDLE_CREATE or _DUPLICATE
 * @target_pid:     PID of the target process
 * @requesting_pid: PID of the process opening the handle
 * @desired_access: Requested access mask
 * @granted_access: Pointer to granted access mask (may be modified by callbacks)
 *
 * Returns STATUS_SUCCESS or status from callback.
 */
int kernel_cb_notify_ob_operation(ob_operation_t operation, int target_pid,
                                   int requesting_pid, unsigned int desired_access,
                                   unsigned int *granted_access)
{
    if (!g_kcb.initialized)
        return STATUS_SUCCESS;

    kcb_ob_info_t info;
    memset(&info, 0, sizeof(info));
    info.operation = operation;
    info.process_id = target_pid;
    info.requesting_pid = requesting_pid;
    info.desired_access = desired_access;
    info.granted_access = granted_access ? *granted_access : desired_access;

    fprintf(stderr, KCB_LOG_PREFIX "ObCallback: op=%s, target=%d, requester=%d, "
            "access=0x%08X\n",
            operation == OB_OPERATION_HANDLE_CREATE ? "CREATE" : "DUPLICATE",
            target_pid, requesting_pid, desired_access);

    int status = STATUS_SUCCESS;
    pthread_mutex_lock(&g_kcb.lock);

    for (int i = 0; i < g_kcb.num_callbacks; i++) {
        if (g_kcb.callbacks[i].type == KCB_TYPE_OB_CALLBACK &&
            g_kcb.callbacks[i].active && g_kcb.callbacks[i].callback) {
            ob_callback_fn fn = (ob_callback_fn)g_kcb.callbacks[i].callback;
            int ret = fn(&info);
            if (ret != STATUS_SUCCESS) {
                fprintf(stderr, KCB_LOG_PREFIX "  ObCallback #%d returned status "
                        "0x%08X\n", g_kcb.callbacks[i].id, ret);
                status = ret;
            }
        }
    }

    /* Update granted access from callback modifications */
    if (granted_access)
        *granted_access = info.granted_access;

    g_kcb.ob_callbacks_invoked++;
    pthread_mutex_unlock(&g_kcb.lock);

    return status;
}

/*
 * kernel_cb_notify_registry - Fire registry access callbacks
 *
 * @notify_class: Type of registry operation
 * @key_path:     Registry key path
 * @value_name:   Value name (for value operations, NULL otherwise)
 * @pid:          Process performing the registry access
 *
 * Returns STATUS_SUCCESS to allow the operation, or an error status to block.
 */
int kernel_cb_notify_registry(reg_notify_class_t notify_class, const char *key_path,
                               const char *value_name, int pid)
{
    if (!g_kcb.initialized)
        return STATUS_SUCCESS;

    kcb_registry_info_t info;
    memset(&info, 0, sizeof(info));
    info.notify_class = notify_class;
    info.process_id = pid;
    if (key_path)
        strncpy(info.key_path, key_path, sizeof(info.key_path) - 1);
    if (value_name)
        strncpy(info.value_name, value_name, sizeof(info.value_name) - 1);

    fprintf(stderr, KCB_LOG_PREFIX "CmCallback: class=%d, key=%s, value=%s, pid=%d\n",
            notify_class, key_path ? key_path : "(null)",
            value_name ? value_name : "(null)", pid);

    int status = STATUS_SUCCESS;
    pthread_mutex_lock(&g_kcb.lock);

    for (int i = 0; i < g_kcb.num_callbacks; i++) {
        if (g_kcb.callbacks[i].type == KCB_TYPE_REGISTRY_CALLBACK &&
            g_kcb.callbacks[i].active && g_kcb.callbacks[i].callback) {
            registry_callback_fn fn = (registry_callback_fn)g_kcb.callbacks[i].callback;
            int ret = fn(&info);
            if (ret != STATUS_SUCCESS) {
                fprintf(stderr, KCB_LOG_PREFIX "  CmCallback #%d returned status "
                        "0x%08X\n", g_kcb.callbacks[i].id, ret);
                status = ret;
            }
        }
    }

    g_kcb.registry_callbacks_invoked++;
    pthread_mutex_unlock(&g_kcb.lock);

    return status;
}

/*
 * kernel_cb_cleanup - Clean up all registered callbacks and shutdown
 *
 * Unregisters all callbacks and releases resources.
 * Returns 0 on success.
 */
int kernel_cb_cleanup(void)
{
    if (!g_kcb.initialized) {
        fprintf(stderr, KCB_LOG_PREFIX "kernel_cb_cleanup: not initialized\n");
        return 0;
    }

    fprintf(stderr, KCB_LOG_PREFIX "Cleaning up kernel callback system\n");

    pthread_mutex_lock(&g_kcb.lock);

    /* Report statistics */
    fprintf(stderr, KCB_LOG_PREFIX "Statistics:\n");
    fprintf(stderr, KCB_LOG_PREFIX "  Process notifications:  %lu\n",
            g_kcb.process_notifications);
    fprintf(stderr, KCB_LOG_PREFIX "  Thread notifications:   %lu\n",
            g_kcb.thread_notifications);
    fprintf(stderr, KCB_LOG_PREFIX "  Image notifications:    %lu\n",
            g_kcb.image_notifications);
    fprintf(stderr, KCB_LOG_PREFIX "  Object callbacks:       %lu\n",
            g_kcb.ob_callbacks_invoked);
    fprintf(stderr, KCB_LOG_PREFIX "  Registry callbacks:     %lu\n",
            g_kcb.registry_callbacks_invoked);

    /* Deactivate all callbacks */
    int active_count = 0;
    for (int i = 0; i < g_kcb.num_callbacks; i++) {
        if (g_kcb.callbacks[i].active) {
            fprintf(stderr, KCB_LOG_PREFIX "  Removing %s callback #%d (owner: %s)\n",
                    kcb_type_name(g_kcb.callbacks[i].type),
                    g_kcb.callbacks[i].id,
                    g_kcb.callbacks[i].owner);
            g_kcb.callbacks[i].active = 0;
            active_count++;
        }
    }

    fprintf(stderr, KCB_LOG_PREFIX "Removed %d active callbacks\n", active_count);

    g_kcb.initialized = 0;
    pthread_mutex_unlock(&g_kcb.lock);
    pthread_mutex_destroy(&g_kcb.lock);

    fprintf(stderr, KCB_LOG_PREFIX "Kernel callback system shut down\n");
    return 0;
}
