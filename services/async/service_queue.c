/*
 * service_queue.c - Asynchronous service start/stop queue
 *
 * Provides a thread-safe queue for service operations so that the
 * SCM daemon can accept commands without blocking on slow service starts.
 * Each queued operation runs on a worker thread.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define MAX_QUEUE_SIZE 256

typedef enum {
    SVC_OP_START,
    SVC_OP_STOP,
    SVC_OP_RESTART
} svc_op_type_t;

typedef struct {
    svc_op_type_t type;
    char          service_name[256];
    void          (*callback)(const char *name, int result, void *ctx);
    void          *callback_ctx;
} svc_op_t;

static svc_op_t        g_queue[MAX_QUEUE_SIZE];
static int             g_queue_head = 0;
static int             g_queue_tail = 0;
static int             g_queue_count = 0;
static pthread_mutex_t g_queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_queue_cond = PTHREAD_COND_INITIALIZER;
static pthread_t       g_worker_thread;
static volatile int    g_worker_running = 0;

/* External SCM functions and lock */
extern int scm_start_service(const char *name);
extern int scm_stop_service(const char *name);
extern pthread_mutex_t g_lock;

static void *worker_func(void *arg)
{
    (void)arg;

    while (g_worker_running) {
        svc_op_t op;
        int have_op = 0;

        pthread_mutex_lock(&g_queue_lock);
        while (g_queue_count == 0 && g_worker_running) {
            pthread_cond_wait(&g_queue_cond, &g_queue_lock);
        }

        if (g_queue_count > 0) {
            op = g_queue[g_queue_head];
            g_queue_head = (g_queue_head + 1) % MAX_QUEUE_SIZE;
            g_queue_count--;
            have_op = 1;
        }
        pthread_mutex_unlock(&g_queue_lock);

        if (!have_op)
            continue;

        /* Execute the operation (must hold g_lock for SCM functions) */
        int result = -1;
        switch (op.type) {
        case SVC_OP_START:
            fprintf(stderr, "[svc_queue] Starting: %s\n", op.service_name);
            pthread_mutex_lock(&g_lock);
            result = scm_start_service(op.service_name);
            pthread_mutex_unlock(&g_lock);
            break;
        case SVC_OP_STOP:
            fprintf(stderr, "[svc_queue] Stopping: %s\n", op.service_name);
            pthread_mutex_lock(&g_lock);
            result = scm_stop_service(op.service_name);
            pthread_mutex_unlock(&g_lock);
            break;
        case SVC_OP_RESTART:
            fprintf(stderr, "[svc_queue] Restarting: %s\n", op.service_name);
            pthread_mutex_lock(&g_lock);
            scm_stop_service(op.service_name);
            pthread_mutex_unlock(&g_lock);
            usleep(500000); /* 500ms grace period */
            pthread_mutex_lock(&g_lock);
            result = scm_start_service(op.service_name);
            pthread_mutex_unlock(&g_lock);
            break;
        }

        if (op.callback)
            op.callback(op.service_name, result, op.callback_ctx);
    }

    return NULL;
}

int svc_queue_init(void)
{
    g_worker_running = 1;
    g_queue_head = 0;
    g_queue_tail = 0;
    g_queue_count = 0;

    if (pthread_create(&g_worker_thread, NULL, worker_func, NULL) != 0) {
        fprintf(stderr, "[svc_queue] Failed to create worker thread\n");
        g_worker_running = 0;
        return -1;
    }

    fprintf(stderr, "[svc_queue] Async service queue initialized\n");
    return 0;
}

void svc_queue_shutdown(void)
{
    pthread_mutex_lock(&g_queue_lock);
    g_worker_running = 0;
    pthread_cond_broadcast(&g_queue_cond);
    pthread_mutex_unlock(&g_queue_lock);
    pthread_join(g_worker_thread, NULL);
    fprintf(stderr, "[svc_queue] Async service queue shut down\n");
}

int svc_queue_enqueue(svc_op_type_t type, const char *name,
                      void (*callback)(const char *, int, void *), void *ctx)
{
    pthread_mutex_lock(&g_queue_lock);

    if (g_queue_count >= MAX_QUEUE_SIZE) {
        pthread_mutex_unlock(&g_queue_lock);
        fprintf(stderr, "[svc_queue] Queue full, rejecting: %s\n", name);
        return -1;
    }

    svc_op_t *op = &g_queue[g_queue_tail];
    op->type = type;
    strncpy(op->service_name, name, sizeof(op->service_name) - 1);
    op->service_name[sizeof(op->service_name) - 1] = '\0';
    op->callback = callback;
    op->callback_ctx = ctx;

    g_queue_tail = (g_queue_tail + 1) % MAX_QUEUE_SIZE;
    g_queue_count++;

    pthread_cond_signal(&g_queue_cond);
    pthread_mutex_unlock(&g_queue_lock);

    return 0;
}

int svc_queue_pending(void)
{
    pthread_mutex_lock(&g_queue_lock);
    int count = g_queue_count;
    pthread_mutex_unlock(&g_queue_lock);
    return count;
}
