/*
 * kernel32_pipe.c - Named pipe implementation
 *
 * Maps Windows named pipes to Unix domain sockets.
 * Pipe names like \\.\pipe\MyPipe are mapped to
 * /tmp/pe-compat/pipes/MyPipe (Unix domain sockets).
 *
 * Implements: CreateNamedPipeA/W, ConnectNamedPipe, DisconnectNamedPipe,
 *             CreatePipe (anonymous pipes), PeekNamedPipe, SetNamedPipeHandleState,
 *             GetNamedPipeInfo, TransactNamedPipe, WaitNamedPipeA.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>

#include "common/dll_common.h"

/* Named pipe open mode flags */
#define PIPE_ACCESS_INBOUND     0x00000001
#define PIPE_ACCESS_OUTBOUND    0x00000002
#define PIPE_ACCESS_DUPLEX      0x00000003

/* Named pipe type flags */
#define PIPE_TYPE_BYTE          0x00000000
#define PIPE_TYPE_MESSAGE       0x00000004
#define PIPE_READMODE_BYTE      0x00000000
#define PIPE_READMODE_MESSAGE   0x00000002
#define PIPE_WAIT               0x00000000
#define PIPE_NOWAIT             0x00000001

/* Named pipe constants */
#define PIPE_UNLIMITED_INSTANCES 255
#define NMPWAIT_USE_DEFAULT_WAIT 0x00000000
#define NMPWAIT_WAIT_FOREVER     0xFFFFFFFF

/* Pipe directory */
#define PIPE_DIR "/tmp/pe-compat/pipes"

/* Internal pipe data stored in handle */
typedef struct {
    int  server_fd;     /* Listening socket (server side) */
    int  client_fd;     /* Connected client socket */
    int  is_server;     /* 1 if this is the server end */
    int  connected;     /* 1 if a client is connected */
    int  mode;          /* PIPE_TYPE_* flags */
    char name[256];     /* Pipe name */
    char socket_path[512]; /* Unix socket path */
} pipe_data_t;

/* Ensure the pipe directory exists */
static void ensure_pipe_dir(void)
{
    mkdir("/tmp/pe-compat", 0777);
    mkdir(PIPE_DIR, 0777);
}

/*
 * Convert a Windows pipe name (\\.\pipe\Name) to a Unix socket path.
 * Returns 0 on success, -1 if the name is not a valid pipe name.
 */
static int pipe_name_to_socket_path(const char *name, char *path, size_t path_size)
{
    /* Skip \\.\pipe\ prefix */
    const char *p = name;

    /* Handle various prefix forms: \\.\pipe\, \\.\PIPE\, //./pipe/ */
    if ((p[0] == '\\' || p[0] == '/') &&
        (p[1] == '\\' || p[1] == '/') &&
        p[2] == '.' &&
        (p[3] == '\\' || p[3] == '/')) {
        p += 4;
        /* Skip "pipe\" or "pipe/" */
        if (strncasecmp(p, "pipe", 4) == 0 && (p[4] == '\\' || p[4] == '/')) {
            p += 5;
        } else {
            return -1;
        }
    } else {
        /* Not a named pipe path - just use the name directly */
        p = name;
    }

    if (!*p) return -1;

    snprintf(path, path_size, "%s/%s", PIPE_DIR, p);

    /* Validate that the resulting path fits in sockaddr_un.sun_path (108 bytes).
     * If it doesn't, bind() would silently truncate and cause hard-to-debug
     * failures or connect to the wrong socket. */
    if (strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        fprintf(stderr, "[kernel32] Named pipe path too long (%zu >= %zu): %s\n",
                strlen(path), sizeof(((struct sockaddr_un *)0)->sun_path), path);
        return -1;
    }

    return 0;
}

/* ----------------------------------------------------------------
 * CreateNamedPipeA / CreateNamedPipeW
 * ---------------------------------------------------------------- */

WINAPI_EXPORT HANDLE CreateNamedPipeA(
    LPCSTR lpName,
    DWORD dwOpenMode,
    DWORD dwPipeMode,
    DWORD nMaxInstances,
    DWORD nOutBufferSize,
    DWORD nInBufferSize,
    DWORD nDefaultTimeOut,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    (void)nMaxInstances;
    (void)nOutBufferSize;
    (void)nInBufferSize;
    (void)nDefaultTimeOut;
    (void)lpSecurityAttributes;

    if (!lpName) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    ensure_pipe_dir();

    pipe_data_t *pd = calloc(1, sizeof(pipe_data_t));
    if (!pd) {
        set_last_error(ERROR_OUTOFMEMORY);
        return INVALID_HANDLE_VALUE;
    }

    pd->is_server = 1;
    pd->mode = dwPipeMode;
    pd->server_fd = -1;
    pd->client_fd = -1;
    strncpy(pd->name, lpName, sizeof(pd->name) - 1);

    if (pipe_name_to_socket_path(lpName, pd->socket_path, sizeof(pd->socket_path)) < 0) {
        free(pd);
        set_last_error(ERROR_INVALID_NAME);
        return INVALID_HANDLE_VALUE;
    }

    /* Create Unix domain socket */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        free(pd);
        set_last_error(errno_to_win32_error(errno));
        return INVALID_HANDLE_VALUE;
    }

    /* Remove old socket file if it exists */
    unlink(pd->socket_path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, pd->socket_path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        free(pd);
        set_last_error(errno_to_win32_error(errno));
        return INVALID_HANDLE_VALUE;
    }

    if (listen(fd, 1) < 0) {
        close(fd);
        unlink(pd->socket_path);
        free(pd);
        set_last_error(errno_to_win32_error(errno));
        return INVALID_HANDLE_VALUE;
    }

    /* Set non-blocking if PIPE_NOWAIT */
    if (dwPipeMode & PIPE_NOWAIT) {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    pd->server_fd = fd;
    (void)dwOpenMode;

    HANDLE h = handle_alloc(HANDLE_TYPE_PIPE, fd, pd);
    if (!h || h == INVALID_HANDLE_VALUE) {
        close(fd);
        unlink(pd->socket_path);
        free(pd);
        set_last_error(ERROR_OUTOFMEMORY);
        return INVALID_HANDLE_VALUE;
    }

    return h;
}

WINAPI_EXPORT HANDLE CreateNamedPipeW(
    LPCWSTR lpName,
    DWORD dwOpenMode,
    DWORD dwPipeMode,
    DWORD nMaxInstances,
    DWORD nOutBufferSize,
    DWORD nInBufferSize,
    DWORD nDefaultTimeOut,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    /* Convert wide to narrow */
    char name_a[512] = {0};
    if (lpName) {
        for (int i = 0; i < 511 && lpName[i]; i++)
            name_a[i] = (char)(lpName[i] & 0x7F);
    }
    return CreateNamedPipeA(name_a, dwOpenMode, dwPipeMode, nMaxInstances,
                            nOutBufferSize, nInBufferSize, nDefaultTimeOut,
                            lpSecurityAttributes);
}

/* ----------------------------------------------------------------
 * ConnectNamedPipe - wait for a client to connect
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped)
{
    (void)lpOverlapped;

    handle_entry_t *he = handle_lookup(hNamedPipe);
    if (!he || he->type != HANDLE_TYPE_PIPE || !he->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    pipe_data_t *pd = (pipe_data_t *)he->data;
    if (!pd->is_server || pd->server_fd < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (pd->connected) {
        set_last_error(ERROR_PIPE_CONNECTED);
        return FALSE;
    }

    /* Accept incoming connection */
    int client_fd = accept(pd->server_fd, NULL, NULL);
    if (client_fd < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    pd->client_fd = client_fd;
    pd->connected = 1;

    /* Update handle to use client fd for I/O */
    he->fd = client_fd;

    return TRUE;
}

/* ----------------------------------------------------------------
 * DisconnectNamedPipe
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL DisconnectNamedPipe(HANDLE hNamedPipe)
{
    handle_entry_t *he = handle_lookup(hNamedPipe);
    if (!he || he->type != HANDLE_TYPE_PIPE || !he->data) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    pipe_data_t *pd = (pipe_data_t *)he->data;

    if (pd->client_fd >= 0) {
        close(pd->client_fd);
        pd->client_fd = -1;
    }
    pd->connected = 0;

    /* Restore handle fd to server socket */
    he->fd = pd->server_fd;

    return TRUE;
}

/* ----------------------------------------------------------------
 * CreatePipe - anonymous pipe (uses Linux pipe())
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL CreatePipe(
    HANDLE *hReadPipe,
    HANDLE *hWritePipe,
    LPSECURITY_ATTRIBUTES lpPipeAttributes,
    DWORD nSize)
{
    (void)lpPipeAttributes;
    (void)nSize;

    if (!hReadPipe || !hWritePipe) {
        set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    *hReadPipe = handle_alloc(HANDLE_TYPE_PIPE, pipefd[0], NULL);
    if (!*hReadPipe || *hReadPipe == INVALID_HANDLE_VALUE) {
        close(pipefd[0]);
        close(pipefd[1]);
        *hReadPipe = NULL;
        *hWritePipe = NULL;
        set_last_error(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    *hWritePipe = handle_alloc(HANDLE_TYPE_PIPE, pipefd[1], NULL);
    if (!*hWritePipe || *hWritePipe == INVALID_HANDLE_VALUE) {
        handle_close(*hReadPipe);   /* releases pipefd[0] via handle table */
        close(pipefd[1]);
        *hReadPipe = NULL;
        *hWritePipe = NULL;
        set_last_error(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    return TRUE;
}

/* ----------------------------------------------------------------
 * PeekNamedPipe
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL PeekNamedPipe(
    HANDLE hNamedPipe,
    LPVOID lpBuffer,
    DWORD nBufferSize,
    LPDWORD lpBytesRead,
    LPDWORD lpTotalBytesAvail,
    LPDWORD lpBytesLeftThisMessage)
{
    int fd = handle_get_fd(hNamedPipe);
    if (fd < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* Use poll to check for available data */
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, 0);
    if (ret < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    if (ret == 0 || !(pfd.revents & POLLIN)) {
        /* No data available */
        if (lpBytesRead) *lpBytesRead = 0;
        if (lpTotalBytesAvail) *lpTotalBytesAvail = 0;
        if (lpBytesLeftThisMessage) *lpBytesLeftThisMessage = 0;
        return TRUE;
    }

    /* Data available - peek at it with MSG_PEEK */
    if (lpBuffer && nBufferSize > 0) {
        ssize_t n = recv(fd, lpBuffer, nBufferSize, MSG_PEEK);
        if (n < 0) n = 0;
        if (lpBytesRead) *lpBytesRead = (DWORD)n;
        if (lpTotalBytesAvail) *lpTotalBytesAvail = (DWORD)n;
    } else {
        if (lpBytesRead) *lpBytesRead = 0;
        if (lpTotalBytesAvail) *lpTotalBytesAvail = 1; /* At least some data */
    }

    if (lpBytesLeftThisMessage) *lpBytesLeftThisMessage = 0;

    return TRUE;
}

/* ----------------------------------------------------------------
 * SetNamedPipeHandleState / GetNamedPipeInfo
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL SetNamedPipeHandleState(
    HANDLE hNamedPipe,
    LPDWORD lpMode,
    LPDWORD lpMaxCollectionCount,
    LPDWORD lpCollectDataTimeout)
{
    (void)hNamedPipe;
    (void)lpMode;
    (void)lpMaxCollectionCount;
    (void)lpCollectDataTimeout;
    return TRUE;
}

WINAPI_EXPORT BOOL GetNamedPipeInfo(
    HANDLE hNamedPipe,
    LPDWORD lpFlags,
    LPDWORD lpOutBufferSize,
    LPDWORD lpInBufferSize,
    LPDWORD lpMaxInstances)
{
    (void)hNamedPipe;
    if (lpFlags) *lpFlags = PIPE_TYPE_BYTE;
    if (lpOutBufferSize) *lpOutBufferSize = 4096;
    if (lpInBufferSize) *lpInBufferSize = 4096;
    if (lpMaxInstances) *lpMaxInstances = 1;
    return TRUE;
}

/* ----------------------------------------------------------------
 * WaitNamedPipeA / TransactNamedPipe stubs
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL WaitNamedPipeA(LPCSTR lpNamedPipeName, DWORD nTimeOut)
{
    (void)nTimeOut;

    /* Check if the pipe exists */
    char socket_path[512];
    if (pipe_name_to_socket_path(lpNamedPipeName, socket_path, sizeof(socket_path)) < 0) {
        set_last_error(ERROR_INVALID_NAME);
        return FALSE;
    }

    struct stat st;
    if (stat(socket_path, &st) == 0)
        return TRUE;

    set_last_error(ERROR_FILE_NOT_FOUND);
    return FALSE;
}

WINAPI_EXPORT BOOL WaitNamedPipeW(LPCWSTR lpNamedPipeName, DWORD nTimeOut)
{
    char name_a[512] = {0};
    if (lpNamedPipeName) {
        for (int i = 0; i < 511 && lpNamedPipeName[i]; i++)
            name_a[i] = (char)(lpNamedPipeName[i] & 0x7F);
    }
    return WaitNamedPipeA(name_a, nTimeOut);
}

WINAPI_EXPORT BOOL TransactNamedPipe(
    HANDLE hNamedPipe,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesRead,
    LPOVERLAPPED lpOverlapped)
{
    (void)lpOverlapped;

    int fd = handle_get_fd(hNamedPipe);
    if (fd < 0) {
        set_last_error(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* Write request */
    if (lpInBuffer && nInBufferSize > 0)
        if (write(fd, lpInBuffer, nInBufferSize) < 0) { /* ignore */ }

    /* Read response */
    if (lpOutBuffer && nOutBufferSize > 0) {
        ssize_t n = read(fd, lpOutBuffer, nOutBufferSize);
        if (n < 0) {
            set_last_error(errno_to_win32_error(errno));
            return FALSE;
        }
        if (lpBytesRead) *lpBytesRead = (DWORD)n;
    }

    return TRUE;
}

/* ----------------------------------------------------------------
 * CallNamedPipeA - convenience function (open, transact, close)
 * ---------------------------------------------------------------- */

WINAPI_EXPORT BOOL CallNamedPipeA(
    LPCSTR lpNamedPipeName,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesRead,
    DWORD nTimeOut)
{
    (void)nTimeOut;

    char socket_path[512];
    if (pipe_name_to_socket_path(lpNamedPipeName, socket_path, sizeof(socket_path)) < 0) {
        set_last_error(ERROR_INVALID_NAME);
        return FALSE;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        set_last_error(errno_to_win32_error(errno));
        return FALSE;
    }

    /* Write request */
    if (lpInBuffer && nInBufferSize > 0)
        if (write(fd, lpInBuffer, nInBufferSize) < 0) { /* ignore */ }

    /* Read response */
    if (lpOutBuffer && nOutBufferSize > 0) {
        ssize_t n = read(fd, lpOutBuffer, nOutBufferSize);
        if (n < 0) {
            close(fd);
            set_last_error(errno_to_win32_error(errno));
            return FALSE;
        }
        if (lpBytesRead) *lpBytesRead = (DWORD)n;
    }

    close(fd);
    return TRUE;
}
