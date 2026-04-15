/*
 * ws2_32_socket.c - Winsock2 networking API stubs
 *
 * Maps Windows socket API to POSIX sockets.
 * WSAStartup, socket, connect, send, recv, bind, listen, accept,
 * select, closesocket, getaddrinfo, gethostbyname, etc.
 */

/* Needed for gethostbyname_r / gethostbyaddr_r on glibc (GNU-specific). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <stdatomic.h>
#include <pthread.h>

#include "common/dll_common.h"
#include "compat/trust_gate.h"

/* Winsock error codes (WSA namespace; distinct from Win32 GetLastError() on
 * real Windows, although values happen to be offset by 10000 from classic
 * POSIX-ish errnos). All socket-api errors MUST land here via
 * WSASetLastError() / ws2_map_errno_to_wsa(), never via kernel32!SetLastError.
 */
#define WSABASEERR          10000
#define WSAEINTR            10004
#define WSAEBADF            10009
#define WSAEACCES           10013
#define WSAEFAULT           10014
#define WSAEINVAL           10022
#define WSAEMFILE           10024
#define WSAEWOULDBLOCK      10035
#define WSAEINPROGRESS      10036
#define WSAEALREADY         10037
#define WSAENOTSOCK         10038
#define WSAEDESTADDRREQ     10039
#define WSAEMSGSIZE         10040
#define WSAEPROTOTYPE       10041
#define WSAENOPROTOOPT      10042
#define WSAEPROTONOSUPPORT  10043
#define WSAESOCKTNOSUPPORT  10044
#define WSAEOPNOTSUPP       10045
#define WSAEPFNOSUPPORT     10046
#define WSAEAFNOSUPPORT     10047
#define WSAEADDRINUSE       10048
#define WSAEADDRNOTAVAIL    10049
#define WSAENETDOWN         10050
#define WSAENETUNREACH      10051
#define WSAENETRESET        10052
#define WSAECONNABORTED     10053
#define WSAECONNRESET       10054
#define WSAENOBUFS          10055
#define WSAEISCONN          10056
#define WSAENOTCONN         10057
#define WSAESHUTDOWN        10058
#define WSAETOOMANYREFS     10059
#define WSAETIMEDOUT        10060
#define WSAECONNREFUSED     10061
#define WSAELOOP            10062
#define WSAENAMETOOLONG     10063
#define WSAEHOSTDOWN        10064
#define WSAEHOSTUNREACH     10065
#define WSAENOTEMPTY        10066
#define WSAEPROCLIM         10067
#define WSAEUSERS           10068
#define WSAEDQUOT           10069
#define WSAESTALE           10070
#define WSAEREMOTE          10071
#define WSAEDISCON          10101
#define WSANOTINITIALISED   10093
#define WSAHOST_NOT_FOUND   11001
#define WSATRY_AGAIN        11002
#define WSANO_DATA          11004

/* Windows socket types match POSIX on Linux */
#define SOCK_STREAM_WIN 1
#define SOCK_DGRAM_WIN  2
#define SOCK_RAW_WIN    3

/* WSADATA structure */
typedef struct {
    WORD    wVersion;
    WORD    wHighVersion;
    char    szDescription[257];
    char    szSystemStatus[129];
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char   *lpVendorInfo;
} WSADATA;

/* Windows SOCKET is UINT_PTR */
typedef UINT_PTR SOCKET_WIN;
#define INVALID_SOCKET_WIN ((SOCKET_WIN)(~0))
#define SOCKET_ERROR_WIN   (-1)

/* Per-thread Winsock error */
static __thread int wsa_last_error = 0;
static atomic_int wsa_init_refcount = 0;
static pthread_mutex_t wsa_init_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Thread-safe check: returns 1 if WSAStartup has been called.
 * Use relaxed memory order — wsa_init_refcount is a monotonic counter
 * and every subsequent socket-op syscall establishes its own ordering,
 * so we don't need seq_cst just to probe "any startup yet?". This shaves
 * a memory-fence off every socket call on weakly-ordered platforms
 * (irrelevant for x86 but matters on future ARM64 ports). */
static inline int wsa_is_initialized(void)
{
    return atomic_load_explicit(&wsa_init_refcount, memory_order_relaxed) > 0;
}

/* Map POSIX getaddrinfo/getnameinfo error codes to WSA error codes */
static int eai_to_wsa(int eai_err)
{
    switch (eai_err) {
    case 0:            return 0;
    case EAI_NONAME:   return WSAHOST_NOT_FOUND;
    case EAI_AGAIN:    return WSATRY_AGAIN;
    case EAI_FAIL:     return WSANO_DATA;
    case EAI_MEMORY:   return WSAENOBUFS;
    case EAI_FAMILY:   return WSAEAFNOSUPPORT;
    case EAI_SOCKTYPE: return WSAESOCKTNOSUPPORT;
    case EAI_SERVICE:  return WSAEINVAL;
#ifdef EAI_NODATA
    case EAI_NODATA:   return WSANO_DATA;
#endif
    default:           return WSAHOST_NOT_FOUND;
    }
}

/*
 * Translate a Linux errno value into a Winsock WSA error code.
 *
 * Every ws2_32 wrapper that forwards to a libc socket primitive MUST call
 * this after a failed call and store the result via WSASetLastError()
 * (or directly into the thread-local wsa_last_error). Windows socket code
 * expects to read raw WSA values (e.g. 10061 WSAECONNREFUSED) from
 * WSAGetLastError(), NOT the Linux ECONNREFUSED (111).
 *
 * Public symbol (exported for sibling ws2_32 TUs if they get added later);
 * the short alias errno_to_wsa() is retained for call-site brevity.
 */
int ws2_map_errno_to_wsa(int err)
{
    switch (err) {
    case 0:             return 0;
    /* --- Permission / handle --- */
    case EACCES:        return WSAEACCES;
    case EPERM:         return WSAEACCES;
    case EBADF:         return WSAEBADF;
    case EFAULT:        return WSAEFAULT;
    case EINVAL:        return WSAEINVAL;
    case EMFILE:        return WSAEMFILE;
    case ENFILE:        return WSAEMFILE;
    case EINTR:         return WSAEINTR;
    /* --- Non-blocking / async --- */
    case EAGAIN:        return WSAEWOULDBLOCK;
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:   return WSAEWOULDBLOCK;
#endif
    case EINPROGRESS:   return WSAEINPROGRESS;
    case EALREADY:      return WSAEALREADY;
    /* --- Address / socket identity --- */
    case ENOTSOCK:      return WSAENOTSOCK;
    case EDESTADDRREQ:  return WSAEDESTADDRREQ;
    case EMSGSIZE:      return WSAEMSGSIZE;
    case EPROTOTYPE:    return WSAEPROTOTYPE;
    case ENOPROTOOPT:   return WSAENOPROTOOPT;
    case EPROTONOSUPPORT: return WSAEPROTONOSUPPORT;
#ifdef ESOCKTNOSUPPORT
    case ESOCKTNOSUPPORT: return WSAESOCKTNOSUPPORT;
#endif
    case EOPNOTSUPP:    return WSAEOPNOTSUPP;
#if defined(ENOTSUP) && ENOTSUP != EOPNOTSUPP
    case ENOTSUP:       return WSAEOPNOTSUPP;
#endif
#ifdef EPFNOSUPPORT
    case EPFNOSUPPORT:  return WSAEPFNOSUPPORT;
#endif
    case EAFNOSUPPORT:  return WSAEAFNOSUPPORT;
    case EADDRINUSE:    return WSAEADDRINUSE;
    case EADDRNOTAVAIL: return WSAEADDRNOTAVAIL;
    /* --- Network state --- */
    case ENETDOWN:      return WSAENETDOWN;
    case ENETUNREACH:   return WSAENETUNREACH;
    case ENETRESET:     return WSAENETRESET;
    case ECONNABORTED:  return WSAECONNABORTED;
    case ECONNRESET:    return WSAECONNRESET;
    case ENOBUFS:       return WSAENOBUFS;
    case ENOMEM:        return WSAENOBUFS;
    case EISCONN:       return WSAEISCONN;
    case ENOTCONN:      return WSAENOTCONN;
#ifdef ESHUTDOWN
    case ESHUTDOWN:     return WSAESHUTDOWN;
#endif
    case EPIPE:         return WSAESHUTDOWN;
#ifdef ETOOMANYREFS
    case ETOOMANYREFS:  return WSAETOOMANYREFS;
#endif
    case ETIMEDOUT:     return WSAETIMEDOUT;
    case ECONNREFUSED:  return WSAECONNREFUSED;
    case ELOOP:         return WSAELOOP;
    case ENAMETOOLONG:  return WSAENAMETOOLONG;
#ifdef EHOSTDOWN
    case EHOSTDOWN:     return WSAEHOSTDOWN;
#endif
    case EHOSTUNREACH:  return WSAEHOSTUNREACH;
    case ENOTEMPTY:     return WSAENOTEMPTY;
#ifdef EUSERS
    case EUSERS:        return WSAEUSERS;
#endif
#ifdef EDQUOT
    case EDQUOT:        return WSAEDQUOT;
#endif
#ifdef ESTALE
    case ESTALE:        return WSAESTALE;
#endif
#ifdef EREMOTE
    case EREMOTE:       return WSAEREMOTE;
#endif
    default:
        /* Unknown error — return a stable opaque value. Do NOT silently
         * claim WSAENOTSOCK as before (that masked real bugs). */
        return WSAEFAULT;
    }
}

/* Short internal alias — kept for readability at existing call sites. */
static inline int errno_to_wsa(int err)
{
    return ws2_map_errno_to_wsa(err);
}

WINAPI_EXPORT int WSAStartup(WORD wVersionRequested, WSADATA *lpWSAData)
{
    (void)wVersionRequested;

    if (lpWSAData) {
        memset(lpWSAData, 0, sizeof(WSADATA));
        lpWSAData->wVersion = 0x0202; /* Winsock 2.2 */
        lpWSAData->wHighVersion = 0x0202;
        strncpy(lpWSAData->szDescription, "PE-Compat Winsock 2.2", sizeof(lpWSAData->szDescription) - 1);
        strncpy(lpWSAData->szSystemStatus, "Running", sizeof(lpWSAData->szSystemStatus) - 1);
        lpWSAData->iMaxSockets = 1024;
        lpWSAData->iMaxUdpDg = 65507;
    }

    pthread_mutex_lock(&wsa_init_mutex);
    atomic_fetch_add(&wsa_init_refcount, 1);
    pthread_mutex_unlock(&wsa_init_mutex);
    return 0;
}

WINAPI_EXPORT int WSACleanup(void)
{
    pthread_mutex_lock(&wsa_init_mutex);
    int prev = atomic_fetch_sub(&wsa_init_refcount, 1);
    if (prev <= 0) {
        /* Already at zero — don't go negative */
        atomic_store(&wsa_init_refcount, 0);
        pthread_mutex_unlock(&wsa_init_mutex);
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    pthread_mutex_unlock(&wsa_init_mutex);
    return 0;
}

WINAPI_EXPORT int WSAGetLastError(void)
{
    return wsa_last_error;
}

WINAPI_EXPORT void WSASetLastError(int iError)
{
    wsa_last_error = iError;
}

WINAPI_EXPORT SOCKET_WIN ws2_socket(int af, int type, int protocol)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return INVALID_SOCKET_WIN;
    }
    int fd = socket(af, type, protocol);
    if (fd < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return INVALID_SOCKET_WIN;
    }
    return (SOCKET_WIN)fd;
}

WINAPI_EXPORT int ws2_connect(SOCKET_WIN s, const struct sockaddr *name, int namelen)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    TRUST_CHECK_RET(TRUST_GATE_NET_CONNECT, "connect", SOCKET_ERROR_WIN);
    int ret = connect((int)s, name, (socklen_t)namelen);
    if (ret < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    return 0;
}

WINAPI_EXPORT int ws2_bind(SOCKET_WIN s, const struct sockaddr *name, int namelen)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    int ret = bind((int)s, name, (socklen_t)namelen);
    if (ret < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    return 0;
}

WINAPI_EXPORT int ws2_listen(SOCKET_WIN s, int backlog)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    int ret = listen((int)s, backlog);
    if (ret < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    return 0;
}

WINAPI_EXPORT SOCKET_WIN ws2_accept(SOCKET_WIN s, struct sockaddr *addr, int *addrlen)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return INVALID_SOCKET_WIN;
    }
    socklen_t len = addrlen ? (socklen_t)*addrlen : 0;
    int fd = accept((int)s, addr, addrlen ? &len : NULL);
    if (fd < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return INVALID_SOCKET_WIN;
    }
    if (addrlen)
        *addrlen = (int)len;
    return (SOCKET_WIN)fd;
}

WINAPI_EXPORT int ws2_send(SOCKET_WIN s, const char *buf, int len, int flags)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    /* Guard against negative lengths — int→size_t cast otherwise produces
     * a near-SIZE_MAX value that send() would interpret as a gigantic buffer,
     * triggering EFAULT or worse (kernel range-check on the user pointer).
     * Windows Winsock returns WSAEFAULT for negative len. */
    if (len < 0) {
        wsa_last_error = WSAEFAULT;
        return SOCKET_ERROR_WIN;
    }
    TRUST_CHECK_RET(TRUST_GATE_NET_CONNECT, "send", SOCKET_ERROR_WIN);
    ssize_t ret = send((int)s, buf, (size_t)len, flags);
    if (ret < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    return (int)ret;
}

WINAPI_EXPORT int ws2_recv(SOCKET_WIN s, char *buf, int len, int flags)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    if (len < 0) {
        wsa_last_error = WSAEFAULT;
        return SOCKET_ERROR_WIN;
    }
    ssize_t ret = recv((int)s, buf, (size_t)len, flags);
    if (ret < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    return (int)ret;
}

WINAPI_EXPORT int ws2_sendto(SOCKET_WIN s, const char *buf, int len, int flags,
                              const struct sockaddr *to, int tolen)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    ssize_t ret = sendto((int)s, buf, (size_t)len, flags, to, (socklen_t)tolen);
    if (ret < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    return (int)ret;
}

WINAPI_EXPORT int ws2_recvfrom(SOCKET_WIN s, char *buf, int len, int flags,
                                struct sockaddr *from, int *fromlen)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    socklen_t flen = fromlen ? (socklen_t)*fromlen : 0;
    ssize_t ret = recvfrom((int)s, buf, (size_t)len, flags, from, fromlen ? &flen : NULL);
    if (ret < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    if (fromlen)
        *fromlen = (int)flen;
    return (int)ret;
}

WINAPI_EXPORT int ws2_closesocket(SOCKET_WIN s)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    if (close((int)s) < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    return 0;
}

WINAPI_EXPORT int ws2_shutdown(SOCKET_WIN s, int how)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    int ret = shutdown((int)s, how);
    if (ret < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    return 0;
}

WINAPI_EXPORT int ws2_select(int nfds, fd_set *readfds, fd_set *writefds,
                              fd_set *exceptfds, struct timeval *timeout)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    int ret = select(nfds, readfds, writefds, exceptfds, timeout);
    if (ret < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    return ret;
}

WINAPI_EXPORT int ws2_ioctlsocket(SOCKET_WIN s, long cmd, unsigned long *argp)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    /* FIONBIO = 0x8004667E on Windows */
    if (cmd == (long)0x8004667E) {
        int flags = fcntl((int)s, F_GETFL, 0);
        if (flags < 0) {
            wsa_last_error = errno_to_wsa(errno);
            return SOCKET_ERROR_WIN;
        }
        if (argp && *argp)
            flags |= O_NONBLOCK;
        else
            flags &= ~O_NONBLOCK;
        if (fcntl((int)s, F_SETFL, flags) < 0) {
            wsa_last_error = errno_to_wsa(errno);
            return SOCKET_ERROR_WIN;
        }
        return 0;
    }
    wsa_last_error = WSAEINVAL;
    return SOCKET_ERROR_WIN;
}

WINAPI_EXPORT int ws2_setsockopt(SOCKET_WIN s, int level, int optname,
                                  const char *optval, int optlen)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    int ret = setsockopt((int)s, level, optname, optval, (socklen_t)optlen);
    if (ret < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    return 0;
}

WINAPI_EXPORT int ws2_getsockopt(SOCKET_WIN s, int level, int optname,
                                  char *optval, int *optlen)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    socklen_t len = optlen ? (socklen_t)*optlen : 0;
    int ret = getsockopt((int)s, level, optname, optval, &len);
    if (ret < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    if (optlen)
        *optlen = (int)len;
    return 0;
}

WINAPI_EXPORT int ws2_getsockname(SOCKET_WIN s, struct sockaddr *name, int *namelen)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    socklen_t len = namelen ? (socklen_t)*namelen : 0;
    int ret = getsockname((int)s, name, &len);
    if (ret < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    if (namelen)
        *namelen = (int)len;
    return 0;
}

WINAPI_EXPORT int ws2_getpeername(SOCKET_WIN s, struct sockaddr *name, int *namelen)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    socklen_t len = namelen ? (socklen_t)*namelen : 0;
    int ret = getpeername((int)s, name, &len);
    if (ret < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    if (namelen)
        *namelen = (int)len;
    return 0;
}

/* --- Name resolution --- */

/* Windows gethostbyname/gethostbyaddr returns a pointer to a per-thread
 * internal buffer. glibc's gethostbyname uses a process-wide static that
 * races between threads (torn aliases/addrs when two PE threads call
 * concurrently — a real, observed hang in IRC bots / game matchmakers).
 * Use the _r variants with a per-thread buffer so each caller gets stable
 * storage. */
static __thread struct hostent ws2_hostent_tls;
static __thread char           ws2_hostent_buf_tls[2048];
static __thread int            ws2_hostent_herr_tls;

WINAPI_EXPORT struct hostent *ws2_gethostbyname(const char *name)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return NULL;
    }
    struct hostent *result = NULL;
    int rc = gethostbyname_r(name, &ws2_hostent_tls,
                             ws2_hostent_buf_tls, sizeof(ws2_hostent_buf_tls),
                             &result, &ws2_hostent_herr_tls);
    if (rc != 0 || !result) {
        wsa_last_error = WSAHOST_NOT_FOUND;
        return NULL;
    }
    return result;
}

WINAPI_EXPORT struct hostent *ws2_gethostbyaddr(const char *addr, int len, int type)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return NULL;
    }
    if (len < 0) {
        wsa_last_error = WSAEFAULT;
        return NULL;
    }
    struct hostent *result = NULL;
    int rc = gethostbyaddr_r(addr, (socklen_t)len, type, &ws2_hostent_tls,
                             ws2_hostent_buf_tls, sizeof(ws2_hostent_buf_tls),
                             &result, &ws2_hostent_herr_tls);
    if (rc != 0 || !result) {
        wsa_last_error = WSAHOST_NOT_FOUND;
        return NULL;
    }
    return result;
}

WINAPI_EXPORT int ws2_gethostname(char *name, int namelen)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    if (!name || namelen <= 0) {
        wsa_last_error = 10014 /* WSAEFAULT */;
        return SOCKET_ERROR_WIN;
    }
    if (gethostname(name, (size_t)namelen) < 0) {
        wsa_last_error = errno_to_wsa(errno);
        return SOCKET_ERROR_WIN;
    }
    /* POSIX gethostname() does not guarantee NUL-termination when the
     * hostname is >= namelen; glibc leaves the last byte as-is. Force
     * termination so PE callers can safely strlen() the result. */
    name[namelen - 1] = '\0';
    return 0;
}

WINAPI_EXPORT int ws2_getaddrinfo(const char *nodename, const char *servname,
                                   const struct addrinfo *hints,
                                   struct addrinfo **res)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return WSAHOST_NOT_FOUND;
    }
    int ret = getaddrinfo(nodename, servname, hints, res);
    if (ret != 0) {
        int wsa_err = eai_to_wsa(ret);
        wsa_last_error = wsa_err;
        return wsa_err;
    }
    return 0;
}

WINAPI_EXPORT void ws2_freeaddrinfo(struct addrinfo *ai)
{
    if (ai)
        freeaddrinfo(ai);
}

WINAPI_EXPORT int ws2_getnameinfo(const struct sockaddr *sa, int salen,
                                   char *host, DWORD hostlen,
                                   char *serv, DWORD servlen, int flags)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return WSAHOST_NOT_FOUND;
    }
    int ret = getnameinfo(sa, (socklen_t)salen, host, (socklen_t)hostlen,
                          serv, (socklen_t)servlen, flags);
    if (ret != 0) {
        int wsa_err = eai_to_wsa(ret);
        wsa_last_error = wsa_err;
        return wsa_err;
    }
    return 0;
}

/* --- Byte order --- */

WINAPI_EXPORT unsigned short ws2_htons(unsigned short hostshort)
{
    return htons(hostshort);
}

WINAPI_EXPORT unsigned short ws2_ntohs(unsigned short netshort)
{
    return ntohs(netshort);
}

WINAPI_EXPORT unsigned long ws2_htonl(unsigned long hostlong)
{
    return htonl(hostlong);
}

WINAPI_EXPORT unsigned long ws2_ntohl(unsigned long netlong)
{
    return ntohl(netlong);
}

WINAPI_EXPORT unsigned long ws2_inet_addr(const char *cp)
{
    return (unsigned long)inet_addr(cp);
}

WINAPI_EXPORT char *ws2_inet_ntoa(struct in_addr in)
{
    return inet_ntoa(in);
}

WINAPI_EXPORT int ws2_inet_pton(int af, const char *src, void *dst)
{
    return inet_pton(af, src, dst);
}

WINAPI_EXPORT const char *ws2_inet_ntop(int af, const void *src, char *dst, unsigned int size)
{
    return inet_ntop(af, src, dst, (socklen_t)size);
}

/* WSAEventSelect / WSAEnumNetworkEvents */

typedef struct {
    long lNetworkEvents;
    int  iErrorCode[10]; /* FD_MAX_EVENTS */
} WSANETWORKEVENTS;

WINAPI_EXPORT int WSAEventSelect(SOCKET_WIN s, HANDLE hEventObject, long lNetworkEvents)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    (void)hEventObject;
    /* Set socket non-blocking when event select is used */
    if (lNetworkEvents) {
        int flags = fcntl((int)s, F_GETFL, 0);
        if (flags >= 0) fcntl((int)s, F_SETFL, flags | O_NONBLOCK);
    }
    return 0;
}

WINAPI_EXPORT int WSAEnumNetworkEvents(SOCKET_WIN s, HANDLE hEventObject,
                                        WSANETWORKEVENTS *lpNetworkEvents)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    (void)hEventObject;
    if (!lpNetworkEvents) {
        wsa_last_error = WSAEINVAL;
        return SOCKET_ERROR_WIN;
    }

    memset(lpNetworkEvents, 0, sizeof(*lpNetworkEvents));

    /* Use poll to check socket state */
    struct pollfd pfd = { .fd = (int)s, .events = POLLIN | POLLOUT, .revents = 0 };
    poll(&pfd, 1, 0);

    /* FD_READ=0x01, FD_WRITE=0x02, FD_ACCEPT=0x08, FD_CONNECT=0x10, FD_CLOSE=0x20 */
    if (pfd.revents & POLLIN)  lpNetworkEvents->lNetworkEvents |= 0x01;
    if (pfd.revents & POLLOUT) lpNetworkEvents->lNetworkEvents |= 0x02;
    if (pfd.revents & POLLHUP) lpNetworkEvents->lNetworkEvents |= 0x20;

    return 0;
}

/* WSAPoll - maps to poll() */
typedef struct {
    SOCKET_WIN fd;
    short events;
    short revents;
} WSAPOLLFD;

WINAPI_EXPORT int WSAPoll(WSAPOLLFD *fdArray, unsigned long fds, int timeout)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    /* WSAPOLLFD has 64-bit fd (SOCKET_WIN=UINT_PTR), struct pollfd has 32-bit int fd.
     * Cannot direct-cast — must convert element-by-element. */
    struct pollfd pfds_stack[64];
    struct pollfd *pfds = (fds <= 64) ? pfds_stack : calloc(fds, sizeof(struct pollfd));
    if (!pfds) { wsa_last_error = WSAENOBUFS; return SOCKET_ERROR_WIN; }
    for (unsigned long i = 0; i < fds; i++) {
        pfds[i].fd = (int)fdArray[i].fd;
        pfds[i].events = fdArray[i].events;
        pfds[i].revents = 0;
    }
    int ret = poll(pfds, (nfds_t)fds, timeout);
    if (ret < 0) {
        wsa_last_error = errno_to_wsa(errno);
        if (pfds != pfds_stack) free(pfds);
        return SOCKET_ERROR_WIN;
    }
    for (unsigned long i = 0; i < fds; i++)
        fdArray[i].revents = pfds[i].revents;
    if (pfds != pfds_stack) free(pfds);
    return ret;
}

/* ---------- WSASend / WSARecv (overlapped I/O) ---------- */

typedef struct {
    unsigned long len;
    char         *buf;
} WSABUF;

typedef struct _WSAOVERLAPPED {
    DWORD    Internal;
    DWORD    InternalHigh;
    DWORD    Offset;
    DWORD    OffsetHigh;
    HANDLE   hEvent;
} WSAOVERLAPPED;

/* PE-side callback: must be ms_abi so any future invocation uses the
 * Windows x64 register/shadow-space convention, not sysv_abi. */
typedef void (__attribute__((ms_abi)) *LPWSAOVERLAPPED_COMPLETION_ROUTINE)(DWORD, DWORD, WSAOVERLAPPED *, DWORD);

WINAPI_EXPORT int WSASend(SOCKET_WIN s, WSABUF *lpBuffers, DWORD dwBufferCount,
                           LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
                           WSAOVERLAPPED *lpOverlapped,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    TRUST_CHECK_RET(TRUST_GATE_NET_CONNECT, "WSASend", SOCKET_ERROR_WIN);
    (void)lpOverlapped; (void)lpCompletionRoutine; (void)dwFlags;

    ssize_t total = 0;
    for (DWORD i = 0; i < dwBufferCount; i++) {
        ssize_t ret = send((int)s, lpBuffers[i].buf, lpBuffers[i].len, MSG_NOSIGNAL);
        if (ret < 0) {
            if (total > 0) break;
            wsa_last_error = errno_to_wsa(errno);
            return SOCKET_ERROR_WIN;
        }
        total += ret;
        if ((unsigned long)ret < lpBuffers[i].len) break;
    }

    if (lpNumberOfBytesSent) *lpNumberOfBytesSent = (DWORD)total;
    return 0;
}

WINAPI_EXPORT int WSARecv(SOCKET_WIN s, WSABUF *lpBuffers, DWORD dwBufferCount,
                           LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
                           WSAOVERLAPPED *lpOverlapped,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    (void)lpOverlapped; (void)lpCompletionRoutine;
    int flags = lpFlags ? (int)*lpFlags : 0;

    ssize_t total = 0;
    for (DWORD i = 0; i < dwBufferCount; i++) {
        ssize_t ret = recv((int)s, lpBuffers[i].buf, lpBuffers[i].len, flags);
        if (ret < 0) {
            if (total > 0) break;
            wsa_last_error = errno_to_wsa(errno);
            return SOCKET_ERROR_WIN;
        }
        if (ret == 0) break;
        total += ret;
        if ((unsigned long)ret < lpBuffers[i].len) break;
    }

    if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = (DWORD)total;
    return 0;
}

WINAPI_EXPORT int WSASendTo(SOCKET_WIN s, WSABUF *lpBuffers, DWORD dwBufferCount,
                             LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
                             const struct sockaddr *lpTo, int iTolen,
                             WSAOVERLAPPED *lpOverlapped,
                             LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    (void)lpOverlapped; (void)lpCompletionRoutine; (void)dwFlags;

    ssize_t total = 0;
    for (DWORD i = 0; i < dwBufferCount; i++) {
        ssize_t ret = sendto((int)s, lpBuffers[i].buf, lpBuffers[i].len, 0,
                             lpTo, (socklen_t)iTolen);
        if (ret < 0) {
            if (total > 0) break;
            wsa_last_error = errno_to_wsa(errno);
            return SOCKET_ERROR_WIN;
        }
        total += ret;
    }

    if (lpNumberOfBytesSent) *lpNumberOfBytesSent = (DWORD)total;
    return 0;
}

WINAPI_EXPORT int WSARecvFrom(SOCKET_WIN s, WSABUF *lpBuffers, DWORD dwBufferCount,
                               LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
                               struct sockaddr *lpFrom, int *lpFromlen,
                               WSAOVERLAPPED *lpOverlapped,
                               LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    if (!wsa_is_initialized()) {
        wsa_last_error = WSANOTINITIALISED;
        return SOCKET_ERROR_WIN;
    }
    (void)lpOverlapped; (void)lpCompletionRoutine;
    int flags = lpFlags ? (int)*lpFlags : 0;

    socklen_t fromlen = lpFromlen ? (socklen_t)*lpFromlen : 0;
    ssize_t total = 0;
    for (DWORD i = 0; i < dwBufferCount; i++) {
        ssize_t ret = recvfrom((int)s, lpBuffers[i].buf, lpBuffers[i].len, flags,
                               lpFrom, lpFromlen ? &fromlen : NULL);
        if (ret < 0) {
            if (total > 0) break;
            wsa_last_error = errno_to_wsa(errno);
            return SOCKET_ERROR_WIN;
        }
        if (ret == 0) break;
        total += ret;
    }

    if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = (DWORD)total;
    if (lpFromlen) *lpFromlen = (int)fromlen;
    return 0;
}

WINAPI_EXPORT HANDLE WSACreateEvent(void)
{
    /* Use eventfd or a simple pipe for signaling */
    return (HANDLE)(uintptr_t)0xAE0001;
}

WINAPI_EXPORT BOOL WSACloseEvent(HANDLE hEvent)
{
    (void)hEvent;
    return TRUE;
}

WINAPI_EXPORT BOOL WSASetEvent(HANDLE hEvent)
{
    (void)hEvent;
    return TRUE;
}

WINAPI_EXPORT BOOL WSAResetEvent(HANDLE hEvent)
{
    (void)hEvent;
    return TRUE;
}

WINAPI_EXPORT DWORD WSAWaitForMultipleEvents(DWORD cEvents, const HANDLE *lphEvents,
                                              BOOL fWaitAll, DWORD dwTimeout,
                                              BOOL fAlertable)
{
    (void)cEvents; (void)lphEvents; (void)fWaitAll; (void)fAlertable;
    /* INFINITE (0xFFFFFFFF) treated as "no timeout — sleep until signaled".
     * We have no real event plumbing here, so just return immediately for
     * INFINITE instead of hanging forever. Session 30: previously this
     * path spun through nanosleep with a 4.3M-second timeout. */
    if (dwTimeout == 0xFFFFFFFFu) {
        return 0;
    }
    if (dwTimeout > 0) {
        struct timespec ts = { .tv_sec = dwTimeout / 1000,
                               .tv_nsec = (dwTimeout % 1000) * 1000000L };
        struct timespec rem;
        /* Handle EINTR properly — a stray signal should not cut the wait
         * short, which would starve HTTP download workers that use
         * WSAWaitForMultipleEvents as a rate limiter. */
        while (nanosleep(&ts, &rem) == -1 && errno == EINTR) {
            ts = rem;
        }
    }
    return 0; /* WSA_WAIT_EVENT_0 */
}

WINAPI_EXPORT int WSADuplicateSocketA(SOCKET_WIN s, DWORD dwProcessId, void *lpProtocolInfo)
{
    (void)s; (void)dwProcessId; (void)lpProtocolInfo;
    wsa_last_error = WSAEOPNOTSUPP;
    return SOCKET_ERROR_WIN;
}

WINAPI_EXPORT int WSASocketA(int af, int type, int protocol,
                              void *lpProtocolInfo, unsigned int g, DWORD dwFlags)
{
    (void)lpProtocolInfo; (void)g; (void)dwFlags;
    return (int)ws2_socket(af, type, protocol);
}

WINAPI_EXPORT int WSASocketW(int af, int type, int protocol,
                              void *lpProtocolInfo, unsigned int g, DWORD dwFlags)
{
    return WSASocketA(af, type, protocol, lpProtocolInfo, g, dwFlags);
}

WINAPI_EXPORT int WSAIoctl(SOCKET_WIN s, DWORD dwIoControlCode,
                            void *lpvInBuffer, DWORD cbInBuffer,
                            void *lpvOutBuffer, DWORD cbOutBuffer,
                            LPDWORD lpcbBytesReturned,
                            WSAOVERLAPPED *lpOverlapped,
                            LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    (void)s; (void)dwIoControlCode; (void)lpvInBuffer; (void)cbInBuffer;
    (void)lpvOutBuffer; (void)cbOutBuffer; (void)lpOverlapped; (void)lpCompletionRoutine;
    if (lpcbBytesReturned) *lpcbBytesReturned = 0;
    return 0;
}

WINAPI_EXPORT int WSAAddressToStringA(void *lpsaAddress, DWORD dwAddressLength,
                                       void *lpProtocolInfo, LPSTR lpszAddressString,
                                       LPDWORD lpdwAddressStringLength)
{
    (void)lpsaAddress; (void)dwAddressLength; (void)lpProtocolInfo;
    (void)lpszAddressString; (void)lpdwAddressStringLength;
    return 0;
}

/*
 * NOTE: We do NOT export bare POSIX names (socket, connect, bind, etc.)
 * as aliases. When loaded with RTLD_GLOBAL, such aliases would override
 * the real POSIX socket functions, breaking the loader's own networking.
 *
 * PE imports are resolved by the import resolver which maps DLL function
 * names to the ws2_ prefixed implementations above. The Windows-specific
 * names (WSAStartup, WSACleanup, closesocket, ioctlsocket, etc.) that
 * don't collide with POSIX are exported directly via WINAPI_EXPORT.
 */
