/*
 * console_socket.c -- ws2_32 winsock smoke test.
 *
 * Surface tested:
 *   ws2_32!WSAStartup, ws2_32!WSACleanup, ws2_32!socket,
 *   ws2_32!setsockopt, ws2_32!bind, ws2_32!listen, ws2_32!closesocket
 *
 * Rationale:
 *   We deliberately do NOT connect to anything; we just stand up a
 *   listening socket on localhost:0 (kernel picks port), getsockname,
 *   then tear down.  Catches:
 *     - WSAStartup version negotiation
 *     - socket(AF_INET, SOCK_STREAM) returns valid handle
 *     - bind to 127.0.0.1:0 succeeds
 *     - listen + getsockname returns the kernel-assigned port
 *
 *   No network traffic generated.  No external host required.
 *
 * Harness expectation: outputs:CONSOLE_SOCKET_OK
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    WSADATA wsa;
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (rc != 0) {
        fprintf(stderr, "WSAStartup failed: rc=%d\n", rc);
        return 40;
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "socket() failed: WSAGetLastError=%d\n",
                WSAGetLastError());
        WSACleanup();
        return 41;
    }

    int reuse = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
               (const char *)&reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0;  /* kernel picks */
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "bind() failed: WSAGetLastError=%d\n",
                WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 42;
    }

    if (listen(s, 1) == SOCKET_ERROR) {
        fprintf(stderr, "listen() failed: WSAGetLastError=%d\n",
                WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 43;
    }

    /* Confirm getsockname returns the kernel-chosen port. */
    struct sockaddr_in bound;
    int blen = (int)sizeof(bound);
    if (getsockname(s, (struct sockaddr *)&bound, &blen) == SOCKET_ERROR) {
        fprintf(stderr, "getsockname failed: WSAGetLastError=%d\n",
                WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return 44;
    }
    unsigned short bound_port = ntohs(bound.sin_port);
    if (bound_port == 0) {
        fprintf(stderr, "getsockname returned port 0 after listen\n");
        closesocket(s);
        WSACleanup();
        return 45;
    }
    printf("listening on 127.0.0.1:%u\n", (unsigned)bound_port);

    closesocket(s);
    WSACleanup();

    printf("CONSOLE_SOCKET_OK\n");
    fflush(stdout);
    return 0;
}
