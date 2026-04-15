/*
 * anticheat_bridge.c - Bridge between PE loader and anti-cheat guard service
 *
 * The PE loader runs Windows executables in userspace. When those executables
 * are games protected by anti-cheat systems (EAC, BattlEye, Vanguard, etc.),
 * the anti-cheat guard service (services/anticheat/anticheat_guard.c) provides
 * cross-process protection.
 *
 * This bridge connects the PE loader to the guard via a Unix domain socket
 * at /tmp/pe-anticheat.sock. All communication is fire-and-forget: if the
 * guard service is not running, all operations silently succeed. This means
 * games work normally without anti-cheat enforcement when the service is down.
 *
 * Protocol:
 *   Each message is a fixed-size packet with a type field and a payload.
 *   The bridge sends messages; the guard optionally replies with status.
 *
 * Integration points:
 *   - pe_import.c calls anticheat_bridge_on_load_library() after resolving DLL
 *   - env_setup.c calls anticheat_bridge_register_game() after PEB init
 *   - main.c calls anticheat_bridge_init() during startup
 *   - main.c calls anticheat_bridge_shutdown() on exit
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define ACB_LOG_PREFIX      "[pe/anticheat] "
#define ACB_SOCKET_PATH     "/tmp/pe-anticheat.sock"
#define ACB_MAX_NAME_LEN    256
#define ACB_MAX_PAYLOAD     512

/*
 * Message types sent from the PE loader bridge to the guard service.
 * These must match the guard's message parsing (future IPC protocol).
 */
typedef enum {
    ACB_MSG_REGISTER_GAME   = 1,    /* Register a game process */
    ACB_MSG_LOAD_LIBRARY    = 2,    /* DLL was loaded */
    ACB_MSG_CREATE_THREAD   = 3,    /* Thread was created */
    ACB_MSG_CHECK_INTEGRITY = 4,    /* Integrity check request */
    ACB_MSG_UNREGISTER      = 5,    /* Game process exiting */
    ACB_MSG_HEARTBEAT       = 6     /* Keep-alive / status check */
} acb_msg_type_t;

/* Wire format for messages */
typedef struct {
    uint32_t        type;           /* acb_msg_type_t */
    uint32_t        payload_len;    /* Length of payload data */
    pid_t           pid;            /* Source process ID */
    char            payload[ACB_MAX_PAYLOAD];
} acb_message_t;

/* Bridge state */
typedef struct {
    int             initialized;
    int             connected;
    int             sock_fd;
    pid_t           game_pid;
    char            game_name[ACB_MAX_NAME_LEN];
    unsigned long   messages_sent;
    unsigned long   send_failures;
} acb_state_t;

static acb_state_t g_bridge = {0};

/* --- Internal helpers --- */

/*
 * Attempt to connect to the anti-cheat guard service socket.
 * Returns 0 on success, -1 on failure.
 *
 * Connection failure is not an error condition -- it means the guard
 * service is not running, and the game proceeds without protection.
 */
static int acb_connect(void)
{
    struct sockaddr_un addr;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        fprintf(stderr, ACB_LOG_PREFIX "socket() failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ACB_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        /*
         * ENOENT = socket file doesn't exist (service not running)
         * ECONNREFUSED = socket exists but nobody is listening
         * Both are normal conditions -- guard is simply not active.
         */
        if (errno == ENOENT || errno == ECONNREFUSED) {
            fprintf(stderr, ACB_LOG_PREFIX "Guard service not available "
                    "(no protection active)\n");
        } else {
            fprintf(stderr, ACB_LOG_PREFIX "connect() failed: %s\n", strerror(errno));
        }
        close(fd);
        return -1;
    }

    g_bridge.sock_fd = fd;
    g_bridge.connected = 1;

    fprintf(stderr, ACB_LOG_PREFIX "Connected to guard service at %s\n", ACB_SOCKET_PATH);
    return 0;
}

/*
 * Send a message to the guard service.
 * Returns 0 on success, -1 on failure.
 *
 * On send failure, the connection is marked as dead and future sends
 * will silently succeed (no-op). This prevents the game from hanging
 * if the guard crashes mid-session.
 */
static int acb_send_message(acb_msg_type_t type, const void *payload, size_t payload_len)
{
    if (!g_bridge.connected)
        return 0;   /* Not connected = silently succeed */

    acb_message_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = (uint32_t)type;
    msg.pid = g_bridge.game_pid ? g_bridge.game_pid : getpid();

    if (payload && payload_len > 0) {
        if (payload_len > ACB_MAX_PAYLOAD)
            payload_len = ACB_MAX_PAYLOAD;
        memcpy(msg.payload, payload, payload_len);
        msg.payload_len = (uint32_t)payload_len;
    }

    ssize_t sent = send(g_bridge.sock_fd, &msg, sizeof(msg), MSG_NOSIGNAL);
    if (sent < 0) {
        if (errno == EPIPE || errno == ECONNRESET) {
            fprintf(stderr, ACB_LOG_PREFIX "Connection lost to guard service\n");
            close(g_bridge.sock_fd);
            g_bridge.sock_fd = -1;
            g_bridge.connected = 0;
        } else {
            fprintf(stderr, ACB_LOG_PREFIX "send() failed: %s\n", strerror(errno));
        }
        g_bridge.send_failures++;
        return -1;
    }

    g_bridge.messages_sent++;
    return 0;
}

/* --- Public API --- */

/*
 * anticheat_bridge_init - Initialize the anti-cheat bridge
 *
 * Attempts to connect to the guard service via Unix domain socket.
 * If the socket does not exist or the service is not running, this
 * succeeds silently -- anti-cheat protection is optional.
 *
 * Returns 0 on success (always succeeds; connection failure is not an error).
 */
int anticheat_bridge_init(void)
{
    if (g_bridge.initialized) {
        fprintf(stderr, ACB_LOG_PREFIX "Already initialized\n");
        return 0;
    }

    fprintf(stderr, ACB_LOG_PREFIX "Initializing anti-cheat bridge\n");

    memset(&g_bridge, 0, sizeof(g_bridge));
    g_bridge.sock_fd = -1;
    g_bridge.initialized = 1;

    /* Attempt connection to guard service */
    if (acb_connect() < 0) {
        /*
         * Connection failed -- this is fine. The guard service is not running,
         * so we operate in passthrough mode (no protection enforcement).
         */
        fprintf(stderr, ACB_LOG_PREFIX "Bridge initialized (passthrough mode)\n");
    } else {
        fprintf(stderr, ACB_LOG_PREFIX "Bridge initialized (connected to guard)\n");
    }

    return 0;
}

/*
 * anticheat_bridge_register_game - Register a game process with the guard
 *
 * @pid:       Process ID of the game
 * @game_name: Human-readable game name (for logging and identification)
 *
 * Tells the guard service that this PID should be added to the protected set.
 * After registration, the guard will block untrusted cross-process access.
 *
 * Returns 0 on success, -1 on error.
 */
int anticheat_bridge_register_game(pid_t pid, const char *game_name)
{
    if (!g_bridge.initialized) {
        fprintf(stderr, ACB_LOG_PREFIX "anticheat_bridge_register_game: "
                "not initialized\n");
        return -1;
    }

    g_bridge.game_pid = pid;
    if (game_name) {
        strncpy(g_bridge.game_name, game_name, sizeof(g_bridge.game_name) - 1);
        g_bridge.game_name[sizeof(g_bridge.game_name) - 1] = '\0';
    } else {
        snprintf(g_bridge.game_name, sizeof(g_bridge.game_name), "game_%d", pid);
    }

    fprintf(stderr, ACB_LOG_PREFIX "Registering game: PID=%d, name=%s\n",
            pid, g_bridge.game_name);

    /*
     * Build the registration payload.
     * Format: game_name\0 (null-terminated string in payload)
     */
    char payload[ACB_MAX_PAYLOAD];
    memset(payload, 0, sizeof(payload));
    strncpy(payload, g_bridge.game_name, sizeof(payload) - 1);
    size_t payload_len = strlen(payload) + 1;

    return acb_send_message(ACB_MSG_REGISTER_GAME, payload, payload_len);
}

/*
 * anticheat_bridge_on_load_library - Notify the guard when a DLL is loaded
 *
 * @dll_name: Name of the loaded DLL (e.g., "kernel32.dll", "hack.dll")
 *
 * Called from pe_import.c after a DLL stub is resolved via dlopen.
 * The guard can use this to detect unexpected module loads that may
 * indicate DLL injection.
 *
 * Returns 0 on success, -1 on error.
 */
int anticheat_bridge_on_load_library(const char *dll_name)
{
    if (!g_bridge.initialized)
        return 0;

    if (!dll_name) {
        fprintf(stderr, ACB_LOG_PREFIX "on_load_library: null dll_name\n");
        return -1;
    }

    fprintf(stderr, ACB_LOG_PREFIX "DLL loaded: %s\n", dll_name);

    char payload[ACB_MAX_PAYLOAD];
    memset(payload, 0, sizeof(payload));
    strncpy(payload, dll_name, sizeof(payload) - 1);
    size_t payload_len = strlen(payload) + 1;

    return acb_send_message(ACB_MSG_LOAD_LIBRARY, payload, payload_len);
}

/*
 * anticheat_bridge_on_create_thread - Notify the guard of thread creation
 *
 * @start_addr: Start address of the new thread
 *
 * Called when CreateThread / _beginthreadex is invoked within the PE process.
 * The guard monitors thread creation to detect CreateRemoteThread injection
 * and code caves.
 *
 * Returns 0 on success, -1 on error.
 */
int anticheat_bridge_on_create_thread(void *start_addr)
{
    if (!g_bridge.initialized)
        return 0;

    fprintf(stderr, ACB_LOG_PREFIX "Thread created: start_addr=%p\n", start_addr);

    /*
     * Payload: the thread start address as a hex string.
     * The guard can compare this against known code regions to detect
     * threads starting from injected code.
     */
    char payload[ACB_MAX_PAYLOAD];
    memset(payload, 0, sizeof(payload));
    snprintf(payload, sizeof(payload), "%p", start_addr);
    size_t payload_len = strlen(payload) + 1;

    return acb_send_message(ACB_MSG_CREATE_THREAD, payload, payload_len);
}

/*
 * anticheat_bridge_check_integrity - Verify PE image integrity
 *
 * @base: Base address of the mapped PE image
 * @size: Size of the mapped PE image
 *
 * Sends the image base and size to the guard, which can then verify that
 * the in-memory image matches the on-disk file (detecting runtime patches
 * to game code, such as aimbot hooks).
 *
 * For the bridge, we also do a local sanity check: verify the PE signature
 * ("MZ" header) is still intact at the base address.
 *
 * Returns 1 if integrity is OK, 0 if tampered, -1 on error.
 */
int anticheat_bridge_check_integrity(void *base, size_t size)
{
    if (!base || size == 0) {
        fprintf(stderr, ACB_LOG_PREFIX "check_integrity: invalid arguments\n");
        return -1;
    }

    fprintf(stderr, ACB_LOG_PREFIX "Integrity check: base=%p, size=0x%zx\n", base, size);

    /*
     * Local sanity check: verify the DOS header "MZ" magic is intact.
     * If someone has overwritten the PE headers, this is a clear sign
     * of tampering.
     */
    const unsigned char *header = (const unsigned char *)base;
    if (size >= 2 && (header[0] != 'M' || header[1] != 'Z')) {
        fprintf(stderr, ACB_LOG_PREFIX "INTEGRITY FAILURE: MZ header corrupted "
                "(found 0x%02X 0x%02X)\n", header[0], header[1]);
        return 0;
    }

    /*
     * Additional check: verify the PE signature at the offset specified
     * by the e_lfanew field in the DOS header.
     */
    if (size >= 64) {
        uint32_t pe_offset = *(uint32_t *)(header + 0x3C); /* e_lfanew */
        if ((size_t)pe_offset + 4 <= size) {
            const unsigned char *pe_sig = header + pe_offset;
            if (pe_sig[0] != 'P' || pe_sig[1] != 'E' ||
                pe_sig[2] != '\0' || pe_sig[3] != '\0') {
                fprintf(stderr, ACB_LOG_PREFIX "INTEGRITY FAILURE: PE signature corrupted "
                        "at offset 0x%X\n", pe_offset);
                return 0;
            }
        }
    }

    /*
     * Notify the guard of the integrity check.
     * Payload format: "base_hex:size_hex"
     */
    if (g_bridge.initialized) {
        char payload[ACB_MAX_PAYLOAD];
        memset(payload, 0, sizeof(payload));
        snprintf(payload, sizeof(payload), "%p:0x%zx", base, size);
        size_t payload_len = strlen(payload) + 1;
        acb_send_message(ACB_MSG_CHECK_INTEGRITY, payload, payload_len);
    }

    fprintf(stderr, ACB_LOG_PREFIX "Integrity check passed\n");
    return 1;
}

/*
 * anticheat_bridge_shutdown - Disconnect from the guard and clean up
 *
 * Sends an unregister message to the guard (so it removes the PID from
 * the protected set), then closes the socket.
 *
 * Returns 0 on success.
 */
int anticheat_bridge_shutdown(void)
{
    if (!g_bridge.initialized) {
        fprintf(stderr, ACB_LOG_PREFIX "Not initialized\n");
        return 0;
    }

    fprintf(stderr, ACB_LOG_PREFIX "Shutting down anti-cheat bridge\n");

    /* Send unregister message to guard */
    if (g_bridge.connected) {
        acb_send_message(ACB_MSG_UNREGISTER, NULL, 0);
    }

    /* Report statistics */
    fprintf(stderr, ACB_LOG_PREFIX "Statistics:\n");
    fprintf(stderr, ACB_LOG_PREFIX "  Messages sent:   %lu\n", g_bridge.messages_sent);
    fprintf(stderr, ACB_LOG_PREFIX "  Send failures:   %lu\n", g_bridge.send_failures);
    fprintf(stderr, ACB_LOG_PREFIX "  Game PID:        %d\n", g_bridge.game_pid);
    fprintf(stderr, ACB_LOG_PREFIX "  Game name:       %s\n", g_bridge.game_name);

    /* Close socket */
    if (g_bridge.sock_fd >= 0) {
        close(g_bridge.sock_fd);
        g_bridge.sock_fd = -1;
    }

    g_bridge.connected = 0;
    g_bridge.initialized = 0;

    fprintf(stderr, ACB_LOG_PREFIX "Bridge shut down\n");
    return 0;
}

/*
 * anticheat_bridge_is_connected - Check if the bridge is connected to the guard
 *
 * Returns 1 if connected and active, 0 otherwise.
 * Useful for games that want to know if anti-cheat protection is active.
 */
int anticheat_bridge_is_connected(void)
{
    return g_bridge.initialized && g_bridge.connected;
}

/*
 * anticheat_bridge_heartbeat - Send a heartbeat to the guard
 *
 * Called periodically to confirm the game process is still running.
 * If the guard does not receive heartbeats, it may assume the process
 * crashed and clean up its protected PID entry.
 *
 * Returns 0 on success, -1 on error.
 */
int anticheat_bridge_heartbeat(void)
{
    if (!g_bridge.initialized || !g_bridge.connected)
        return 0;

    return acb_send_message(ACB_MSG_HEARTBEAT, NULL, 0);
}
