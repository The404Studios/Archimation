/*
 * steam_api_stub.c - Steamworks API stubs
 *
 * Minimal stub for steam_api64.dll / steam_api.dll.
 * Games that link against steam_api need these to launch.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/dll_common.h"

#define STEAM_API_OK 1

/* Steam callback structures */
typedef uint32_t HSteamPipe;
typedef uint32_t HSteamUser;
typedef uint64_t CSteamID;

/* Fake Steam interfaces */
typedef struct { void *vtbl; } ISteamClient;
typedef struct { void *vtbl; } ISteamUser;
typedef struct { void *vtbl; } ISteamFriends;
typedef struct { void *vtbl; } ISteamUtils;
typedef struct { void *vtbl; } ISteamMatchmaking;
typedef struct { void *vtbl; } ISteamUserStats;
typedef struct { void *vtbl; } ISteamApps;
typedef struct { void *vtbl; } ISteamNetworking;
typedef struct { void *vtbl; } ISteamRemoteStorage;
typedef struct { void *vtbl; } ISteamScreenshots;
typedef struct { void *vtbl; } ISteamController;
typedef struct { void *vtbl; } ISteamUGC;

static ISteamClient g_steam_client;
static ISteamUser g_steam_user;
static ISteamFriends g_steam_friends;
static ISteamUtils g_steam_utils;
static ISteamMatchmaking g_steam_matchmaking;
static ISteamUserStats g_steam_userstats;
static ISteamApps g_steam_apps;
static ISteamNetworking g_steam_networking;
static ISteamRemoteStorage g_steam_remote_storage;
static ISteamScreenshots g_steam_screenshots;
static ISteamController g_steam_controller;
static ISteamUGC g_steam_ugc;

static int g_steam_initialized = 0;

/* Generic stub vtable methods -- prevent NULL vtbl crashes */
static __attribute__((ms_abi)) uint64_t steam_stub_return_0(void *self) { (void)self; return 0; }

/* Generic vtable with enough entries to cover Steam interfaces.
 * Real Steam interfaces can have 100+ methods; undersizing this causes OOB
 * reads and crashes when a game invokes a high-slot method (e.g. ISteamUGC,
 * ISteamNetworking). 256 slots covers all known Steamworks interfaces. */
#define STEAM_VTBL_SLOTS 256
static void *g_steam_vtbl[STEAM_VTBL_SLOTS] = {0};

static void init_steam_vtbl(void)
{
    static int done = 0;
    if (done) return;
    for (int i = 0; i < STEAM_VTBL_SLOTS; i++)
        g_steam_vtbl[i] = (void *)steam_stub_return_0;
    done = 1;
}

static void init_all_steam_interfaces(void)
{
    static int all_done = 0;
    if (all_done) return;
    init_steam_vtbl();
    g_steam_client.vtbl = g_steam_vtbl;
    g_steam_user.vtbl = g_steam_vtbl;
    g_steam_friends.vtbl = g_steam_vtbl;
    g_steam_utils.vtbl = g_steam_vtbl;
    g_steam_matchmaking.vtbl = g_steam_vtbl;
    g_steam_userstats.vtbl = g_steam_vtbl;
    g_steam_apps.vtbl = g_steam_vtbl;
    g_steam_networking.vtbl = g_steam_vtbl;
    g_steam_remote_storage.vtbl = g_steam_vtbl;
    g_steam_screenshots.vtbl = g_steam_vtbl;
    g_steam_controller.vtbl = g_steam_vtbl;
    g_steam_ugc.vtbl = g_steam_vtbl;
    all_done = 1;
}

/* ================================================================== */
/*  Core Steam API                                                    */
/* ================================================================== */

WINAPI_EXPORT int SteamAPI_Init(void)
{
    fprintf(stderr, "[steam_api] SteamAPI_Init()\n");
    init_all_steam_interfaces();
    g_steam_initialized = 1;
    return STEAM_API_OK;
}

WINAPI_EXPORT int SteamAPI_InitSafe(void)
{
    return SteamAPI_Init();
}

WINAPI_EXPORT void SteamAPI_Shutdown(void)
{
    fprintf(stderr, "[steam_api] SteamAPI_Shutdown()\n");
    g_steam_initialized = 0;
}

WINAPI_EXPORT int SteamAPI_IsSteamRunning(void)
{
    return 1; /* Pretend Steam is running */
}

WINAPI_EXPORT int SteamAPI_RestartAppIfNecessary(uint32_t appId)
{
    fprintf(stderr, "[steam_api] SteamAPI_RestartAppIfNecessary(appId=%u) -> 0 (no restart)\n", appId);
    return 0; /* 0 = no restart needed */
}

WINAPI_EXPORT void SteamAPI_RunCallbacks(void)
{
    /* No-op: no real callbacks to dispatch */
}

WINAPI_EXPORT void SteamAPI_RegisterCallback(void *pCallback, int iCallback)
{
    (void)pCallback; (void)iCallback;
}

WINAPI_EXPORT void SteamAPI_UnregisterCallback(void *pCallback)
{
    (void)pCallback;
}

WINAPI_EXPORT void SteamAPI_RegisterCallResult(void *pCallback, uint64_t hAPICall)
{
    (void)pCallback; (void)hAPICall;
}

WINAPI_EXPORT void SteamAPI_UnregisterCallResult(void *pCallback, uint64_t hAPICall)
{
    (void)pCallback; (void)hAPICall;
}

/* ================================================================== */
/*  Interface accessors                                               */
/* ================================================================== */

WINAPI_EXPORT ISteamClient *SteamClient(void) { init_all_steam_interfaces(); return &g_steam_client; }
WINAPI_EXPORT ISteamUser *SteamUser(void) { init_all_steam_interfaces(); return &g_steam_user; }
WINAPI_EXPORT ISteamFriends *SteamFriends(void) { init_all_steam_interfaces(); return &g_steam_friends; }
WINAPI_EXPORT ISteamUtils *SteamUtils(void) { init_all_steam_interfaces(); return &g_steam_utils; }
WINAPI_EXPORT ISteamMatchmaking *SteamMatchmaking(void) { init_all_steam_interfaces(); return &g_steam_matchmaking; }
WINAPI_EXPORT ISteamUserStats *SteamUserStats(void) { init_all_steam_interfaces(); return &g_steam_userstats; }
WINAPI_EXPORT ISteamApps *SteamApps(void) { init_all_steam_interfaces(); return &g_steam_apps; }
WINAPI_EXPORT ISteamNetworking *SteamNetworking(void) { init_all_steam_interfaces(); return &g_steam_networking; }
WINAPI_EXPORT ISteamRemoteStorage *SteamRemoteStorage(void) { init_all_steam_interfaces(); return &g_steam_remote_storage; }
WINAPI_EXPORT ISteamScreenshots *SteamScreenshots(void) { init_all_steam_interfaces(); return &g_steam_screenshots; }
WINAPI_EXPORT ISteamController *SteamController(void) { init_all_steam_interfaces(); return &g_steam_controller; }
WINAPI_EXPORT ISteamUGC *SteamUGC(void) { init_all_steam_interfaces(); return &g_steam_ugc; }

WINAPI_EXPORT HSteamPipe SteamAPI_GetHSteamPipe(void) { return 1; }
WINAPI_EXPORT HSteamUser SteamAPI_GetHSteamUser(void) { return 1; }

/* ================================================================== */
/*  Steam internal API (flat API used by newer SDK)                   */
/* ================================================================== */

WINAPI_EXPORT void *SteamInternal_FindOrCreateUserInterface(HSteamUser user, const char *version)
{
    fprintf(stderr, "[steam_api] SteamInternal_FindOrCreateUserInterface(user=%u, '%s')\n",
            user, version ? version : "(null)");
    init_all_steam_interfaces();
    /* Return a non-NULL pointer so callers don't crash */
    if (version) {
        if (strstr(version, "SteamUser")) return &g_steam_user;
        if (strstr(version, "SteamFriends")) return &g_steam_friends;
        if (strstr(version, "SteamUtils")) return &g_steam_utils;
        if (strstr(version, "SteamApps")) return &g_steam_apps;
        if (strstr(version, "SteamUserStats")) return &g_steam_userstats;
        if (strstr(version, "SteamMatchmaking")) return &g_steam_matchmaking;
        if (strstr(version, "SteamNetworking")) return &g_steam_networking;
        if (strstr(version, "SteamRemoteStorage")) return &g_steam_remote_storage;
        if (strstr(version, "SteamScreenshots")) return &g_steam_screenshots;
        if (strstr(version, "SteamController")) return &g_steam_controller;
        if (strstr(version, "SteamUGC")) return &g_steam_ugc;
    }
    return &g_steam_client;
}

WINAPI_EXPORT void *SteamInternal_CreateInterface(const char *version)
{
    fprintf(stderr, "[steam_api] SteamInternal_CreateInterface('%s')\n",
            version ? version : "(null)");
    return SteamInternal_FindOrCreateUserInterface(1, version);
}

WINAPI_EXPORT int SteamInternal_GameServer_Init(uint32_t ip, uint16_t steamPort,
    uint16_t gamePort, uint16_t queryPort, int eServerMode, const char *version)
{
    (void)ip; (void)steamPort; (void)gamePort; (void)queryPort;
    (void)eServerMode; (void)version;
    return 1;
}

WINAPI_EXPORT void *SteamGameServer(void) { return &g_steam_client; }
WINAPI_EXPORT void *SteamGameServerStats(void) { return &g_steam_userstats; }

WINAPI_EXPORT void SteamGameServer_Shutdown(void) { }
WINAPI_EXPORT void SteamGameServer_RunCallbacks(void) { }
WINAPI_EXPORT int SteamGameServer_BSecure(void) { return 0; }
WINAPI_EXPORT uint64_t SteamGameServer_GetSteamID(void) { return 0; }

/* Versioned accessors (S_API ISteamXxx *SteamXxx_vNNN()) */
WINAPI_EXPORT void *SteamAPI_SteamUser_v021(void) { return &g_steam_user; }
WINAPI_EXPORT void *SteamAPI_SteamFriends_v017(void) { return &g_steam_friends; }
WINAPI_EXPORT void *SteamAPI_SteamUtils_v010(void) { return &g_steam_utils; }
WINAPI_EXPORT void *SteamAPI_SteamApps_v008(void) { return &g_steam_apps; }
WINAPI_EXPORT void *SteamAPI_SteamUserStats_v012(void) { return &g_steam_userstats; }
WINAPI_EXPORT void *SteamAPI_SteamNetworking_v006(void) { return &g_steam_networking; }
WINAPI_EXPORT void *SteamAPI_SteamRemoteStorage_v016(void) { return &g_steam_remote_storage; }
WINAPI_EXPORT void *SteamAPI_SteamScreenshots_v003(void) { return &g_steam_screenshots; }
WINAPI_EXPORT void *SteamAPI_SteamController_v008(void) { return &g_steam_controller; }
WINAPI_EXPORT void *SteamAPI_SteamUGC_v016(void) { return &g_steam_ugc; }

/* Steam API callback management */
WINAPI_EXPORT void SteamAPI_ManualDispatch_Init(void) { }
WINAPI_EXPORT void SteamAPI_ManualDispatch_RunFrame(HSteamPipe pipe) { (void)pipe; }
WINAPI_EXPORT int SteamAPI_ManualDispatch_GetNextCallback(HSteamPipe pipe, void *msg)
{ (void)pipe; (void)msg; return 0; }
WINAPI_EXPORT void SteamAPI_ManualDispatch_FreeLastCallback(HSteamPipe pipe) { (void)pipe; }
