/*
 * winmm_time.c - Multimedia timer, audio, MIDI, and joystick stubs
 *
 * Covers winmm.dll exports used by games: timeGetTime, waveOut*,
 * midiOut*, joyGet*, PlaySound, mciSendString.
 * Audio output is silently dropped; timers use CLOCK_MONOTONIC.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/dll_common.h"

/* Multimedia error codes */
#define MMSYSERR_NOERROR    0
#define MMSYSERR_ERROR      1
#define TIMERR_NOERROR      0
#define JOYERR_PARMS        165

/* TIMECAPS structure layout */
typedef struct {
    UINT wPeriodMin;
    UINT wPeriodMax;
} TIMECAPS;

/* Minimal WAVEOUTCAPSA structure (enough to satisfy callers) */
typedef struct {
    WORD  wMid;
    WORD  wPid;
    DWORD vDriverVersion;
    CHAR  szPname[32];
    DWORD dwFormats;
    WORD  wChannels;
    WORD  wReserved1;
    DWORD dwSupport;
} WAVEOUTCAPSA;

/* Common format flags */
#define WAVE_FORMAT_1M08    0x00000001  /* 11.025 kHz, Mono, 8-bit */
#define WAVE_FORMAT_1S08    0x00000002  /* 11.025 kHz, Stereo, 8-bit */
#define WAVE_FORMAT_1M16    0x00000004  /* 11.025 kHz, Mono, 16-bit */
#define WAVE_FORMAT_1S16    0x00000008  /* 11.025 kHz, Stereo, 16-bit */
#define WAVE_FORMAT_2M08    0x00000010  /* 22.05 kHz, Mono, 8-bit */
#define WAVE_FORMAT_2S08    0x00000020  /* 22.05 kHz, Stereo, 8-bit */
#define WAVE_FORMAT_2M16    0x00000040  /* 22.05 kHz, Mono, 16-bit */
#define WAVE_FORMAT_2S16    0x00000080  /* 22.05 kHz, Stereo, 16-bit */
#define WAVE_FORMAT_4M08    0x00000100  /* 44.1 kHz, Mono, 8-bit */
#define WAVE_FORMAT_4S08    0x00000200  /* 44.1 kHz, Stereo, 8-bit */
#define WAVE_FORMAT_4M16    0x00000400  /* 44.1 kHz, Mono, 16-bit */
#define WAVE_FORMAT_4S16    0x00000800  /* 44.1 kHz, Stereo, 16-bit */

/* ------------------------------------------------------------------ */
/*  Timer functions                                                   */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT DWORD timeGetTime(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    DWORD ms = (DWORD)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
#ifdef PE_TRACE_WINMM
    fprintf(stderr, "[winmm] timeGetTime() -> %u\n", (unsigned)ms);
#endif
    return ms;
}

WINAPI_EXPORT UINT timeBeginPeriod(UINT period)
{
    fprintf(stderr, "[winmm] timeBeginPeriod(%u)\n", period);
    return TIMERR_NOERROR;
}

WINAPI_EXPORT UINT timeEndPeriod(UINT period)
{
    fprintf(stderr, "[winmm] timeEndPeriod(%u)\n", period);
    return TIMERR_NOERROR;
}

WINAPI_EXPORT UINT timeGetDevCaps(void *caps, UINT size)
{
    fprintf(stderr, "[winmm] timeGetDevCaps(%p, %u)\n", caps, size);

    if (!caps || size < sizeof(TIMECAPS))
        return MMSYSERR_ERROR;

    TIMECAPS *tc = (TIMECAPS *)caps;
    tc->wPeriodMin = 1;     /* 1 ms minimum */
    tc->wPeriodMax = 1000;  /* 1000 ms maximum */
    return TIMERR_NOERROR;
}

/* ------------------------------------------------------------------ */
/*  Wave audio output functions                                       */
/* ------------------------------------------------------------------ */

/*
 * WAVEHDR - waveform-audio buffer header.
 * The dwFlags field MUST be updated by waveOutWrite/waveOutPrepareHeader
 * or callers that poll for WHDR_DONE will spin forever.
 */
#define WHDR_DONE       0x00000001
#define WHDR_PREPARED   0x00000002
#define WHDR_BEGINLOOP  0x00000004
#define WHDR_ENDLOOP    0x00000008
#define WHDR_INQUEUE    0x00000010

typedef struct {
    LPSTR  lpData;
    DWORD  dwBufferLength;
    DWORD  dwBytesRecorded;
    DWORD  dwUser;          /* caller-defined */
    DWORD  dwFlags;
    DWORD  dwLoops;
    void  *lpNext;          /* reserved */
    DWORD  reserved;
} WAVEHDR;

/* MMTIME structure for waveOutGetPosition */
#define TIME_MS         0x0001
#define TIME_SAMPLES    0x0002
#define TIME_BYTES      0x0004

typedef struct {
    UINT wType;
    union {
        DWORD ms;
        DWORD sample;
        DWORD cb;
    } u;
} MMTIME;

/* Fake handle value for opened wave devices */
static HANDLE winmm_fake_waveout = (HANDLE)(uintptr_t)0xAA001000;

WINAPI_EXPORT UINT waveOutGetNumDevs(void)
{
    fprintf(stderr, "[winmm] waveOutGetNumDevs() -> 1\n");
    return 1;
}

WINAPI_EXPORT UINT waveOutGetDevCapsA(UINT id, void *caps, UINT size)
{
    fprintf(stderr, "[winmm] waveOutGetDevCapsA(%u, %p, %u)\n", id, caps, size);

    if (!caps || size < sizeof(WAVEOUTCAPSA))
        return MMSYSERR_ERROR;

    WAVEOUTCAPSA *woc = (WAVEOUTCAPSA *)caps;
    memset(woc, 0, sizeof(WAVEOUTCAPSA));
    woc->wMid = 1;                    /* Manufacturer ID */
    woc->wPid = 1;                    /* Product ID */
    woc->vDriverVersion = 0x0100;     /* Version 1.0 */
    strncpy(woc->szPname, "PE-Compat Audio", sizeof(woc->szPname) - 1);
    woc->dwFormats = WAVE_FORMAT_1M08 | WAVE_FORMAT_1S08 |
                     WAVE_FORMAT_1M16 | WAVE_FORMAT_1S16 |
                     WAVE_FORMAT_2M08 | WAVE_FORMAT_2S08 |
                     WAVE_FORMAT_2M16 | WAVE_FORMAT_2S16 |
                     WAVE_FORMAT_4M08 | WAVE_FORMAT_4S08 |
                     WAVE_FORMAT_4M16 | WAVE_FORMAT_4S16;
    woc->wChannels = 2;
    woc->dwSupport = 0;
    return MMSYSERR_NOERROR;
}

WINAPI_EXPORT UINT waveOutOpen(HANDLE *hwo, UINT id, void *format,
                               DWORD callback, DWORD instance, DWORD flags)
{
    fprintf(stderr, "[winmm] waveOutOpen(%p, %u, %p, 0x%x, 0x%x, 0x%x)\n",
            (void *)hwo, id, format, (unsigned)callback,
            (unsigned)instance, (unsigned)flags);

    if (hwo)
        *hwo = winmm_fake_waveout;

    return MMSYSERR_NOERROR;
}

WINAPI_EXPORT UINT waveOutClose(HANDLE hwo)
{
    fprintf(stderr, "[winmm] waveOutClose(%p)\n", hwo);
    return MMSYSERR_NOERROR;
}

WINAPI_EXPORT UINT waveOutWrite(HANDLE hwo, void *hdr, UINT size)
{
    fprintf(stderr, "[winmm] waveOutWrite(%p, %p, %u) [audio dropped]\n",
            hwo, hdr, size);

    /*
     * BUG FIX: callers poll WAVEHDR.dwFlags for WHDR_DONE to know when
     * the buffer has been consumed.  Without setting this flag the caller
     * spins forever in a busy-wait loop waiting for playback completion.
     */
    if (hdr && size >= sizeof(WAVEHDR)) {
        WAVEHDR *wh = (WAVEHDR *)hdr;
        wh->dwFlags &= ~WHDR_INQUEUE;
        wh->dwFlags |= WHDR_DONE;
    }

    return MMSYSERR_NOERROR;
}

WINAPI_EXPORT UINT waveOutReset(HANDLE hwo)
{
    fprintf(stderr, "[winmm] waveOutReset(%p)\n", hwo);
    return MMSYSERR_NOERROR;
}

WINAPI_EXPORT UINT waveOutPrepareHeader(HANDLE hwo, void *hdr, UINT size)
{
    fprintf(stderr, "[winmm] waveOutPrepareHeader(%p, %p, %u)\n",
            hwo, hdr, size);

    /* Mark the header as prepared so the app knows it can submit it */
    if (hdr && size >= sizeof(WAVEHDR)) {
        WAVEHDR *wh = (WAVEHDR *)hdr;
        wh->dwFlags |= WHDR_PREPARED;
    }

    return MMSYSERR_NOERROR;
}

WINAPI_EXPORT UINT waveOutUnprepareHeader(HANDLE hwo, void *hdr, UINT size)
{
    fprintf(stderr, "[winmm] waveOutUnprepareHeader(%p, %p, %u)\n",
            hwo, hdr, size);

    if (hdr && size >= sizeof(WAVEHDR)) {
        WAVEHDR *wh = (WAVEHDR *)hdr;
        wh->dwFlags &= ~WHDR_PREPARED;
    }

    return MMSYSERR_NOERROR;
}

WINAPI_EXPORT UINT waveOutGetVolume(HANDLE hwo, DWORD *volume)
{
    (void)hwo;
    fprintf(stderr, "[winmm] waveOutGetVolume(%p, %p)\n", hwo, (void *)volume);
    if (volume)
        *volume = 0xFFFFFFFF;  /* both channels at full volume */
    return MMSYSERR_NOERROR;
}

WINAPI_EXPORT UINT waveOutSetVolume(HANDLE hwo, DWORD volume)
{
    (void)hwo;
    fprintf(stderr, "[winmm] waveOutSetVolume(%p, 0x%x)\n", hwo, (unsigned)volume);
    return MMSYSERR_NOERROR;
}

WINAPI_EXPORT UINT waveOutGetPosition(HANDLE hwo, void *mmt, UINT size)
{
    (void)hwo;
    fprintf(stderr, "[winmm] waveOutGetPosition(%p, %p, %u)\n", hwo, mmt, size);

    if (!mmt || size < sizeof(MMTIME))
        return MMSYSERR_ERROR;

    MMTIME *mm = (MMTIME *)mmt;
    /* Return 0 bytes played -- audio is being silently dropped */
    mm->wType = TIME_BYTES;
    mm->u.cb = 0;
    return MMSYSERR_NOERROR;
}

WINAPI_EXPORT UINT waveOutPause(HANDLE hwo)
{
    fprintf(stderr, "[winmm] waveOutPause(%p)\n", hwo);
    return MMSYSERR_NOERROR;
}

WINAPI_EXPORT UINT waveOutRestart(HANDLE hwo)
{
    fprintf(stderr, "[winmm] waveOutRestart(%p)\n", hwo);
    return MMSYSERR_NOERROR;
}

/* ------------------------------------------------------------------ */
/*  MIDI output                                                       */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT UINT midiOutGetNumDevs(void)
{
    fprintf(stderr, "[winmm] midiOutGetNumDevs() -> 0\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Joystick functions                                                */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT UINT joyGetNumDevs(void)
{
    fprintf(stderr, "[winmm] joyGetNumDevs() -> 0\n");
    return 0;
}

WINAPI_EXPORT UINT joyGetDevCapsA(UINT id, void *caps, UINT size)
{
    fprintf(stderr, "[winmm] joyGetDevCapsA(%u, %p, %u) -> JOYERR_PARMS\n",
            id, caps, size);
    return JOYERR_PARMS;
}

WINAPI_EXPORT UINT joyGetPosEx(UINT id, void *info)
{
    fprintf(stderr, "[winmm] joyGetPosEx(%u, %p) -> JOYERR_PARMS\n", id, info);
    return JOYERR_PARMS;
}

/* ------------------------------------------------------------------ */
/*  PlaySound / mciSendString                                         */
/* ------------------------------------------------------------------ */

WINAPI_EXPORT BOOL PlaySoundA(LPCSTR sound, HANDLE module, DWORD flags)
{
    fprintf(stderr, "[winmm] PlaySoundA(\"%s\", %p, 0x%x) -> TRUE [silent]\n",
            sound ? sound : "(null)", module, (unsigned)flags);
    return TRUE;
}

WINAPI_EXPORT DWORD mciSendStringA(LPCSTR cmd, LPSTR ret, UINT retLen,
                                   HANDLE callback)
{
    fprintf(stderr, "[winmm] mciSendStringA(\"%s\", %p, %u, %p) -> 0\n",
            cmd ? cmd : "(null)", ret, retLen, callback);

    /* Clear return buffer if provided */
    if (ret && retLen > 0)
        ret[0] = '\0';

    return 0;
}
