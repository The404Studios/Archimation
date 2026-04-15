/*
 * dsound_audio.c - DirectSound via PulseAudio/PipeWire
 *
 * Real audio output using PulseAudio simple API (works on PipeWire too).
 * Implements IDirectSound8, IDirectSoundBuffer with real PCM playback
 * through a pthread-driven circular buffer feeding pa_simple_write().
 *
 * ALL exported functions use WINAPI_EXPORT (__attribute__((ms_abi, visibility("default"))))
 * ALL COM vtable function pointers AND their implementations use __attribute__((ms_abi))
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <pthread.h>
#include <dlfcn.h>
#include <unistd.h>

#include "common/dll_common.h"

/* ================================================================== */
/*  DirectSound constants                                              */
/* ================================================================== */

/* HRESULT codes */
#define DS_OK                   ((HRESULT)0x00000000)
#define DS_NO_VIRTUALIZATION    ((HRESULT)0x0878000A)
#define DSERR_ALLOCATED         ((HRESULT)0x8878000A)
#define DSERR_CONTROLUNAVAIL    ((HRESULT)0x8878001E)
#define DSERR_INVALIDPARAM      ((HRESULT)0x80070057)
#define DSERR_INVALIDCALL       ((HRESULT)0x88780032)
#define DSERR_GENERIC           ((HRESULT)0x80004005)
#define DSERR_PRIOLEVELNEEDED   ((HRESULT)0x88780046)
#define DSERR_OUTOFMEMORY       ((HRESULT)0x8007000E)
#define DSERR_BADFORMAT         ((HRESULT)0x88780064)
#define DSERR_UNSUPPORTED       ((HRESULT)0x80004001)
#define DSERR_NODRIVER          ((HRESULT)0x88780078)
#define DSERR_ALREADYINITIALIZED ((HRESULT)0x88780082)
#define DSERR_BUFFERLOST        ((HRESULT)0x88780096)
#define E_NOINTERFACE           ((HRESULT)0x80004002)
#define E_NOTIMPL               ((HRESULT)0x80004001)
#define S_FALSE                 ((HRESULT)0x00000001)

/* DSBCAPS flags */
#define DSBCAPS_PRIMARYBUFFER       0x00000001
#define DSBCAPS_STATIC              0x00000002
#define DSBCAPS_LOCHARDWARE         0x00000004
#define DSBCAPS_LOCSOFTWARE         0x00000008
#define DSBCAPS_CTRLFREQUENCY       0x00000020
#define DSBCAPS_CTRLPAN             0x00000040
#define DSBCAPS_CTRLVOLUME          0x00000080
#define DSBCAPS_CTRLPOSITIONNOTIFY  0x00000100
#define DSBCAPS_GLOBALFOCUS         0x00008000
#define DSBCAPS_GETCURRENTPOSITION2 0x00010000
#define DSBCAPS_STICKYFOCUS         0x00004000
#define DSBCAPS_TRUEPLAYPOSITION    0x00080000

/* DSBPLAY flags */
#define DSBPLAY_LOOPING             0x00000001

/* DSBSTATUS flags */
#define DSBSTATUS_PLAYING           0x00000001
#define DSBSTATUS_BUFFERLOST        0x00000002
#define DSBSTATUS_LOOPING           0x00000004

/* DSBLOCK flags */
#define DSBLOCK_FROMWRITECURSOR     0x00000001
#define DSBLOCK_ENTIREBUFFER        0x00000002

/* Cooperative levels */
#define DSSCL_NORMAL                1
#define DSSCL_PRIORITY              2
#define DSSCL_EXCLUSIVE             3
#define DSSCL_WRITEPRIMARY          4

/* Speaker config */
#define DSSPEAKER_DIRECTOUT         0x00000000
#define DSSPEAKER_HEADPHONE         0x00000001
#define DSSPEAKER_MONO              0x00000002
#define DSSPEAKER_QUAD              0x00000003
#define DSSPEAKER_STEREO            0x00000004
#define DSSPEAKER_SURROUND          0x00000005
#define DSSPEAKER_5POINT1           0x00000006
#define DSSPEAKER_7POINT1           0x00000007

/* WAVE format tags */
#define WAVE_FORMAT_PCM             1
#define WAVE_FORMAT_IEEE_FLOAT      3

/* ================================================================== */
/*  PulseAudio simple API (loaded at runtime via dlopen)               */
/* ================================================================== */

/* pa_sample_format_t values */
#define PA_SAMPLE_U8            0
#define PA_SAMPLE_ALAW          1
#define PA_SAMPLE_ULAW          2
#define PA_SAMPLE_S16LE         3
#define PA_SAMPLE_S16BE         4
#define PA_SAMPLE_FLOAT32LE     5
#define PA_SAMPLE_FLOAT32BE     6
#define PA_SAMPLE_S32LE         7
#define PA_SAMPLE_S32BE         8
#define PA_SAMPLE_S24LE         9
#define PA_SAMPLE_S24BE         10
#define PA_SAMPLE_S24_32LE      11
#define PA_SAMPLE_S24_32BE      12

/* pa_stream_direction_t */
#define PA_STREAM_NODIRECTION   0
#define PA_STREAM_PLAYBACK      1
#define PA_STREAM_RECORD        2
#define PA_STREAM_UPLOAD        3

typedef struct {
    int      format;    /* pa_sample_format_t */
    uint32_t rate;
    uint8_t  channels;
} pa_sample_spec;

typedef void pa_simple;
typedef uint64_t pa_usec_t;

/* Function pointer types for dlsym */
typedef pa_simple *(*pa_simple_new_fn)(
    const char *server, const char *name, int dir, const char *dev,
    const char *stream_name, const pa_sample_spec *ss,
    void *channel_map, void *attr, int *error);
typedef void        (*pa_simple_free_fn)(pa_simple *s);
typedef int         (*pa_simple_write_fn)(pa_simple *s, const void *data,
                                          size_t bytes, int *error);
typedef int         (*pa_simple_drain_fn)(pa_simple *s, int *error);
typedef int         (*pa_simple_flush_fn)(pa_simple *s, int *error);
typedef pa_usec_t   (*pa_simple_get_latency_fn)(pa_simple *s, int *error);
typedef const char *(*pa_strerror_fn)(int error);

/* Global PulseAudio state */
static void *g_pulse_lib           = NULL;
static int   g_pulse_init_tried    = 0;

static pa_simple_new_fn         p_pa_simple_new         = NULL;
static pa_simple_free_fn        p_pa_simple_free        = NULL;
static pa_simple_write_fn       p_pa_simple_write       = NULL;
static pa_simple_drain_fn       p_pa_simple_drain       = NULL;
static pa_simple_flush_fn       p_pa_simple_flush       = NULL;
static pa_simple_get_latency_fn p_pa_simple_get_latency = NULL;
static pa_strerror_fn           p_pa_strerror           = NULL;

/*
 * Load PulseAudio simple API via dlopen.
 * Returns 0 on success, -1 if PulseAudio is unavailable.
 * Graceful fallback: audio will be silent if PA is missing.
 */
static int pulse_load(void)
{
    if (g_pulse_init_tried)
        return g_pulse_lib ? 0 : -1;
    g_pulse_init_tried = 1;

    const char *libs[] = {
        "libpulse-simple.so.0",
        "libpulse-simple.so",
        NULL
    };

    for (int i = 0; libs[i]; i++) {
        g_pulse_lib = dlopen(libs[i], RTLD_NOW);
        if (g_pulse_lib) break;
    }

    if (!g_pulse_lib) {
        fprintf(stderr, "[dsound] PulseAudio not found - audio will be silent\n");
        return -1;
    }

    p_pa_simple_new         = (pa_simple_new_fn)dlsym(g_pulse_lib, "pa_simple_new");
    p_pa_simple_free        = (pa_simple_free_fn)dlsym(g_pulse_lib, "pa_simple_free");
    p_pa_simple_write       = (pa_simple_write_fn)dlsym(g_pulse_lib, "pa_simple_write");
    p_pa_simple_drain       = (pa_simple_drain_fn)dlsym(g_pulse_lib, "pa_simple_drain");
    p_pa_simple_flush       = (pa_simple_flush_fn)dlsym(g_pulse_lib, "pa_simple_flush");
    p_pa_simple_get_latency = (pa_simple_get_latency_fn)dlsym(g_pulse_lib, "pa_simple_get_latency");
    p_pa_strerror           = (pa_strerror_fn)dlsym(g_pulse_lib, "pa_strerror");

    if (!p_pa_simple_new || !p_pa_simple_write || !p_pa_simple_free) {
        fprintf(stderr, "[dsound] PulseAudio missing required functions\n");
        dlclose(g_pulse_lib);
        g_pulse_lib = NULL;
        return -1;
    }

    fprintf(stderr, "[dsound] PulseAudio loaded successfully\n");
    return 0;
}

/* ================================================================== */
/*  WAVEFORMATEX                                                       */
/* ================================================================== */

typedef struct {
    uint16_t wFormatTag;       /* 1 = PCM, 3 = IEEE_FLOAT */
    uint16_t nChannels;
    uint32_t nSamplesPerSec;
    uint32_t nAvgBytesPerSec;
    uint16_t nBlockAlign;
    uint16_t wBitsPerSample;
    uint16_t cbSize;
} WAVEFORMATEX;

/* ================================================================== */
/*  DSBUFFERDESC                                                       */
/* ================================================================== */

typedef struct {
    DWORD        dwSize;
    DWORD        dwFlags;
    DWORD        dwBufferBytes;
    DWORD        dwReserved;
    WAVEFORMATEX *lpwfxFormat;
    GUID         guid3DAlgorithm;
} DSBUFFERDESC;

/* ================================================================== */
/*  DSBCAPS (returned by GetCaps)                                      */
/* ================================================================== */

typedef struct {
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwBufferBytes;
    DWORD dwUnlockTransferRate;
    DWORD dwPlayCpuOverhead;
} DSBCAPS;

/* ================================================================== */
/*  DSCAPS (IDirectSound::GetCaps)                                     */
/* ================================================================== */

typedef struct {
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwMinSecondarySampleRate;
    DWORD dwMaxSecondarySampleRate;
    DWORD dwPrimaryBuffers;
    DWORD dwMaxHwMixingAllBuffers;
    DWORD dwMaxHwMixingStaticBuffers;
    DWORD dwMaxHwMixingStreamingBuffers;
    DWORD dwFreeHwMixingAllBuffers;
    DWORD dwFreeHwMixingStaticBuffers;
    DWORD dwFreeHwMixingStreamingBuffers;
    DWORD dwMaxHw3DAllBuffers;
    DWORD dwMaxHw3DStaticBuffers;
    DWORD dwMaxHw3DStreamingBuffers;
    DWORD dwFreeHw3DAllBuffers;
    DWORD dwFreeHw3DStaticBuffers;
    DWORD dwFreeHw3DStreamingBuffers;
    DWORD dwTotalHwMemBytes;
    DWORD dwFreeHwMemBytes;
    DWORD dwMaxContigFreeHwMemBytes;
    DWORD dwUnlockTransferRateHwBuffers;
    DWORD dwPlayCpuOverheadSwBuffers;
    DWORD dwReserved1;
    DWORD dwReserved2;
} DSCAPS;

/* ================================================================== */
/*  Volume conversion helpers                                          */
/* ================================================================== */

/*
 * Convert DirectSound centibels (-10000..0) to linear amplitude (0.0..1.0).
 * DS uses hundredths of a decibel: -10000 = silence, 0 = full volume.
 * Formula: linear = 10^(centibels / 2000)
 */
static float ds_volume_to_linear(LONG centibels)
{
    if (centibels <= -10000) return 0.0f;
    if (centibels >= 0) return 1.0f;
    return powf(10.0f, (float)centibels / 2000.0f);
}

/* ================================================================== */
/*  Forward declarations                                               */
/* ================================================================== */

typedef struct IDirectSoundBuffer  IDirectSoundBuffer;
typedef struct IDirectSound8       IDirectSound8;

static IDirectSoundBuffer *create_dsbuffer(const DSBUFFERDESC *desc);
static void dsbuf_destroy_pa_stream(IDirectSoundBuffer *buf);
static int  dsbuf_create_pa_stream(IDirectSoundBuffer *buf);

/* ================================================================== */
/*  IDirectSoundBuffer COM vtable                                      */
/* ================================================================== */

typedef struct {
    /* IUnknown */
    HRESULT  (__attribute__((ms_abi)) *QueryInterface)(IDirectSoundBuffer *self, const void *riid, void **ppv);
    uint32_t (__attribute__((ms_abi)) *AddRef)(IDirectSoundBuffer *self);
    uint32_t (__attribute__((ms_abi)) *Release)(IDirectSoundBuffer *self);
    /* IDirectSoundBuffer */
    HRESULT  (__attribute__((ms_abi)) *GetCaps)(IDirectSoundBuffer *self, DSBCAPS *caps);
    HRESULT  (__attribute__((ms_abi)) *GetCurrentPosition)(IDirectSoundBuffer *self, DWORD *play_cursor, DWORD *write_cursor);
    HRESULT  (__attribute__((ms_abi)) *GetFormat)(IDirectSoundBuffer *self, WAVEFORMATEX *fmt, DWORD size_allocated, DWORD *size_written);
    HRESULT  (__attribute__((ms_abi)) *GetVolume)(IDirectSoundBuffer *self, LONG *volume);
    HRESULT  (__attribute__((ms_abi)) *GetPan)(IDirectSoundBuffer *self, LONG *pan);
    HRESULT  (__attribute__((ms_abi)) *GetFrequency)(IDirectSoundBuffer *self, DWORD *freq);
    HRESULT  (__attribute__((ms_abi)) *GetStatus)(IDirectSoundBuffer *self, DWORD *status);
    HRESULT  (__attribute__((ms_abi)) *Initialize)(IDirectSoundBuffer *self, void *ds, const DSBUFFERDESC *desc);
    HRESULT  (__attribute__((ms_abi)) *Lock)(IDirectSoundBuffer *self, DWORD offset, DWORD bytes, void **ptr1, DWORD *len1, void **ptr2, DWORD *len2, DWORD flags);
    HRESULT  (__attribute__((ms_abi)) *Play)(IDirectSoundBuffer *self, DWORD reserved1, DWORD reserved2, DWORD flags);
    HRESULT  (__attribute__((ms_abi)) *SetCurrentPosition)(IDirectSoundBuffer *self, DWORD new_pos);
    HRESULT  (__attribute__((ms_abi)) *SetFormat)(IDirectSoundBuffer *self, const WAVEFORMATEX *fmt);
    HRESULT  (__attribute__((ms_abi)) *SetVolume)(IDirectSoundBuffer *self, LONG volume);
    HRESULT  (__attribute__((ms_abi)) *SetPan)(IDirectSoundBuffer *self, LONG pan);
    HRESULT  (__attribute__((ms_abi)) *SetFrequency)(IDirectSoundBuffer *self, DWORD freq);
    HRESULT  (__attribute__((ms_abi)) *Stop)(IDirectSoundBuffer *self);
    HRESULT  (__attribute__((ms_abi)) *Unlock)(IDirectSoundBuffer *self, void *ptr1, DWORD len1, void *ptr2, DWORD len2);
    HRESULT  (__attribute__((ms_abi)) *Restore)(IDirectSoundBuffer *self);
} IDirectSoundBufferVtbl;

struct IDirectSoundBuffer {
    const IDirectSoundBufferVtbl *lpVtbl;
    volatile int ref_count;

    /* PCM circular buffer */
    uint8_t  *pcm_data;
    DWORD     pcm_size;        /* total buffer size in bytes */
    DWORD     play_cursor;     /* read position (consumed by PA thread) */
    DWORD     write_cursor;    /* write position (advanced by app via Lock/Unlock) */

    /* Audio format */
    WAVEFORMATEX fmt;
    int       is_primary;

    /* Playback state */
    volatile int playing;
    volatile int looping;
    LONG      volume;          /* -10000..0 centibels */
    LONG      pan;             /* -10000..10000 */
    DWORD     flags;           /* DSBCAPS flags from creation */

    /* PulseAudio stream handle */
    pa_simple *pa_stream;

    /* Playback thread */
    pthread_t       play_thread;
    volatile int    thread_running;
    int             thread_created;  /* nonzero if pthread_create succeeded */
    pthread_mutex_t lock;
};

/* ================================================================== */
/*  PulseAudio stream management                                       */
/* ================================================================== */

/*
 * Map WAVEFORMATEX to pa_sample_spec.
 */
static void wfx_to_pa_spec(const WAVEFORMATEX *wfx, pa_sample_spec *ss)
{
    ss->rate     = wfx->nSamplesPerSec;
    ss->channels = (uint8_t)wfx->nChannels;

    if (wfx->wFormatTag == WAVE_FORMAT_IEEE_FLOAT) {
        ss->format = PA_SAMPLE_FLOAT32LE;
    } else {
        /* PCM */
        switch (wfx->wBitsPerSample) {
        case 8:  ss->format = PA_SAMPLE_U8;        break;
        case 32: ss->format = PA_SAMPLE_S32LE;     break;
        case 24: ss->format = PA_SAMPLE_S24LE;     break;
        case 16:
        default: ss->format = PA_SAMPLE_S16LE;     break;
        }
    }
}

/*
 * Create a PulseAudio playback stream for a buffer.
 * Returns 0 on success, -1 on failure.
 */
static int dsbuf_create_pa_stream(IDirectSoundBuffer *buf)
{
    if (!g_pulse_lib || !p_pa_simple_new)
        return -1;

    if (buf->pa_stream)
        return 0; /* already exists */

    pa_sample_spec ss;
    wfx_to_pa_spec(&buf->fmt, &ss);

    int pa_err = 0;
    buf->pa_stream = p_pa_simple_new(
        NULL,               /* default server */
        "PELoader",         /* application name */
        PA_STREAM_PLAYBACK,
        NULL,               /* default device */
        "DirectSound",      /* stream description */
        &ss,
        NULL,               /* default channel map */
        NULL,               /* default buffering attributes */
        &pa_err
    );

    if (!buf->pa_stream) {
        fprintf(stderr, "[dsound] pa_simple_new failed: %s\n",
                p_pa_strerror ? p_pa_strerror(pa_err) : "unknown error");
        return -1;
    }

    return 0;
}

/*
 * Destroy a PulseAudio stream, draining first if possible.
 */
static void dsbuf_destroy_pa_stream(IDirectSoundBuffer *buf)
{
    if (!buf->pa_stream)
        return;

    if (p_pa_simple_drain) {
        int err = 0;
        p_pa_simple_drain(buf->pa_stream, &err);
    }

    if (p_pa_simple_free)
        p_pa_simple_free(buf->pa_stream);

    buf->pa_stream = NULL;
}

/* ================================================================== */
/*  Playback thread                                                    */
/* ================================================================== */

/*
 * Apply volume scaling to a chunk of PCM data in-place.
 * Supports 8-bit unsigned, 16-bit signed LE, 32-bit float LE.
 */
static void apply_volume(uint8_t *data, size_t bytes,
                         const WAVEFORMATEX *fmt, float vol)
{
    if (vol >= 0.99f)
        return; /* full volume, nothing to do */

    if (fmt->wFormatTag == WAVE_FORMAT_IEEE_FLOAT && fmt->wBitsPerSample == 32) {
        float *samples = (float *)data;
        size_t n = bytes / sizeof(float);
        for (size_t i = 0; i < n; i++)
            samples[i] *= vol;
    } else if (fmt->wBitsPerSample == 16) {
        int16_t *samples = (int16_t *)data;
        size_t n = bytes / sizeof(int16_t);
        for (size_t i = 0; i < n; i++)
            samples[i] = (int16_t)((float)samples[i] * vol);
    } else if (fmt->wBitsPerSample == 8) {
        /* 8-bit PCM is unsigned with 128 as center */
        for (size_t i = 0; i < bytes; i++) {
            float s = ((float)data[i] - 128.0f) * vol;
            int v = (int)(s + 128.0f);
            if (v < 0) v = 0;
            if (v > 255) v = 255;
            data[i] = (uint8_t)v;
        }
    }
    /* For other formats, skip volume scaling (rare edge cases) */
}

/*
 * Playback thread: reads from circular buffer, writes to PulseAudio.
 *
 * Runs in a loop writing small chunks (10ms worth) to the PA stream.
 * For looping buffers, wraps around to the beginning when reaching the end.
 * For non-looping buffers, stops when play_cursor catches up to write_cursor.
 */
static void *dsound_playback_thread(void *arg)
{
    IDirectSoundBuffer *buf = (IDirectSoundBuffer *)arg;

    /* Calculate chunk size: ~10ms of audio */
    const int chunk_ms = 10;
    size_t chunk_bytes = ((size_t)buf->fmt.nAvgBytesPerSec * chunk_ms) / 1000;
    /* Align chunk to block boundary */
    if (buf->fmt.nBlockAlign > 0)
        chunk_bytes = (chunk_bytes / buf->fmt.nBlockAlign) * buf->fmt.nBlockAlign;
    if (chunk_bytes == 0)
        chunk_bytes = 1024;

    uint8_t *tmp = malloc(chunk_bytes);
    if (!tmp) {
        fprintf(stderr, "[dsound] playback thread: malloc failed\n");
        return NULL;
    }

    while (buf->thread_running && buf->playing) {
        pthread_mutex_lock(&buf->lock);

        DWORD pc = buf->play_cursor;
        DWORD wc = buf->write_cursor;
        DWORD sz = buf->pcm_size;

        /* Calculate available data in circular buffer */
        DWORD avail;
        if (wc >= pc) {
            avail = wc - pc;
        } else {
            avail = sz - pc + wc;
        }

        if (avail == 0) {
            if (buf->looping) {
                /*
                 * Looping buffer with no new data written by the app:
                 * The entire buffer is the content. Replay from current
                 * play_cursor position, wrapping around the full buffer.
                 */
                avail = sz;
            } else {
                /* Non-looping, no data available: wait for more data */
                pthread_mutex_unlock(&buf->lock);
                usleep(1000); /* 1ms sleep to avoid busy-wait */
                continue;
            }
        }

        /* Determine how much to read this iteration */
        size_t to_read = (avail < (DWORD)chunk_bytes) ? avail : chunk_bytes;

        /* Copy from circular buffer, handling wrap-around */
        DWORD pos = pc;
        for (size_t i = 0; i < to_read; i++) {
            tmp[i] = buf->pcm_data[pos];
            pos++;
            if (pos >= sz) pos = 0;
        }

        /* Advance play cursor */
        buf->play_cursor = pos;

        /* Snapshot volume for this chunk */
        float vol = ds_volume_to_linear(buf->volume);
        WAVEFORMATEX fmt_copy = buf->fmt;

        pthread_mutex_unlock(&buf->lock);

        /* Apply volume scaling to the copied chunk */
        apply_volume(tmp, to_read, &fmt_copy, vol);

        /* Write to PulseAudio */
        if (buf->pa_stream && p_pa_simple_write && to_read > 0) {
            int pa_err = 0;
            int ret = p_pa_simple_write(buf->pa_stream, tmp, to_read, &pa_err);
            if (ret < 0) {
                fprintf(stderr, "[dsound] pa_simple_write error: %s\n",
                        p_pa_strerror ? p_pa_strerror(pa_err) : "unknown");
                /* Don't break - keep trying */
            }
        }

        /* Sleep for roughly half the chunk duration to stay ahead */
        usleep((unsigned int)(chunk_ms * 500));
    }

    /* If non-looping playback ended naturally, mark as stopped */
    buf->playing = 0;

    free(tmp);
    return NULL;
}

/*
 * Start the playback thread if not already running.
 */
static int dsbuf_start_thread(IDirectSoundBuffer *buf)
{
    if (buf->thread_running)
        return 0;

    buf->thread_running = 1;
    int ret = pthread_create(&buf->play_thread, NULL, dsound_playback_thread, buf);
    if (ret != 0) {
        fprintf(stderr, "[dsound] pthread_create failed: %d\n", ret);
        buf->thread_running = 0;
        return -1;
    }
    buf->thread_created = 1;
    return 0;
}

/*
 * Stop and join the playback thread.
 */
static void dsbuf_stop_thread(IDirectSoundBuffer *buf)
{
    if (!buf->thread_running)
        return;

    buf->thread_running = 0;

    if (buf->thread_created) {
        pthread_join(buf->play_thread, NULL);
        buf->thread_created = 0;
    }
}

/* ================================================================== */
/*  IDirectSoundBuffer method implementations                          */
/* ================================================================== */

static const unsigned char IID_IUnknown_bytes[16] = {
    0x00,0x00,0x00,0x00, 0x00,0x00, 0x00,0x00,
    0xC0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46
};

static __attribute__((ms_abi))
HRESULT dsbuf_QueryInterface(IDirectSoundBuffer *self, const void *riid, void **ppv)
{
    if (!ppv)
        return DSERR_INVALIDPARAM;

    *ppv = NULL;
    if (!riid || memcmp(riid, IID_IUnknown_bytes, 16) == 0) {
        *ppv = self;
        __sync_add_and_fetch(&self->ref_count, 1);
        return DS_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi))
uint32_t dsbuf_AddRef(IDirectSoundBuffer *self)
{
    return (uint32_t)__sync_add_and_fetch(&self->ref_count, 1);
}

static __attribute__((ms_abi))
uint32_t dsbuf_Release(IDirectSoundBuffer *self)
{
    int ref = __sync_sub_and_fetch(&self->ref_count, 1);
    if (ref <= 0) {
        /* Stop playback and clean up */
        self->playing = 0;
        dsbuf_stop_thread(self);
        dsbuf_destroy_pa_stream(self);
        pthread_mutex_destroy(&self->lock);
        free(self->pcm_data);
        free(self);
        return 0;
    }
    return (uint32_t)ref;
}

static __attribute__((ms_abi))
HRESULT dsbuf_GetCaps(IDirectSoundBuffer *self, DSBCAPS *caps)
{
    if (!caps)
        return DSERR_INVALIDPARAM;

    /* Respect dwSize to avoid overwrite if caller passes smaller struct */
    memset(caps, 0, sizeof(DSBCAPS));
    caps->dwSize = sizeof(DSBCAPS);
    caps->dwFlags = self->is_primary
        ? DSBCAPS_PRIMARYBUFFER
        : (self->flags & (DSBCAPS_CTRLVOLUME | DSBCAPS_CTRLPAN |
                          DSBCAPS_CTRLFREQUENCY | DSBCAPS_LOCSOFTWARE |
                          DSBCAPS_GLOBALFOCUS | DSBCAPS_GETCURRENTPOSITION2));
    if (!self->is_primary)
        caps->dwFlags |= DSBCAPS_LOCSOFTWARE;
    caps->dwBufferBytes = self->pcm_size;
    caps->dwUnlockTransferRate = 0;
    caps->dwPlayCpuOverhead = 0;
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_GetCurrentPosition(IDirectSoundBuffer *self, DWORD *play_cursor, DWORD *write_cursor)
{
    pthread_mutex_lock(&self->lock);
    if (play_cursor)
        *play_cursor = self->play_cursor;
    if (write_cursor) {
        /*
         * The write cursor is typically slightly ahead of the play cursor.
         * For a non-playing buffer, report the actual write cursor.
         * For a playing buffer, the write cursor should be ahead of play
         * by a small margin (~15ms worth of data is typical on Windows).
         */
        if (self->playing && self->fmt.nAvgBytesPerSec > 0) {
            DWORD lead = (self->fmt.nAvgBytesPerSec * 15) / 1000;
            if (self->fmt.nBlockAlign > 0)
                lead = (lead / self->fmt.nBlockAlign) * self->fmt.nBlockAlign;
            *write_cursor = (self->play_cursor + lead) % self->pcm_size;
        } else {
            *write_cursor = self->write_cursor;
        }
    }
    pthread_mutex_unlock(&self->lock);
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_GetFormat(IDirectSoundBuffer *self, WAVEFORMATEX *fmt,
                        DWORD size_allocated, DWORD *size_written)
{
    DWORD needed = sizeof(WAVEFORMATEX);
    if (size_written)
        *size_written = needed;
    if (fmt && size_allocated >= needed)
        memcpy(fmt, &self->fmt, needed);
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_GetVolume(IDirectSoundBuffer *self, LONG *volume)
{
    if (!volume)
        return DSERR_INVALIDPARAM;
    *volume = self->volume;
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_SetVolume(IDirectSoundBuffer *self, LONG volume)
{
    if (volume < -10000) volume = -10000;
    if (volume > 0) volume = 0;
    self->volume = volume;
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_GetPan(IDirectSoundBuffer *self, LONG *pan)
{
    if (!pan)
        return DSERR_INVALIDPARAM;
    *pan = self->pan;
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_SetPan(IDirectSoundBuffer *self, LONG pan)
{
    if (pan < -10000) pan = -10000;
    if (pan > 10000) pan = 10000;
    self->pan = pan;
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_GetFrequency(IDirectSoundBuffer *self, DWORD *freq)
{
    if (!freq)
        return DSERR_INVALIDPARAM;
    *freq = self->fmt.nSamplesPerSec;
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_SetFrequency(IDirectSoundBuffer *self, DWORD freq)
{
    if (freq == 0)
        return DS_OK; /* DSBFREQUENCY_ORIGINAL: keep current */

    /* DirectSound allows 100..200000 Hz */
    if (freq < 100) freq = 100;
    if (freq > 200000) freq = 200000;

    pthread_mutex_lock(&self->lock);
    self->fmt.nSamplesPerSec = freq;
    self->fmt.nAvgBytesPerSec = freq * self->fmt.nBlockAlign;

    /*
     * If we have a PA stream, we need to tear it down and recreate it
     * with the new sample rate. The playback thread will pick up the
     * new stream on the next write iteration.
     */
    if (self->pa_stream) {
        /* Flush then destroy */
        if (p_pa_simple_flush) {
            int err = 0;
            p_pa_simple_flush(self->pa_stream, &err);
        }
        if (p_pa_simple_free)
            p_pa_simple_free(self->pa_stream);
        self->pa_stream = NULL;

        /* Recreate with new format */
        dsbuf_create_pa_stream(self);
    }
    pthread_mutex_unlock(&self->lock);

    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_GetStatus(IDirectSoundBuffer *self, DWORD *status)
{
    if (!status)
        return DSERR_INVALIDPARAM;
    *status = 0;
    if (self->playing) *status |= DSBSTATUS_PLAYING;
    if (self->looping) *status |= DSBSTATUS_LOOPING;
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_Initialize(IDirectSoundBuffer *self, void *ds, const DSBUFFERDESC *desc)
{
    (void)self; (void)ds; (void)desc;
    /* Already initialized at creation time */
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_Lock(IDirectSoundBuffer *self, DWORD offset, DWORD bytes,
                   void **ptr1, DWORD *len1, void **ptr2, DWORD *len2, DWORD flags)
{
    if (!ptr1 || !len1)
        return DSERR_INVALIDPARAM;

    pthread_mutex_lock(&self->lock);

    /* Handle DSBLOCK flags */
    if (flags & DSBLOCK_FROMWRITECURSOR)
        offset = self->write_cursor;

    if (flags & DSBLOCK_ENTIREBUFFER)
        bytes = self->pcm_size;

    /* Clamp bytes to buffer size */
    if (bytes > self->pcm_size)
        bytes = self->pcm_size;

    /* Normalize offset */
    if (offset >= self->pcm_size)
        offset = offset % self->pcm_size;

    /* Calculate first region: from offset to end of buffer or end of requested range */
    DWORD first_part = self->pcm_size - offset;
    if (first_part > bytes)
        first_part = bytes;

    *ptr1 = self->pcm_data + offset;
    *len1 = first_part;

    /* Calculate second region: wrap-around from start of buffer */
    DWORD second_part = bytes - first_part;
    if (second_part > 0 && ptr2 && len2) {
        *ptr2 = self->pcm_data;
        *len2 = second_part;
    } else {
        if (ptr2) *ptr2 = NULL;
        if (len2) *len2 = 0;
    }

    /*
     * Note: the mutex is held across Lock/Unlock. This is intentional --
     * the application writes into the locked regions between Lock and Unlock.
     * The mutex prevents the playback thread from reading during this time.
     */

    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_Unlock(IDirectSoundBuffer *self, void *ptr1, DWORD len1,
                     void *ptr2, DWORD len2)
{
    (void)ptr1;
    (void)ptr2;

    /* Advance write cursor by the total unlocked size */
    DWORD total = len1 + len2;
    self->write_cursor = (self->write_cursor + total) % self->pcm_size;

    pthread_mutex_unlock(&self->lock);
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_Play(IDirectSoundBuffer *self, DWORD reserved1, DWORD reserved2, DWORD flags)
{
    (void)reserved1;
    (void)reserved2;

    if (self->playing)
        return DS_OK; /* already playing */

    self->looping = (flags & DSBPLAY_LOOPING) ? 1 : 0;
    self->playing = 1;

    /* Create PulseAudio stream if not already open (skip for primary buffers) */
    if (!self->pa_stream && !self->is_primary)
        dsbuf_create_pa_stream(self);

    /* Start playback thread */
    if (self->pa_stream)
        dsbuf_start_thread(self);

    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_Stop(IDirectSoundBuffer *self)
{
    if (!self->playing)
        return DS_OK;

    self->playing = 0;
    dsbuf_stop_thread(self);

    /* Flush any remaining buffered audio in PulseAudio */
    if (self->pa_stream && p_pa_simple_flush) {
        int err = 0;
        p_pa_simple_flush(self->pa_stream, &err);
    }

    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_SetCurrentPosition(IDirectSoundBuffer *self, DWORD new_pos)
{
    pthread_mutex_lock(&self->lock);
    if (self->pcm_size > 0)
        self->play_cursor = new_pos % self->pcm_size;
    pthread_mutex_unlock(&self->lock);
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_SetFormat(IDirectSoundBuffer *self, const WAVEFORMATEX *fmt)
{
    if (!fmt)
        return DSERR_INVALIDPARAM;

    pthread_mutex_lock(&self->lock);

    /* Copy the new format */
    memcpy(&self->fmt, fmt, sizeof(WAVEFORMATEX));

    /*
     * Tear down existing PA stream so it will be recreated on next Play()
     * with the new format parameters.
     */
    if (self->pa_stream) {
        if (p_pa_simple_flush) {
            int err = 0;
            p_pa_simple_flush(self->pa_stream, &err);
        }
        if (p_pa_simple_free)
            p_pa_simple_free(self->pa_stream);
        self->pa_stream = NULL;
    }

    pthread_mutex_unlock(&self->lock);
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT dsbuf_Restore(IDirectSoundBuffer *self)
{
    (void)self;
    /* Buffer is never lost in our implementation */
    return DS_OK;
}

/* ================================================================== */
/*  IDirectSoundBuffer vtable (shared, immutable)                      */
/* ================================================================== */

static const IDirectSoundBufferVtbl g_dsbuf_vtbl = {
    .QueryInterface     = dsbuf_QueryInterface,
    .AddRef             = dsbuf_AddRef,
    .Release            = dsbuf_Release,
    .GetCaps            = dsbuf_GetCaps,
    .GetCurrentPosition = dsbuf_GetCurrentPosition,
    .GetFormat          = dsbuf_GetFormat,
    .GetVolume          = dsbuf_GetVolume,
    .GetPan             = dsbuf_GetPan,
    .GetFrequency       = dsbuf_GetFrequency,
    .GetStatus          = dsbuf_GetStatus,
    .Initialize         = dsbuf_Initialize,
    .Lock               = dsbuf_Lock,
    .Play               = dsbuf_Play,
    .SetCurrentPosition = dsbuf_SetCurrentPosition,
    .SetFormat          = dsbuf_SetFormat,
    .SetVolume          = dsbuf_SetVolume,
    .SetPan             = dsbuf_SetPan,
    .SetFrequency       = dsbuf_SetFrequency,
    .Stop               = dsbuf_Stop,
    .Unlock             = dsbuf_Unlock,
    .Restore            = dsbuf_Restore,
};

/* ================================================================== */
/*  Buffer creation helper                                             */
/* ================================================================== */

static IDirectSoundBuffer *create_dsbuffer(const DSBUFFERDESC *desc)
{
    IDirectSoundBuffer *buf = calloc(1, sizeof(IDirectSoundBuffer));
    if (!buf) return NULL;

    buf->lpVtbl = &g_dsbuf_vtbl;
    buf->ref_count = 1;
    pthread_mutex_init(&buf->lock, NULL);
    buf->volume = 0;   /* full volume */
    buf->pan = 0;       /* centered */

    if (desc) {
        buf->flags = desc->dwFlags;
        buf->is_primary = (desc->dwFlags & DSBCAPS_PRIMARYBUFFER) ? 1 : 0;

        if (desc->lpwfxFormat) {
            memcpy(&buf->fmt, desc->lpwfxFormat, sizeof(WAVEFORMATEX));
        } else {
            /* Default: 44100 Hz, 16-bit, stereo PCM */
            buf->fmt.wFormatTag     = WAVE_FORMAT_PCM;
            buf->fmt.nChannels      = 2;
            buf->fmt.nSamplesPerSec = 44100;
            buf->fmt.wBitsPerSample = 16;
            buf->fmt.nBlockAlign    = 4;
            buf->fmt.nAvgBytesPerSec = 44100 * 4;
            buf->fmt.cbSize         = 0;
        }

        if (desc->dwBufferBytes > 0) {
            buf->pcm_size = desc->dwBufferBytes;
        } else {
            /* Primary or zero-size: 1 second default */
            buf->pcm_size = buf->fmt.nAvgBytesPerSec;
            if (buf->pcm_size == 0)
                buf->pcm_size = 44100 * 4; /* fallback */
        }
    } else {
        /* No descriptor: default format */
        buf->fmt.wFormatTag     = WAVE_FORMAT_PCM;
        buf->fmt.nChannels      = 2;
        buf->fmt.nSamplesPerSec = 44100;
        buf->fmt.wBitsPerSample = 16;
        buf->fmt.nBlockAlign    = 4;
        buf->fmt.nAvgBytesPerSec = 44100 * 4;
        buf->fmt.cbSize         = 0;
        buf->pcm_size           = 44100 * 4; /* 1 second */
    }

    buf->pcm_data = calloc(1, buf->pcm_size);
    if (!buf->pcm_data) {
        pthread_mutex_destroy(&buf->lock);
        free(buf);
        return NULL;
    }

    return buf;
}

/* ================================================================== */
/*  IDirectSound8 COM vtable                                           */
/* ================================================================== */

typedef struct {
    /* IUnknown */
    HRESULT  (__attribute__((ms_abi)) *QueryInterface)(IDirectSound8 *self, const void *riid, void **ppv);
    uint32_t (__attribute__((ms_abi)) *AddRef)(IDirectSound8 *self);
    uint32_t (__attribute__((ms_abi)) *Release)(IDirectSound8 *self);
    /* IDirectSound */
    HRESULT  (__attribute__((ms_abi)) *CreateSoundBuffer)(IDirectSound8 *self, const DSBUFFERDESC *desc, IDirectSoundBuffer **ppBuf, void *pUnkOuter);
    HRESULT  (__attribute__((ms_abi)) *GetCaps)(IDirectSound8 *self, DSCAPS *caps);
    HRESULT  (__attribute__((ms_abi)) *DuplicateSoundBuffer)(IDirectSound8 *self, IDirectSoundBuffer *orig, IDirectSoundBuffer **ppDup);
    HRESULT  (__attribute__((ms_abi)) *SetCooperativeLevel)(IDirectSound8 *self, HWND hwnd, DWORD level);
    HRESULT  (__attribute__((ms_abi)) *Compact)(IDirectSound8 *self);
    HRESULT  (__attribute__((ms_abi)) *GetSpeakerConfig)(IDirectSound8 *self, DWORD *config);
    HRESULT  (__attribute__((ms_abi)) *SetSpeakerConfig)(IDirectSound8 *self, DWORD config);
    HRESULT  (__attribute__((ms_abi)) *Initialize)(IDirectSound8 *self, const void *guid);
    /* IDirectSound8 extension */
    HRESULT  (__attribute__((ms_abi)) *VerifyCertification)(IDirectSound8 *self, DWORD *certified);
} IDirectSound8Vtbl;

struct IDirectSound8 {
    const IDirectSound8Vtbl *lpVtbl;
    volatile int ref_count;
    IDirectSoundBuffer *primary;   /* cached primary buffer */
    DWORD coop_level;              /* cooperative level */
};

/* ================================================================== */
/*  IDirectSound8 method implementations                               */
/* ================================================================== */

static __attribute__((ms_abi))
HRESULT ds8_QueryInterface(IDirectSound8 *self, const void *riid, void **ppv)
{
    if (!ppv)
        return DSERR_INVALIDPARAM;

    *ppv = NULL;
    if (!riid || memcmp(riid, IID_IUnknown_bytes, 16) == 0) {
        *ppv = self;
        __sync_add_and_fetch(&self->ref_count, 1);
        return DS_OK;
    }
    return E_NOINTERFACE;
}

static __attribute__((ms_abi))
uint32_t ds8_AddRef(IDirectSound8 *self)
{
    return (uint32_t)__sync_add_and_fetch(&self->ref_count, 1);
}

static __attribute__((ms_abi))
uint32_t ds8_Release(IDirectSound8 *self)
{
    int ref = __sync_sub_and_fetch(&self->ref_count, 1);
    if (ref <= 0) {
        if (self->primary) {
            IDirectSoundBuffer *p = self->primary;
            self->primary = NULL;
            p->lpVtbl->Release(p);
        }
        free(self);
        return 0;
    }
    return (uint32_t)ref;
}

static __attribute__((ms_abi))
HRESULT ds8_CreateSoundBuffer(IDirectSound8 *self, const DSBUFFERDESC *desc,
                              IDirectSoundBuffer **ppBuf, void *pUnkOuter)
{
    (void)pUnkOuter;

    if (!ppBuf)
        return DSERR_INVALIDPARAM;

    /* Primary buffer request */
    if (desc && (desc->dwFlags & DSBCAPS_PRIMARYBUFFER)) {
        if (!self->primary)
            self->primary = create_dsbuffer(desc);

        if (self->primary) {
            __sync_add_and_fetch(&self->primary->ref_count, 1);
            *ppBuf = self->primary;
            fprintf(stderr, "[dsound] CreateSoundBuffer: primary buffer (%u Hz, %u-bit, %u ch)\n",
                    self->primary->fmt.nSamplesPerSec,
                    self->primary->fmt.wBitsPerSample,
                    self->primary->fmt.nChannels);
            return DS_OK;
        }
        *ppBuf = NULL;
        return DSERR_OUTOFMEMORY;
    }

    /* Secondary buffer */
    IDirectSoundBuffer *buf = create_dsbuffer(desc);
    if (!buf) {
        *ppBuf = NULL;
        return DSERR_OUTOFMEMORY;
    }

    fprintf(stderr, "[dsound] CreateSoundBuffer: %u Hz, %u-bit, %u ch, %u bytes%s\n",
            buf->fmt.nSamplesPerSec, buf->fmt.wBitsPerSample,
            buf->fmt.nChannels, buf->pcm_size,
            (buf->fmt.wFormatTag == WAVE_FORMAT_IEEE_FLOAT) ? " (float)" : "");

    *ppBuf = buf;
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT ds8_GetCaps(IDirectSound8 *self, DSCAPS *caps)
{
    (void)self;

    if (!caps)
        return DSERR_INVALIDPARAM;

    memset(caps, 0, sizeof(DSCAPS));
    caps->dwSize                         = sizeof(DSCAPS);
    caps->dwFlags                        = 0x00000301; /* PRIMARY_MONO | PRIMARY_STEREO | PRIMARY_16BIT */
    caps->dwMinSecondarySampleRate       = 100;
    caps->dwMaxSecondarySampleRate       = 200000;
    caps->dwPrimaryBuffers               = 1;
    caps->dwMaxHwMixingAllBuffers        = 100;
    caps->dwMaxHwMixingStaticBuffers     = 100;
    caps->dwMaxHwMixingStreamingBuffers  = 100;
    caps->dwFreeHwMixingAllBuffers       = 100;
    caps->dwFreeHwMixingStaticBuffers    = 100;
    caps->dwFreeHwMixingStreamingBuffers = 100;
    caps->dwTotalHwMemBytes              = 0;
    caps->dwFreeHwMemBytes               = 0;

    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT ds8_DuplicateSoundBuffer(IDirectSound8 *self, IDirectSoundBuffer *orig,
                                 IDirectSoundBuffer **ppDup)
{
    (void)self;

    if (!orig || !ppDup)
        return DSERR_INVALIDPARAM;

    /* Create a new buffer with the same format */
    IDirectSoundBuffer *dup = create_dsbuffer(NULL);
    if (!dup) {
        *ppDup = NULL;
        return DSERR_OUTOFMEMORY;
    }

    pthread_mutex_lock(&orig->lock);

    /* Copy format */
    memcpy(&dup->fmt, &orig->fmt, sizeof(WAVEFORMATEX));
    dup->is_primary = 0; /* duplicates are always secondary */
    dup->flags = orig->flags & ~DSBCAPS_PRIMARYBUFFER;

    /* Resize PCM buffer if needed */
    if (dup->pcm_size != orig->pcm_size) {
        free(dup->pcm_data);
        dup->pcm_size = orig->pcm_size;
        dup->pcm_data = calloc(1, dup->pcm_size);
        if (!dup->pcm_data) {
            pthread_mutex_unlock(&orig->lock);
            dup->lpVtbl->Release(dup);
            *ppDup = NULL;
            return DSERR_OUTOFMEMORY;
        }
    }

    /* Copy PCM data */
    if (orig->pcm_data)
        memcpy(dup->pcm_data, orig->pcm_data, dup->pcm_size);

    dup->volume = orig->volume;
    dup->pan = orig->pan;

    pthread_mutex_unlock(&orig->lock);

    *ppDup = dup;
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT ds8_SetCooperativeLevel(IDirectSound8 *self, HWND hwnd, DWORD level)
{
    (void)hwnd;
    self->coop_level = level;
    fprintf(stderr, "[dsound] SetCooperativeLevel: %u\n", level);
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT ds8_Compact(IDirectSound8 *self)
{
    (void)self;
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT ds8_GetSpeakerConfig(IDirectSound8 *self, DWORD *config)
{
    (void)self;
    if (!config)
        return DSERR_INVALIDPARAM;
    *config = DSSPEAKER_STEREO;
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT ds8_SetSpeakerConfig(IDirectSound8 *self, DWORD config)
{
    (void)self; (void)config;
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT ds8_Initialize(IDirectSound8 *self, const void *guid)
{
    (void)self; (void)guid;
    return DS_OK;
}

static __attribute__((ms_abi))
HRESULT ds8_VerifyCertification(IDirectSound8 *self, DWORD *certified)
{
    (void)self;
    if (certified)
        *certified = 0; /* DS_UNCERTIFIED */
    return DS_OK;
}

/* ================================================================== */
/*  IDirectSound8 shared vtable                                        */
/* ================================================================== */

static const IDirectSound8Vtbl g_ds8_vtbl = {
    .QueryInterface       = ds8_QueryInterface,
    .AddRef               = ds8_AddRef,
    .Release              = ds8_Release,
    .CreateSoundBuffer    = ds8_CreateSoundBuffer,
    .GetCaps              = ds8_GetCaps,
    .DuplicateSoundBuffer = ds8_DuplicateSoundBuffer,
    .SetCooperativeLevel  = ds8_SetCooperativeLevel,
    .Compact              = ds8_Compact,
    .GetSpeakerConfig     = ds8_GetSpeakerConfig,
    .SetSpeakerConfig     = ds8_SetSpeakerConfig,
    .Initialize           = ds8_Initialize,
    .VerifyCertification  = ds8_VerifyCertification,
};

/* ================================================================== */
/*  IDirectSound8 object creation                                      */
/* ================================================================== */

static IDirectSound8 *create_dsound8_object(void)
{
    /* Ensure PulseAudio is loaded */
    pulse_load();

    IDirectSound8 *ds = calloc(1, sizeof(IDirectSound8));
    if (!ds) return NULL;

    ds->lpVtbl    = &g_ds8_vtbl;
    ds->ref_count = 1;
    ds->coop_level = DSSCL_NORMAL;

    return ds;
}

/* ================================================================== */
/*  GUID for IDirectSound8 (referenced by some callers)                */
/* ================================================================== */

typedef const GUID *LPCGUID;

/* ================================================================== */
/*  Exported Functions                                                 */
/* ================================================================== */

WINAPI_EXPORT HRESULT DirectSoundCreate(LPCGUID device, void **ppDS, void *outer)
{
    (void)device; (void)outer;
    fprintf(stderr, "[dsound] DirectSoundCreate\n");

    if (!ppDS)
        return DSERR_INVALIDPARAM;

    IDirectSound8 *ds = create_dsound8_object();
    if (!ds) {
        *ppDS = NULL;
        return DSERR_OUTOFMEMORY;
    }

    *ppDS = ds;
    return DS_OK;
}

WINAPI_EXPORT HRESULT DirectSoundCreate8(LPCGUID device, void **ppDS8, void *outer)
{
    (void)device; (void)outer;
    fprintf(stderr, "[dsound] DirectSoundCreate8\n");

    if (!ppDS8)
        return DSERR_INVALIDPARAM;

    IDirectSound8 *ds = create_dsound8_object();
    if (!ds) {
        *ppDS8 = NULL;
        return DSERR_OUTOFMEMORY;
    }

    *ppDS8 = ds;
    return DS_OK;
}

/* Enumerate callback types */
typedef int (__attribute__((ms_abi)) *LPDSENUMCALLBACKA)(void *guid, const char *desc, const char *module, void *ctx);
typedef int (__attribute__((ms_abi)) *LPDSENUMCALLBACKW)(void *guid, const uint16_t *desc, const uint16_t *module, void *ctx);

WINAPI_EXPORT HRESULT DirectSoundEnumerateA(LPDSENUMCALLBACKA cb, void *ctx)
{
    fprintf(stderr, "[dsound] DirectSoundEnumerateA\n");
    if (cb) {
        /* Report one default playback device (NULL GUID = default) */
        cb(NULL, "PulseAudio Default", "PELoader Audio", ctx);
    }
    return DS_OK;
}

WINAPI_EXPORT HRESULT DirectSoundEnumerateW(LPDSENUMCALLBACKW cb, void *ctx)
{
    fprintf(stderr, "[dsound] DirectSoundEnumerateW\n");
    if (cb) {
        static const uint16_t name[] = {
            'P','u','l','s','e','A','u','d','i','o',' ',
            'D','e','f','a','u','l','t', 0
        };
        static const uint16_t mod[] = {
            'P','E','L','o','a','d','e','r',' ',
            'A','u','d','i','o', 0
        };
        cb(NULL, name, mod, ctx);
    }
    return DS_OK;
}

WINAPI_EXPORT HRESULT DirectSoundCaptureCreate(LPCGUID device, void **ppDSC, void *outer)
{
    (void)device; (void)outer;
    fprintf(stderr, "[dsound] DirectSoundCaptureCreate: E_NOTIMPL\n");
    if (ppDSC) *ppDSC = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT DirectSoundCaptureCreate8(LPCGUID device, void **ppDSC8, void *outer)
{
    (void)device; (void)outer;
    fprintf(stderr, "[dsound] DirectSoundCaptureCreate8: E_NOTIMPL\n");
    if (ppDSC8) *ppDSC8 = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT DirectSoundCaptureEnumerateA(void *cb, void *ctx)
{
    (void)cb; (void)ctx;
    fprintf(stderr, "[dsound] DirectSoundCaptureEnumerateA\n");
    return DS_OK;
}

WINAPI_EXPORT HRESULT DirectSoundCaptureEnumerateW(void *cb, void *ctx)
{
    (void)cb; (void)ctx;
    fprintf(stderr, "[dsound] DirectSoundCaptureEnumerateW\n");
    return DS_OK;
}

WINAPI_EXPORT HRESULT DirectSoundFullDuplexCreate(
    LPCGUID capture_dev, LPCGUID render_dev,
    const void *capture_desc, const void *render_desc,
    HWND hwnd, DWORD level,
    void **ppDSFD, void **ppDSCBuf8, void **ppDSBuf8, void *outer)
{
    (void)capture_dev; (void)render_dev;
    (void)capture_desc; (void)render_desc;
    (void)hwnd; (void)level; (void)outer;
    fprintf(stderr, "[dsound] DirectSoundFullDuplexCreate: E_NOTIMPL\n");
    if (ppDSFD) *ppDSFD = NULL;
    if (ppDSCBuf8) *ppDSCBuf8 = NULL;
    if (ppDSBuf8) *ppDSBuf8 = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT GetDeviceID(const void *pGuidSrc, void *pGuidDest)
{
    (void)pGuidSrc;
    if (pGuidDest)
        memset(pGuidDest, 0, sizeof(GUID));
    return DS_OK;
}

WINAPI_EXPORT HRESULT DllCanUnloadNow(void)
{
    return S_FALSE; /* Don't unload */
}

WINAPI_EXPORT HRESULT DllGetClassObject(const void *rclsid, const void *riid, void **ppv)
{
    (void)rclsid; (void)riid;
    fprintf(stderr, "[dsound] DllGetClassObject: E_NOINTERFACE\n");
    if (ppv) *ppv = NULL;
    return E_NOINTERFACE;
}
