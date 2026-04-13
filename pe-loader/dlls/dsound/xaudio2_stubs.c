/*
 * xaudio2_stubs.c - XAudio2 COM interface with PulseAudio backend
 *
 * Provides XAudio2Create and working mastering/source voices.
 * Maps xaudio2_9.dll, xaudio2_8.dll, xaudio2_7.dll.
 * Source voices submit PCM buffers played via PulseAudio.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>

#include "common/dll_common.h"

/* XAudio2 error codes */
#define XAUDIO2_E_INVALID_CALL       ((HRESULT)0x88960001)
#define XAUDIO2_E_DEVICE_INVALIDATED ((HRESULT)0x88960004)
#define S_OK ((HRESULT)0)

/* WAVEFORMATEX */
typedef struct {
    uint16_t wFormatTag;
    uint16_t nChannels;
    uint32_t nSamplesPerSec;
    uint32_t nAvgBytesPerSec;
    uint16_t nBlockAlign;
    uint16_t wBitsPerSample;
    uint16_t cbSize;
} WAVEFORMATEX_XA2;

/* PulseAudio simple API (shared with dsound_audio.c via dlopen) */
#define PA_SAMPLE_S16LE   3
#define PA_STREAM_PLAYBACK 1

typedef struct { int format; uint32_t rate; uint8_t channels; } pa_sample_spec;
typedef void pa_simple;

typedef pa_simple *(*pa_simple_new_fn)(const char *, const char *, int, const char *,
    const char *, const pa_sample_spec *, void *, void *, int *);
typedef void (*pa_simple_free_fn)(pa_simple *);
typedef int (*pa_simple_write_fn)(pa_simple *, const void *, size_t, int *);
typedef int (*pa_simple_drain_fn)(pa_simple *, int *);

static void *g_pa_lib = NULL;
static int g_pa_tried = 0;
static pa_simple_new_fn   p_new;
static pa_simple_free_fn  p_free;
static pa_simple_write_fn p_write;
static pa_simple_drain_fn p_drain;

static int pa_load(void)
{
    if (g_pa_tried) return g_pa_lib ? 0 : -1;
    g_pa_tried = 1;
    g_pa_lib = dlopen("libpulse-simple.so.0", RTLD_NOW);
    if (!g_pa_lib) g_pa_lib = dlopen("libpulse-simple.so", RTLD_NOW);
    if (!g_pa_lib) return -1;
    p_new   = (pa_simple_new_fn)dlsym(g_pa_lib, "pa_simple_new");
    p_free  = (pa_simple_free_fn)dlsym(g_pa_lib, "pa_simple_free");
    p_write = (pa_simple_write_fn)dlsym(g_pa_lib, "pa_simple_write");
    p_drain = (pa_simple_drain_fn)dlsym(g_pa_lib, "pa_simple_drain");
    return (p_new && p_write) ? 0 : -1;
}

/* ================================================================== */
/*  IXAudio2SourceVoice                                               */
/* ================================================================== */

/* XAUDIO2_BUFFER */
typedef struct {
    uint32_t Flags;
    uint32_t AudioBytes;
    const uint8_t *pAudioData;
    uint32_t PlayBegin;
    uint32_t PlayLength;
    uint32_t LoopBegin;
    uint32_t LoopLength;
    uint32_t LoopCount;
    void *pContext;
} XAUDIO2_BUFFER;

/* Buffer queue entry */
typedef struct buf_entry {
    uint8_t *data;
    uint32_t size;
    void *context;
    struct buf_entry *next;
} buf_entry_t;

typedef struct IXAudio2SourceVoice IXAudio2SourceVoice;

typedef struct {
    HRESULT (__attribute__((ms_abi)) *GetVoiceDetails)(IXAudio2SourceVoice *, void *);
    HRESULT (__attribute__((ms_abi)) *SetOutputVoices)(IXAudio2SourceVoice *, const void *);
    HRESULT (__attribute__((ms_abi)) *SetEffectChain)(IXAudio2SourceVoice *, const void *);
    HRESULT (__attribute__((ms_abi)) *EnableEffect)(IXAudio2SourceVoice *, uint32_t, uint32_t);
    HRESULT (__attribute__((ms_abi)) *DisableEffect)(IXAudio2SourceVoice *, uint32_t, uint32_t);
    void    (__attribute__((ms_abi)) *GetEffectState)(IXAudio2SourceVoice *, uint32_t, int *);
    HRESULT (__attribute__((ms_abi)) *SetEffectParameters)(IXAudio2SourceVoice *, uint32_t, const void *, uint32_t, uint32_t);
    HRESULT (__attribute__((ms_abi)) *GetEffectParameters)(IXAudio2SourceVoice *, uint32_t, void *, uint32_t);
    HRESULT (__attribute__((ms_abi)) *SetFilterParameters)(IXAudio2SourceVoice *, const void *, uint32_t);
    void    (__attribute__((ms_abi)) *GetFilterParameters)(IXAudio2SourceVoice *, void *);
    HRESULT (__attribute__((ms_abi)) *SetOutputFilterParameters)(IXAudio2SourceVoice *, void *, const void *, uint32_t);
    void    (__attribute__((ms_abi)) *GetOutputFilterParameters)(IXAudio2SourceVoice *, void *, void *);
    HRESULT (__attribute__((ms_abi)) *SetVolume)(IXAudio2SourceVoice *, float, uint32_t);
    void    (__attribute__((ms_abi)) *GetVolume)(IXAudio2SourceVoice *, float *);
    HRESULT (__attribute__((ms_abi)) *SetChannelVolumes)(IXAudio2SourceVoice *, uint32_t, const float *, uint32_t);
    void    (__attribute__((ms_abi)) *GetChannelVolumes)(IXAudio2SourceVoice *, uint32_t, float *);
    HRESULT (__attribute__((ms_abi)) *SetOutputMatrix)(IXAudio2SourceVoice *, void *, uint32_t, uint32_t, const float *, uint32_t);
    void    (__attribute__((ms_abi)) *GetOutputMatrix)(IXAudio2SourceVoice *, void *, uint32_t, uint32_t, float *);
    void    (__attribute__((ms_abi)) *DestroyVoice)(IXAudio2SourceVoice *);
    /* Source voice specific */
    HRESULT (__attribute__((ms_abi)) *Start)(IXAudio2SourceVoice *, uint32_t, uint32_t);
    HRESULT (__attribute__((ms_abi)) *Stop)(IXAudio2SourceVoice *, uint32_t, uint32_t);
    HRESULT (__attribute__((ms_abi)) *SubmitSourceBuffer)(IXAudio2SourceVoice *, const XAUDIO2_BUFFER *, const void *);
    HRESULT (__attribute__((ms_abi)) *FlushSourceBuffers)(IXAudio2SourceVoice *);
    HRESULT (__attribute__((ms_abi)) *Discontinuity)(IXAudio2SourceVoice *);
    HRESULT (__attribute__((ms_abi)) *ExitLoop)(IXAudio2SourceVoice *, uint32_t);
    void    (__attribute__((ms_abi)) *GetState)(IXAudio2SourceVoice *, void *, uint32_t);
    HRESULT (__attribute__((ms_abi)) *SetFrequencyRatio)(IXAudio2SourceVoice *, float, uint32_t);
    void    (__attribute__((ms_abi)) *GetFrequencyRatio)(IXAudio2SourceVoice *, float *);
    HRESULT (__attribute__((ms_abi)) *SetSourceSampleRate)(IXAudio2SourceVoice *, uint32_t);
} IXAudio2SourceVoiceVtbl;

struct IXAudio2SourceVoice {
    const IXAudio2SourceVoiceVtbl *lpVtbl;
    pa_simple *stream;
    WAVEFORMATEX_XA2 fmt;
    float volume;
    volatile int playing;
    buf_entry_t *buf_head;
    buf_entry_t *buf_tail;
    pthread_mutex_t lock;
    pthread_t thread;
    volatile int thread_running;
};

static void *source_voice_thread(void *arg)
{
    IXAudio2SourceVoice *sv = (IXAudio2SourceVoice *)arg;
    while (sv->thread_running) {
        pthread_mutex_lock(&sv->lock);
        buf_entry_t *buf = sv->buf_head;
        if (buf) {
            sv->buf_head = buf->next;
            if (!sv->buf_head) sv->buf_tail = NULL;
        }
        pthread_mutex_unlock(&sv->lock);

        if (buf && sv->stream && sv->playing) {
            int err = 0;
            p_write(sv->stream, buf->data, buf->size, &err);
            free(buf->data);
            free(buf);
        } else if (!buf) {
            usleep(5000);
        }
    }
    return NULL;
}

/* Source voice vtable methods */
static __attribute__((ms_abi)) HRESULT sv_GetVoiceDetails(IXAudio2SourceVoice *s, void *d)
{ (void)s; if (d) memset(d, 0, 32); return S_OK; }
static __attribute__((ms_abi)) HRESULT sv_SetOutputVoices(IXAudio2SourceVoice *s, const void *l)
{ (void)s; (void)l; return S_OK; }
static __attribute__((ms_abi)) HRESULT sv_SetEffectChain(IXAudio2SourceVoice *s, const void *c)
{ (void)s; (void)c; return S_OK; }
static __attribute__((ms_abi)) HRESULT sv_EnableEffect(IXAudio2SourceVoice *s, uint32_t i, uint32_t o)
{ (void)s; (void)i; (void)o; return S_OK; }
static __attribute__((ms_abi)) HRESULT sv_DisableEffect(IXAudio2SourceVoice *s, uint32_t i, uint32_t o)
{ (void)s; (void)i; (void)o; return S_OK; }
static __attribute__((ms_abi)) void sv_GetEffectState(IXAudio2SourceVoice *s, uint32_t i, int *e)
{ (void)s; (void)i; if (e) *e = 0; }
static __attribute__((ms_abi)) HRESULT sv_SetEffectParams(IXAudio2SourceVoice *s, uint32_t i, const void *p, uint32_t sz, uint32_t o)
{ (void)s; (void)i; (void)p; (void)sz; (void)o; return S_OK; }
static __attribute__((ms_abi)) HRESULT sv_GetEffectParams(IXAudio2SourceVoice *s, uint32_t i, void *p, uint32_t sz)
{ (void)s; (void)i; (void)p; (void)sz; return S_OK; }
static __attribute__((ms_abi)) HRESULT sv_SetFilterParams(IXAudio2SourceVoice *s, const void *p, uint32_t o)
{ (void)s; (void)p; (void)o; return S_OK; }
static __attribute__((ms_abi)) void sv_GetFilterParams(IXAudio2SourceVoice *s, void *p)
{ (void)s; (void)p; }
static __attribute__((ms_abi)) HRESULT sv_SetOutFilterParams(IXAudio2SourceVoice *s, void *v, const void *p, uint32_t o)
{ (void)s; (void)v; (void)p; (void)o; return S_OK; }
static __attribute__((ms_abi)) void sv_GetOutFilterParams(IXAudio2SourceVoice *s, void *v, void *p)
{ (void)s; (void)v; (void)p; }

static __attribute__((ms_abi)) HRESULT sv_SetVolume(IXAudio2SourceVoice *s, float v, uint32_t o)
{ (void)o; s->volume = v; return S_OK; }
static __attribute__((ms_abi)) void sv_GetVolume(IXAudio2SourceVoice *s, float *v)
{ if (v) *v = s->volume; }
static __attribute__((ms_abi)) HRESULT sv_SetChannelVolumes(IXAudio2SourceVoice *s, uint32_t c, const float *v, uint32_t o)
{ (void)s; (void)c; (void)v; (void)o; return S_OK; }
static __attribute__((ms_abi)) void sv_GetChannelVolumes(IXAudio2SourceVoice *s, uint32_t c, float *v)
{ (void)s; if (v && c > 0) { for (uint32_t i = 0; i < c; i++) v[i] = 1.0f; } }
static __attribute__((ms_abi)) HRESULT sv_SetOutputMatrix(IXAudio2SourceVoice *s, void *d, uint32_t sc, uint32_t dc, const float *m, uint32_t o)
{ (void)s; (void)d; (void)sc; (void)dc; (void)m; (void)o; return S_OK; }
static __attribute__((ms_abi)) void sv_GetOutputMatrix(IXAudio2SourceVoice *s, void *d, uint32_t sc, uint32_t dc, float *m)
{ (void)s; (void)d; (void)sc; (void)dc; (void)m; }

static __attribute__((ms_abi)) void sv_DestroyVoice(IXAudio2SourceVoice *s)
{
    s->playing = 0;
    s->thread_running = 0;
    if (s->thread) pthread_join(s->thread, NULL);
    if (s->stream && p_free) p_free(s->stream);
    /* Flush buffer queue */
    pthread_mutex_lock(&s->lock);
    buf_entry_t *b = s->buf_head;
    while (b) { buf_entry_t *n = b->next; free(b->data); free(b); b = n; }
    pthread_mutex_unlock(&s->lock);
    pthread_mutex_destroy(&s->lock);
    free((void *)s->lpVtbl);
    free(s);
}

static __attribute__((ms_abi)) HRESULT sv_Start(IXAudio2SourceVoice *s, uint32_t f, uint32_t o)
{
    (void)f; (void)o;
    s->playing = 1;
    if (!s->thread_running && s->stream) {
        s->thread_running = 1;
        pthread_create(&s->thread, NULL, source_voice_thread, s);
    }
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT sv_Stop(IXAudio2SourceVoice *s, uint32_t f, uint32_t o)
{ (void)f; (void)o; s->playing = 0; return S_OK; }

static __attribute__((ms_abi)) HRESULT sv_SubmitSourceBuffer(IXAudio2SourceVoice *s,
    const XAUDIO2_BUFFER *pBuffer, const void *pBufferWMA)
{
    (void)pBufferWMA;
    if (!pBuffer || !pBuffer->pAudioData || pBuffer->AudioBytes == 0)
        return XAUDIO2_E_INVALID_CALL;

    buf_entry_t *e = calloc(1, sizeof(buf_entry_t));
    if (!e) return XAUDIO2_E_INVALID_CALL;
    e->data = malloc(pBuffer->AudioBytes);
    if (!e->data) { free(e); return XAUDIO2_E_INVALID_CALL; }
    memcpy(e->data, pBuffer->pAudioData, pBuffer->AudioBytes);
    e->size = pBuffer->AudioBytes;
    e->context = pBuffer->pContext;

    pthread_mutex_lock(&s->lock);
    if (s->buf_tail) { s->buf_tail->next = e; s->buf_tail = e; }
    else { s->buf_head = s->buf_tail = e; }
    pthread_mutex_unlock(&s->lock);
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT sv_FlushSourceBuffers(IXAudio2SourceVoice *s)
{
    pthread_mutex_lock(&s->lock);
    buf_entry_t *b = s->buf_head;
    while (b) { buf_entry_t *n = b->next; free(b->data); free(b); b = n; }
    s->buf_head = s->buf_tail = NULL;
    pthread_mutex_unlock(&s->lock);
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT sv_Discontinuity(IXAudio2SourceVoice *s) { (void)s; return S_OK; }
static __attribute__((ms_abi)) HRESULT sv_ExitLoop(IXAudio2SourceVoice *s, uint32_t o) { (void)s; (void)o; return S_OK; }

static __attribute__((ms_abi)) void sv_GetState(IXAudio2SourceVoice *s, void *state, uint32_t flags)
{
    (void)flags;
    /* XAUDIO2_VOICE_STATE: { pCurrentBufferContext, BuffersQueued, SamplesPlayed } */
    if (state) {
        uint64_t *st = (uint64_t *)state;
        st[0] = 0; /* pCurrentBufferContext */
        pthread_mutex_lock(&s->lock);
        uint32_t count = 0;
        buf_entry_t *b = s->buf_head;
        while (b) { count++; b = b->next; }
        pthread_mutex_unlock(&s->lock);
        ((uint32_t *)state)[2] = count; /* BuffersQueued */
        st[1] = 0; /* SamplesPlayed */
    }
}

static __attribute__((ms_abi)) HRESULT sv_SetFrequencyRatio(IXAudio2SourceVoice *s, float r, uint32_t o)
{ (void)s; (void)r; (void)o; return S_OK; }
static __attribute__((ms_abi)) void sv_GetFrequencyRatio(IXAudio2SourceVoice *s, float *r)
{ (void)s; if (r) *r = 1.0f; }
static __attribute__((ms_abi)) HRESULT sv_SetSourceSampleRate(IXAudio2SourceVoice *s, uint32_t r)
{ (void)s; (void)r; return S_OK; }

static IXAudio2SourceVoice *create_source_voice(const WAVEFORMATEX_XA2 *fmt)
{
    IXAudio2SourceVoiceVtbl *v = calloc(1, sizeof(IXAudio2SourceVoiceVtbl));
    if (!v) return NULL;
    v->GetVoiceDetails = sv_GetVoiceDetails;
    v->SetOutputVoices = sv_SetOutputVoices;
    v->SetEffectChain = sv_SetEffectChain;
    v->EnableEffect = sv_EnableEffect;
    v->DisableEffect = sv_DisableEffect;
    v->GetEffectState = sv_GetEffectState;
    v->SetEffectParameters = sv_SetEffectParams;
    v->GetEffectParameters = sv_GetEffectParams;
    v->SetFilterParameters = sv_SetFilterParams;
    v->GetFilterParameters = sv_GetFilterParams;
    v->SetOutputFilterParameters = sv_SetOutFilterParams;
    v->GetOutputFilterParameters = sv_GetOutFilterParams;
    v->SetVolume = sv_SetVolume;
    v->GetVolume = sv_GetVolume;
    v->SetChannelVolumes = sv_SetChannelVolumes;
    v->GetChannelVolumes = sv_GetChannelVolumes;
    v->SetOutputMatrix = sv_SetOutputMatrix;
    v->GetOutputMatrix = sv_GetOutputMatrix;
    v->DestroyVoice = sv_DestroyVoice;
    v->Start = sv_Start;
    v->Stop = sv_Stop;
    v->SubmitSourceBuffer = sv_SubmitSourceBuffer;
    v->FlushSourceBuffers = sv_FlushSourceBuffers;
    v->Discontinuity = sv_Discontinuity;
    v->ExitLoop = sv_ExitLoop;
    v->GetState = sv_GetState;
    v->SetFrequencyRatio = sv_SetFrequencyRatio;
    v->GetFrequencyRatio = sv_GetFrequencyRatio;
    v->SetSourceSampleRate = sv_SetSourceSampleRate;

    IXAudio2SourceVoice *sv = calloc(1, sizeof(IXAudio2SourceVoice));
    if (!sv) { free(v); return NULL; }
    sv->lpVtbl = v;
    sv->volume = 1.0f;
    pthread_mutex_init(&sv->lock, NULL);

    if (fmt) {
        memcpy(&sv->fmt, fmt, sizeof(WAVEFORMATEX_XA2));
        /* Create PulseAudio stream */
        if (pa_load() == 0 && p_new) {
            pa_sample_spec ss = {
                .format = PA_SAMPLE_S16LE,
                .rate = fmt->nSamplesPerSec ? fmt->nSamplesPerSec : 44100,
                .channels = fmt->nChannels ? fmt->nChannels : 2
            };
            int err = 0;
            sv->stream = p_new(NULL, "PELoader", PA_STREAM_PLAYBACK, NULL,
                               "XAudio2", &ss, NULL, NULL, &err);
        }
    }

    fprintf(stderr, "[xaudio2] CreateSourceVoice: %u Hz, %u ch, stream=%p\n",
            fmt ? fmt->nSamplesPerSec : 0, fmt ? fmt->nChannels : 0, (void *)sv->stream);
    return sv;
}

/* ================================================================== */
/*  IXAudio2MasteringVoice (simplified)                               */
/* ================================================================== */

typedef struct IXAudio2MasteringVoice {
    void *lpVtbl; /* Placeholder vtable */
    float volume;
} IXAudio2MasteringVoice;

static IXAudio2MasteringVoice g_mastering_voice = { NULL, 1.0f };

/* ================================================================== */
/*  IXAudio2                                                          */
/* ================================================================== */

typedef struct IXAudio2_vtbl {
    HRESULT (__attribute__((ms_abi)) *QueryInterface)(void *, const void *, void **);
    uint32_t (__attribute__((ms_abi)) *AddRef)(void *);
    uint32_t (__attribute__((ms_abi)) *Release)(void *);
    HRESULT (__attribute__((ms_abi)) *RegisterForCallbacks)(void *, void *);
    void    (__attribute__((ms_abi)) *UnregisterForCallbacks)(void *, void *);
    HRESULT (__attribute__((ms_abi)) *CreateSourceVoice)(void *, void **, const void *,
             uint32_t, float, void *, void *, void *);
    HRESULT (__attribute__((ms_abi)) *CreateSubmixVoice)(void *, void **, uint32_t, uint32_t,
             uint32_t, uint32_t, void *, void *);
    HRESULT (__attribute__((ms_abi)) *CreateMasteringVoice)(void *, void **, uint32_t, uint32_t,
             uint32_t, const void *, void *, int);
    HRESULT (__attribute__((ms_abi)) *StartEngine)(void *);
    void    (__attribute__((ms_abi)) *StopEngine)(void *);
    HRESULT (__attribute__((ms_abi)) *CommitChanges)(void *, uint32_t);
    void    (__attribute__((ms_abi)) *GetPerformanceData)(void *, void *);
    void    (__attribute__((ms_abi)) *SetDebugConfiguration)(void *, const void *, void *);
} IXAudio2_vtbl;

typedef struct {
    IXAudio2_vtbl *lpVtbl;
    int ref_count;
} IXAudio2_obj;

static const unsigned char IID_IUnknown_bytes[16] = {
    0x00,0x00,0x00,0x00, 0x00,0x00, 0x00,0x00,
    0xC0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46
};

static __attribute__((ms_abi)) HRESULT xa2_qi(void *t, const void *r, void **p)
{
    if (!p) return (HRESULT)0x80004003; /* E_POINTER */
    *p = NULL;
    if (!r || memcmp(r, IID_IUnknown_bytes, 16) == 0) {
        *p = t;
        ((IXAudio2_obj *)t)->ref_count++;
        return S_OK;
    }
    return (HRESULT)0x80004002; /* E_NOINTERFACE */
}
static __attribute__((ms_abi)) uint32_t xa2_addref(void *t)
{ return ++((IXAudio2_obj *)t)->ref_count; }
static __attribute__((ms_abi)) uint32_t xa2_release(void *t)
{
    IXAudio2_obj *o = (IXAudio2_obj *)t;
    if (--o->ref_count <= 0) { free(o->lpVtbl); free(o); return 0; }
    return o->ref_count;
}
static __attribute__((ms_abi)) HRESULT xa2_regcb(void *t, void *c) { (void)t; (void)c; return S_OK; }
static __attribute__((ms_abi)) void xa2_unregcb(void *t, void *c) { (void)t; (void)c; }

static __attribute__((ms_abi)) HRESULT xa2_create_sv(void *This, void **ppVoice,
    const void *fmt, uint32_t flags, float freq, void *cb, void *sends, void *fx)
{
    (void)This; (void)flags; (void)freq; (void)cb; (void)sends; (void)fx;
    if (!ppVoice) return XAUDIO2_E_INVALID_CALL;
    IXAudio2SourceVoice *sv = create_source_voice((const WAVEFORMATEX_XA2 *)fmt);
    if (!sv) { *ppVoice = NULL; return XAUDIO2_E_DEVICE_INVALIDATED; }
    *ppVoice = sv;
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT xa2_create_submix(void *t, void **v,
    uint32_t ch, uint32_t rate, uint32_t fl, uint32_t st, void *sn, void *fx)
{
    (void)t; (void)ch; (void)rate; (void)fl; (void)st; (void)sn; (void)fx;
    if (v) *v = NULL;
    return S_OK; /* Submix voices are optional */
}

static __attribute__((ms_abi)) HRESULT xa2_create_mv(void *t, void **v,
    uint32_t ch, uint32_t rate, uint32_t fl, const void *dev, void *fx, int cat)
{
    (void)t; (void)ch; (void)rate; (void)fl; (void)dev; (void)fx; (void)cat;
    if (v) *v = &g_mastering_voice;
    fprintf(stderr, "[xaudio2] CreateMasteringVoice: ok\n");
    return S_OK;
}

static __attribute__((ms_abi)) HRESULT xa2_start(void *t) { (void)t; return S_OK; }
static __attribute__((ms_abi)) void xa2_stop(void *t) { (void)t; }
static __attribute__((ms_abi)) HRESULT xa2_commit(void *t, uint32_t o) { (void)t; (void)o; return S_OK; }
static __attribute__((ms_abi)) void xa2_perf(void *t, void *d) { (void)t; if (d) memset(d, 0, 64); }
static __attribute__((ms_abi)) void xa2_debug(void *t, const void *c, void *r) { (void)t; (void)c; (void)r; }

WINAPI_EXPORT HRESULT XAudio2Create(void **ppXAudio2, uint32_t Flags, uint32_t XAudio2Processor)
{
    (void)Flags; (void)XAudio2Processor;
    fprintf(stderr, "[xaudio2] XAudio2Create\n");
    if (!ppXAudio2) return XAUDIO2_E_INVALID_CALL;

    IXAudio2_vtbl *vtbl = calloc(1, sizeof(IXAudio2_vtbl));
    if (!vtbl) return XAUDIO2_E_DEVICE_INVALIDATED;
    vtbl->QueryInterface = xa2_qi;
    vtbl->AddRef = xa2_addref;
    vtbl->Release = xa2_release;
    vtbl->RegisterForCallbacks = xa2_regcb;
    vtbl->UnregisterForCallbacks = xa2_unregcb;
    vtbl->CreateSourceVoice = xa2_create_sv;
    vtbl->CreateSubmixVoice = xa2_create_submix;
    vtbl->CreateMasteringVoice = xa2_create_mv;
    vtbl->StartEngine = xa2_start;
    vtbl->StopEngine = xa2_stop;
    vtbl->CommitChanges = xa2_commit;
    vtbl->GetPerformanceData = xa2_perf;
    vtbl->SetDebugConfiguration = xa2_debug;

    IXAudio2_obj *obj = calloc(1, sizeof(IXAudio2_obj));
    if (!obj) { free(vtbl); return XAUDIO2_E_DEVICE_INVALIDATED; }
    obj->lpVtbl = vtbl;
    obj->ref_count = 1;
    *ppXAudio2 = obj;
    return S_OK;
}

/* APO stubs */
WINAPI_EXPORT HRESULT CreateAudioVolumeMeter(void **ppApo)
{
    if (ppApo) *ppApo = NULL;
    return 0x80004002; /* E_NOINTERFACE */
}

WINAPI_EXPORT HRESULT CreateAudioReverb(void **ppApo)
{
    if (ppApo) *ppApo = NULL;
    return 0x80004002;
}
