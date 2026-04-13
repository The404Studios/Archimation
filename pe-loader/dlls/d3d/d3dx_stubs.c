/*
 * d3dx_stubs.c - D3DX utility library stubs
 *
 * Stubs for d3dx9_*.dll, d3dx10_*.dll, d3dx11_*.dll.
 * These are legacy DirectX utility DLLs that many games import.
 * They're NOT part of DXVK (which only handles D3D9/11/DXGI core).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "common/dll_common.h"

#define S_OK          ((HRESULT)0x00000000)
#define E_NOTIMPL     ((HRESULT)0x80004001)
#define E_FAIL        ((HRESULT)0x80004005)
#define E_OUTOFMEMORY ((HRESULT)0x8007000E)
#define D3DERR_INVALIDCALL ((HRESULT)0x8876086C)

/* ================================================================== */
/*  D3DX9 Math Functions                                              */
/* ================================================================== */

typedef struct { float _11,_12,_13,_14,_21,_22,_23,_24,_31,_32,_33,_34,_41,_42,_43,_44; } D3DXMATRIX;
typedef struct { float x,y,z; } D3DXVECTOR3;
typedef struct { float x,y,z,w; } D3DXVECTOR4;
typedef struct { float x,y; } D3DXVECTOR2;
typedef struct { float x,y,z,w; } D3DXQUATERNION;
typedef struct { float r,g,b,a; } D3DXCOLOR;

/* Identity matrix */
WINAPI_EXPORT D3DXMATRIX *D3DXMatrixIdentity(D3DXMATRIX *out)
{
    if (!out) return NULL;
    memset(out, 0, sizeof(D3DXMATRIX));
    out->_11 = out->_22 = out->_33 = out->_44 = 1.0f;
    return out;
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixPerspectiveFovLH(D3DXMATRIX *out,
    float fovy, float aspect, float zn, float zf)
{
    if (!out) return NULL;
    memset(out, 0, sizeof(D3DXMATRIX));
    float yScale = 1.0f / tanf(fovy / 2.0f);
    float xScale = yScale / aspect;
    out->_11 = xScale;
    out->_22 = yScale;
    out->_33 = zf / (zf - zn);
    out->_34 = 1.0f;
    out->_43 = -zn * zf / (zf - zn);
    return out;
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixPerspectiveFovRH(D3DXMATRIX *out,
    float fovy, float aspect, float zn, float zf)
{
    if (!out) return NULL;
    memset(out, 0, sizeof(D3DXMATRIX));
    float yScale = 1.0f / tanf(fovy / 2.0f);
    float xScale = yScale / aspect;
    out->_11 = xScale;
    out->_22 = yScale;
    out->_33 = zf / (zn - zf);
    out->_34 = -1.0f;
    out->_43 = zn * zf / (zn - zf);
    return out;
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixOrthoLH(D3DXMATRIX *out,
    float w, float h, float zn, float zf)
{
    if (!out) return NULL;
    memset(out, 0, sizeof(D3DXMATRIX));
    out->_11 = 2.0f / w;
    out->_22 = 2.0f / h;
    out->_33 = 1.0f / (zf - zn);
    out->_43 = -zn / (zf - zn);
    out->_44 = 1.0f;
    return out;
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixOrthoOffCenterLH(D3DXMATRIX *out,
    float l, float r, float b, float t, float zn, float zf)
{
    if (!out) return NULL;
    memset(out, 0, sizeof(D3DXMATRIX));
    out->_11 = 2.0f / (r - l);
    out->_22 = 2.0f / (t - b);
    out->_33 = 1.0f / (zf - zn);
    out->_41 = (l + r) / (l - r);
    out->_42 = (t + b) / (b - t);
    out->_43 = zn / (zn - zf);
    out->_44 = 1.0f;
    return out;
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixLookAtLH(D3DXMATRIX *out,
    const D3DXVECTOR3 *eye, const D3DXVECTOR3 *at, const D3DXVECTOR3 *up)
{
    if (!out || !eye || !at || !up) return out;
    D3DXVECTOR3 zaxis = { at->x - eye->x, at->y - eye->y, at->z - eye->z };
    float zlen = sqrtf(zaxis.x*zaxis.x + zaxis.y*zaxis.y + zaxis.z*zaxis.z);
    if (zlen > 0) { zaxis.x /= zlen; zaxis.y /= zlen; zaxis.z /= zlen; }

    D3DXVECTOR3 xaxis = { up->y*zaxis.z - up->z*zaxis.y,
                           up->z*zaxis.x - up->x*zaxis.z,
                           up->x*zaxis.y - up->y*zaxis.x };
    float xlen = sqrtf(xaxis.x*xaxis.x + xaxis.y*xaxis.y + xaxis.z*xaxis.z);
    if (xlen > 0) { xaxis.x /= xlen; xaxis.y /= xlen; xaxis.z /= xlen; }

    D3DXVECTOR3 yaxis = { zaxis.y*xaxis.z - zaxis.z*xaxis.y,
                           zaxis.z*xaxis.x - zaxis.x*xaxis.z,
                           zaxis.x*xaxis.y - zaxis.y*xaxis.x };

    memset(out, 0, sizeof(D3DXMATRIX));
    out->_11 = xaxis.x; out->_21 = xaxis.y; out->_31 = xaxis.z;
    out->_12 = yaxis.x; out->_22 = yaxis.y; out->_32 = yaxis.z;
    out->_13 = zaxis.x; out->_23 = zaxis.y; out->_33 = zaxis.z;
    out->_41 = -(xaxis.x*eye->x + xaxis.y*eye->y + xaxis.z*eye->z);
    out->_42 = -(yaxis.x*eye->x + yaxis.y*eye->y + yaxis.z*eye->z);
    out->_43 = -(zaxis.x*eye->x + zaxis.y*eye->y + zaxis.z*eye->z);
    out->_44 = 1.0f;
    return out;
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixLookAtRH(D3DXMATRIX *out,
    const D3DXVECTOR3 *eye, const D3DXVECTOR3 *at, const D3DXVECTOR3 *up)
{
    /* Same as LH but negate z */
    D3DXVECTOR3 neg_at = { 2*eye->x - at->x, 2*eye->y - at->y, 2*eye->z - at->z };
    return D3DXMatrixLookAtLH(out, eye, &neg_at, up);
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixTranslation(D3DXMATRIX *out, float x, float y, float z)
{
    D3DXMatrixIdentity(out);
    if (out) { out->_41 = x; out->_42 = y; out->_43 = z; }
    return out;
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixScaling(D3DXMATRIX *out, float sx, float sy, float sz)
{
    if (!out) return NULL;
    memset(out, 0, sizeof(D3DXMATRIX));
    out->_11 = sx; out->_22 = sy; out->_33 = sz; out->_44 = 1.0f;
    return out;
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixRotationX(D3DXMATRIX *out, float angle)
{
    D3DXMatrixIdentity(out);
    if (out) { out->_22 = cosf(angle); out->_23 = sinf(angle);
               out->_32 = -sinf(angle); out->_33 = cosf(angle); }
    return out;
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixRotationY(D3DXMATRIX *out, float angle)
{
    D3DXMatrixIdentity(out);
    if (out) { out->_11 = cosf(angle); out->_13 = -sinf(angle);
               out->_31 = sinf(angle); out->_33 = cosf(angle); }
    return out;
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixRotationZ(D3DXMATRIX *out, float angle)
{
    D3DXMatrixIdentity(out);
    if (out) { out->_11 = cosf(angle); out->_12 = sinf(angle);
               out->_21 = -sinf(angle); out->_22 = cosf(angle); }
    return out;
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixMultiply(D3DXMATRIX *out, const D3DXMATRIX *a, const D3DXMATRIX *b)
{
    if (!out || !a || !b) return out;
    D3DXMATRIX tmp;
    float *o = (float *)&tmp, *A = (float *)a, *B = (float *)b;
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            o[i*4+j] = 0;
            for (int k = 0; k < 4; k++)
                o[i*4+j] += A[i*4+k] * B[k*4+j];
        }
    memcpy(out, &tmp, sizeof(D3DXMATRIX));
    return out;
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixTranspose(D3DXMATRIX *out, const D3DXMATRIX *m)
{
    if (!out || !m) return out;
    D3DXMATRIX tmp;
    float *o = (float *)&tmp, *s = (float *)m;
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            o[i*4+j] = s[j*4+i];
    memcpy(out, &tmp, sizeof(D3DXMATRIX));
    return out;
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixInverse(D3DXMATRIX *out, float *pDet, const D3DXMATRIX *m)
{
    if (!out || !m) return NULL;
    float *s = (float *)m;
    float *o = (float *)out;
    /* Compute cofactors and determinant using standard 4x4 inverse formula */
    float inv[16], det;
    inv[0]  =  s[5]*s[10]*s[15] - s[5]*s[11]*s[14] - s[9]*s[6]*s[15] + s[9]*s[7]*s[14] + s[13]*s[6]*s[11] - s[13]*s[7]*s[10];
    inv[4]  = -s[4]*s[10]*s[15] + s[4]*s[11]*s[14] + s[8]*s[6]*s[15] - s[8]*s[7]*s[14] - s[12]*s[6]*s[11] + s[12]*s[7]*s[10];
    inv[8]  =  s[4]*s[9]*s[15]  - s[4]*s[11]*s[13] - s[8]*s[5]*s[15] + s[8]*s[7]*s[13] + s[12]*s[5]*s[11] - s[12]*s[7]*s[9];
    inv[12] = -s[4]*s[9]*s[14]  + s[4]*s[10]*s[13] + s[8]*s[5]*s[14] - s[8]*s[6]*s[13] - s[12]*s[5]*s[10] + s[12]*s[6]*s[9];
    inv[1]  = -s[1]*s[10]*s[15] + s[1]*s[11]*s[14] + s[9]*s[2]*s[15] - s[9]*s[3]*s[14] - s[13]*s[2]*s[11] + s[13]*s[3]*s[10];
    inv[5]  =  s[0]*s[10]*s[15] - s[0]*s[11]*s[14] - s[8]*s[2]*s[15] + s[8]*s[3]*s[14] + s[12]*s[2]*s[11] - s[12]*s[3]*s[10];
    inv[9]  = -s[0]*s[9]*s[15]  + s[0]*s[11]*s[13] + s[8]*s[1]*s[15] - s[8]*s[3]*s[13] - s[12]*s[1]*s[11] + s[12]*s[3]*s[9];
    inv[13] =  s[0]*s[9]*s[14]  - s[0]*s[10]*s[13] - s[8]*s[1]*s[14] + s[8]*s[2]*s[13] + s[12]*s[1]*s[10] - s[12]*s[2]*s[9];
    inv[2]  =  s[1]*s[6]*s[15]  - s[1]*s[7]*s[14]  - s[5]*s[2]*s[15] + s[5]*s[3]*s[14] + s[13]*s[2]*s[7]  - s[13]*s[3]*s[6];
    inv[6]  = -s[0]*s[6]*s[15]  + s[0]*s[7]*s[14]  + s[4]*s[2]*s[15] - s[4]*s[3]*s[14] - s[12]*s[2]*s[7]  + s[12]*s[3]*s[6];
    inv[10] =  s[0]*s[5]*s[15]  - s[0]*s[7]*s[13]  - s[4]*s[1]*s[15] + s[4]*s[3]*s[13] + s[12]*s[1]*s[7]  - s[12]*s[3]*s[5];
    inv[14] = -s[0]*s[5]*s[14]  + s[0]*s[6]*s[13]  + s[4]*s[1]*s[14] - s[4]*s[2]*s[13] - s[12]*s[1]*s[6]  + s[12]*s[2]*s[5];
    inv[3]  = -s[1]*s[6]*s[11]  + s[1]*s[7]*s[10]  + s[5]*s[2]*s[11] - s[5]*s[3]*s[10] - s[9]*s[2]*s[7]   + s[9]*s[3]*s[6];
    inv[7]  =  s[0]*s[6]*s[11]  - s[0]*s[7]*s[10]  - s[4]*s[2]*s[11] + s[4]*s[3]*s[10] + s[8]*s[2]*s[7]   - s[8]*s[3]*s[6];
    inv[11] = -s[0]*s[5]*s[11]  + s[0]*s[7]*s[9]   + s[4]*s[1]*s[11] - s[4]*s[3]*s[9]  - s[8]*s[1]*s[7]   + s[8]*s[3]*s[5];
    inv[15] =  s[0]*s[5]*s[10]  - s[0]*s[6]*s[9]   - s[4]*s[1]*s[10] + s[4]*s[2]*s[9]  + s[8]*s[1]*s[6]   - s[8]*s[2]*s[5];
    det = s[0]*inv[0] + s[1]*inv[4] + s[2]*inv[8] + s[3]*inv[12];
    if (det == 0.0f || det != det) { if (pDet) *pDet = 0.0f; return NULL; }
    if (pDet) *pDet = det;
    det = 1.0f / det;
    for (int i = 0; i < 16; i++) o[i] = inv[i] * det;
    return out;
}

WINAPI_EXPORT D3DXMATRIX *D3DXMatrixRotationQuaternion(D3DXMATRIX *out, const D3DXQUATERNION *q)
{
    if (!out || !q) return out;
    float xx = q->x*q->x, yy = q->y*q->y, zz = q->z*q->z;
    float xy = q->x*q->y, xz = q->x*q->z, yz = q->y*q->z;
    float wx = q->w*q->x, wy = q->w*q->y, wz = q->w*q->z;
    memset(out, 0, sizeof(D3DXMATRIX));
    out->_11 = 1 - 2*(yy+zz); out->_12 = 2*(xy+wz);     out->_13 = 2*(xz-wy);
    out->_21 = 2*(xy-wz);     out->_22 = 1 - 2*(xx+zz); out->_23 = 2*(yz+wx);
    out->_31 = 2*(xz+wy);     out->_32 = 2*(yz-wx);     out->_33 = 1 - 2*(xx+yy);
    out->_44 = 1.0f;
    return out;
}

WINAPI_EXPORT D3DXVECTOR3 *D3DXVec3Normalize(D3DXVECTOR3 *out, const D3DXVECTOR3 *v)
{
    if (!out || !v) return out;
    float len = sqrtf(v->x*v->x + v->y*v->y + v->z*v->z);
    if (len > 0.0001f) { out->x = v->x/len; out->y = v->y/len; out->z = v->z/len; }
    else { out->x = out->y = out->z = 0; }
    return out;
}

WINAPI_EXPORT D3DXVECTOR3 *D3DXVec3Cross(D3DXVECTOR3 *out, const D3DXVECTOR3 *a, const D3DXVECTOR3 *b)
{
    if (!out || !a || !b) return out;
    out->x = a->y*b->z - a->z*b->y;
    out->y = a->z*b->x - a->x*b->z;
    out->z = a->x*b->y - a->y*b->x;
    return out;
}

WINAPI_EXPORT float D3DXVec3Dot(const D3DXVECTOR3 *a, const D3DXVECTOR3 *b)
{
    if (!a || !b) return 0;
    return a->x*b->x + a->y*b->y + a->z*b->z;
}

WINAPI_EXPORT float D3DXVec3Length(const D3DXVECTOR3 *v)
{
    if (!v) return 0;
    return sqrtf(v->x*v->x + v->y*v->y + v->z*v->z);
}

WINAPI_EXPORT D3DXVECTOR3 *D3DXVec3TransformCoord(D3DXVECTOR3 *out,
    const D3DXVECTOR3 *v, const D3DXMATRIX *m)
{
    if (!out || !v || !m) return out;
    float *M = (float *)m;
    float w = v->x*M[3] + v->y*M[7] + v->z*M[11] + M[15];
    if (w == 0) w = 1;
    out->x = (v->x*M[0] + v->y*M[4] + v->z*M[8]  + M[12]) / w;
    out->y = (v->x*M[1] + v->y*M[5] + v->z*M[9]  + M[13]) / w;
    out->z = (v->x*M[2] + v->y*M[6] + v->z*M[10] + M[14]) / w;
    return out;
}

WINAPI_EXPORT D3DXVECTOR4 *D3DXVec3Transform(D3DXVECTOR4 *out,
    const D3DXVECTOR3 *v, const D3DXMATRIX *m)
{
    if (!out || !v || !m) return out;
    float *M = (float *)m;
    out->x = v->x*M[0] + v->y*M[4] + v->z*M[8]  + M[12];
    out->y = v->x*M[1] + v->y*M[5] + v->z*M[9]  + M[13];
    out->z = v->x*M[2] + v->y*M[6] + v->z*M[10] + M[14];
    out->w = v->x*M[3] + v->y*M[7] + v->z*M[11] + M[15];
    return out;
}

WINAPI_EXPORT D3DXVECTOR4 *D3DXVec4Transform(D3DXVECTOR4 *out,
    const D3DXVECTOR4 *v, const D3DXMATRIX *m)
{
    if (!out || !v || !m) return out;
    float *M = (float *)m;
    out->x = v->x*M[0] + v->y*M[4] + v->z*M[8]  + v->w*M[12];
    out->y = v->x*M[1] + v->y*M[5] + v->z*M[9]  + v->w*M[13];
    out->z = v->x*M[2] + v->y*M[6] + v->z*M[10] + v->w*M[14];
    out->w = v->x*M[3] + v->y*M[7] + v->z*M[11] + v->w*M[15];
    return out;
}

WINAPI_EXPORT float D3DXVec2Length(const D3DXVECTOR2 *v)
{
    if (!v) return 0;
    return sqrtf(v->x*v->x + v->y*v->y);
}

WINAPI_EXPORT D3DXQUATERNION *D3DXQuaternionIdentity(D3DXQUATERNION *out)
{
    if (out) { out->x = 0; out->y = 0; out->z = 0; out->w = 1; }
    return out;
}

WINAPI_EXPORT D3DXQUATERNION *D3DXQuaternionRotationMatrix(D3DXQUATERNION *out, const D3DXMATRIX *m)
{
    if (!out || !m) return out;
    float tr = m->_11 + m->_22 + m->_33;
    if (tr > 0) {
        float s = sqrtf(tr + 1.0f) * 2;
        out->w = 0.25f * s;
        out->x = (m->_23 - m->_32) / s;
        out->y = (m->_31 - m->_13) / s;
        out->z = (m->_12 - m->_21) / s;
    } else {
        D3DXQuaternionIdentity(out);
    }
    return out;
}

WINAPI_EXPORT D3DXQUATERNION *D3DXQuaternionSlerp(D3DXQUATERNION *out,
    const D3DXQUATERNION *a, const D3DXQUATERNION *b, float t)
{
    if (!out || !a || !b) return out;
    float dot = a->x*b->x + a->y*b->y + a->z*b->z + a->w*b->w;
    int negate_b = 0;
    if (dot < 0) { dot = -dot; negate_b = 1; }
    float s0 = 1.0f - t, s1 = t;
    if (dot < 0.999f) {
        float omega = acosf(dot);
        float sinv = 1.0f / sinf(omega);
        s0 = sinf(s0 * omega) * sinv;
        s1 = sinf(s1 * omega) * sinv;
    }
    if (negate_b) { s1 = -s1; }
    out->x = s0*a->x + s1*b->x;
    out->y = s0*a->y + s1*b->y;
    out->z = s0*a->z + s1*b->z;
    out->w = s0*a->w + s1*b->w;
    return out;
}

WINAPI_EXPORT D3DXCOLOR *D3DXColorLerp(D3DXCOLOR *out, const D3DXCOLOR *a, const D3DXCOLOR *b, float t)
{
    if (!out || !a || !b) return out;
    out->r = a->r + (b->r - a->r) * t;
    out->g = a->g + (b->g - a->g) * t;
    out->b = a->b + (b->b - a->b) * t;
    out->a = a->a + (b->a - a->a) * t;
    return out;
}

WINAPI_EXPORT float D3DXToRadian(float degree) { return degree * 3.14159265f / 180.0f; }
WINAPI_EXPORT float D3DXToDegree(float radian) { return radian * 180.0f / 3.14159265f; }

/* ================================================================== */
/*  D3DX9 Texture/Shader Functions (stubs)                            */
/* ================================================================== */

/* D3DXCreateTextureFromFileA defined in d3d_stubs.c — don't duplicate */

WINAPI_EXPORT HRESULT D3DXCreateTextureFromFileW(void *dev, LPCWSTR file, void **tex)
{
    (void)dev; (void)file;
    if (tex) *tex = NULL;
    return D3DERR_INVALIDCALL;
}

WINAPI_EXPORT HRESULT D3DXCreateTextureFromFileInMemory(void *dev, const void *data,
    UINT size, void **tex)
{
    (void)dev; (void)data; (void)size;
    if (tex) *tex = NULL;
    return D3DERR_INVALIDCALL;
}

WINAPI_EXPORT HRESULT D3DXCreateTextureFromFileInMemoryEx(void *dev, const void *data,
    UINT size, UINT w, UINT h, UINT mip, DWORD usage, int fmt, int pool,
    DWORD filter, DWORD mipfilter, DWORD colorkey, void *info, void *palette, void **tex)
{
    (void)dev; (void)data; (void)size; (void)w; (void)h; (void)mip;
    (void)usage; (void)fmt; (void)pool; (void)filter; (void)mipfilter;
    (void)colorkey; (void)info; (void)palette;
    if (tex) *tex = NULL;
    return D3DERR_INVALIDCALL;
}

WINAPI_EXPORT HRESULT D3DXCreateTextureFromFileExA(void *dev, LPCSTR file,
    UINT w, UINT h, UINT mip, DWORD usage, int fmt, int pool,
    DWORD filter, DWORD mipfilter, DWORD colorkey, void *info, void *palette, void **tex)
{
    (void)dev; (void)file; (void)w; (void)h; (void)mip;
    (void)usage; (void)fmt; (void)pool; (void)filter; (void)mipfilter;
    (void)colorkey; (void)info; (void)palette;
    if (tex) *tex = NULL;
    return D3DERR_INVALIDCALL;
}

WINAPI_EXPORT HRESULT D3DXCreateCubeTextureFromFileA(void *dev, LPCSTR file, void **tex)
{
    (void)dev; (void)file;
    if (tex) *tex = NULL;
    return D3DERR_INVALIDCALL;
}

WINAPI_EXPORT HRESULT D3DXCreateVolumeTextureFromFileA(void *dev, LPCSTR file, void **tex)
{
    (void)dev; (void)file;
    if (tex) *tex = NULL;
    return D3DERR_INVALIDCALL;
}

WINAPI_EXPORT HRESULT D3DXCompileShader(LPCSTR data, UINT len, const void *defines,
    void *include, LPCSTR func, LPCSTR profile, DWORD flags,
    void **code, void **errors, void **constants)
{
    (void)data; (void)len; (void)defines; (void)include;
    (void)func; (void)profile; (void)flags;
    fprintf(stderr, "[d3dx] D3DXCompileShader('%s', '%s'): stub\n",
            func ? func : "(null)", profile ? profile : "(null)");
    if (code) *code = NULL;
    if (errors) *errors = NULL;
    if (constants) *constants = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DXCompileShaderFromFileA(LPCSTR file, const void *defines,
    void *include, LPCSTR func, LPCSTR profile, DWORD flags,
    void **code, void **errors, void **constants)
{
    (void)file; (void)defines; (void)include;
    (void)func; (void)profile; (void)flags;
    if (code) *code = NULL;
    if (errors) *errors = NULL;
    if (constants) *constants = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DXCreateEffect(void *dev, const void *data, UINT len,
    const void *defines, void *include, DWORD flags, void *pool,
    void **effect, void **errors)
{
    (void)dev; (void)data; (void)len; (void)defines; (void)include;
    (void)flags; (void)pool;
    if (effect) *effect = NULL;
    if (errors) *errors = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DXCreateEffectFromFileA(void *dev, LPCSTR file,
    const void *defines, void *include, DWORD flags, void *pool,
    void **effect, void **errors)
{
    (void)dev; (void)file; (void)defines; (void)include;
    (void)flags; (void)pool;
    if (effect) *effect = NULL;
    if (errors) *errors = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DXCreateMesh(DWORD numFaces, DWORD numVertices, DWORD options,
    const void *decl, void *dev, void **mesh)
{
    (void)numFaces; (void)numVertices; (void)options; (void)decl; (void)dev;
    if (mesh) *mesh = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DXCreateSprite(void *dev, void **sprite)
{
    (void)dev;
    if (sprite) *sprite = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DXCreateFontA(void *dev, int height, UINT width, UINT weight,
    UINT mipLevels, int italic, DWORD charSet, DWORD outputPrecision,
    DWORD quality, DWORD pitchAndFamily, LPCSTR faceName, void **font)
{
    (void)dev; (void)height; (void)width; (void)weight; (void)mipLevels;
    (void)italic; (void)charSet; (void)outputPrecision; (void)quality;
    (void)pitchAndFamily; (void)faceName;
    if (font) *font = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DXCreateLine(void *dev, void **line)
{
    (void)dev;
    if (line) *line = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DXSaveSurfaceToFileA(LPCSTR file, int fmt, void *surf,
    const void *palette, const void *rect)
{
    (void)file; (void)fmt; (void)surf; (void)palette; (void)rect;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DXSaveTextureToFileA(LPCSTR file, int fmt, void *tex, const void *palette)
{
    (void)file; (void)fmt; (void)tex; (void)palette;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DXLoadSurfaceFromMemory(void *dst, const void *dstPal,
    const void *dstRect, const void *srcData, int srcFmt, UINT srcPitch,
    const void *srcPal, const void *srcRect, DWORD filter, DWORD colorkey)
{
    (void)dst; (void)dstPal; (void)dstRect; (void)srcData; (void)srcFmt;
    (void)srcPitch; (void)srcPal; (void)srcRect; (void)filter; (void)colorkey;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DXLoadSurfaceFromSurface(void *dst, const void *dstPal,
    const void *dstRect, void *src, const void *srcPal, const void *srcRect,
    DWORD filter, DWORD colorkey)
{
    (void)dst; (void)dstPal; (void)dstRect; (void)src; (void)srcPal;
    (void)srcRect; (void)filter; (void)colorkey;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DXGetImageInfoFromFileA(LPCSTR file, void *info)
{
    (void)file; (void)info;
    return E_FAIL;
}

WINAPI_EXPORT HRESULT D3DXGetImageInfoFromFileInMemory(const void *data, UINT size, void *info)
{
    (void)data; (void)size; (void)info;
    return E_FAIL;
}

WINAPI_EXPORT HRESULT D3DXFilterTexture(void *tex, const void *palette, UINT srcLevel, DWORD filter)
{
    (void)tex; (void)palette; (void)srcLevel; (void)filter;
    return S_OK;
}

/* Misc D3DX stubs */
WINAPI_EXPORT HRESULT D3DXDeclaratorFromFVF(DWORD fvf, void *decl)
{
    (void)fvf; (void)decl;
    return E_NOTIMPL;
}

WINAPI_EXPORT UINT D3DXGetFVFVertexSize(DWORD fvf)
{
    (void)fvf;
    return 32; /* Rough estimate */
}

WINAPI_EXPORT UINT D3DXGetDeclVertexSize(const void *decl, DWORD stream)
{
    (void)decl; (void)stream;
    return 32;
}

/* D3DX10/D3DX11 stubs */
WINAPI_EXPORT HRESULT D3DX11CompileFromFileA(LPCSTR file, const void *defines,
    void *include, LPCSTR func, LPCSTR profile, UINT flags1, UINT flags2,
    void *pump, void **shader, void **errors, void *result)
{
    (void)file; (void)defines; (void)include; (void)func; (void)profile;
    (void)flags1; (void)flags2; (void)pump; (void)result;
    if (shader) *shader = NULL;
    if (errors) *errors = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DX11CreateShaderResourceViewFromFileA(void *dev,
    LPCSTR file, void *loadInfo, void *pump, void **srv, void *result)
{
    (void)dev; (void)file; (void)loadInfo; (void)pump; (void)result;
    if (srv) *srv = NULL;
    return E_NOTIMPL;
}

WINAPI_EXPORT HRESULT D3DX11CreateTextureFromFileA(void *dev, LPCSTR file,
    void *loadInfo, void *pump, void **tex, void *result)
{
    (void)dev; (void)file; (void)loadInfo; (void)pump; (void)result;
    if (tex) *tex = NULL;
    return E_NOTIMPL;
}
