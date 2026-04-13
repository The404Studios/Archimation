/*
 * msvcrt_math.c - MSVCRT math function wrappers
 */

#include <stdio.h>
#include <math.h>
#include <float.h>

#include "common/dll_common.h"

WINAPI_EXPORT int _isnan(double x)
{
    return isnan(x);
}

WINAPI_EXPORT int _isnanf(float x)
{
    return isnan(x);
}

WINAPI_EXPORT int _finite(double x)
{
    return isfinite(x);
}

WINAPI_EXPORT int _finitef(float x)
{
    return isfinite(x);
}

WINAPI_EXPORT double _copysign(double x, double y)
{
    return copysign(x, y);
}

WINAPI_EXPORT float _copysignf(float x, float y)
{
    return copysignf(x, y);
}

/* _fpclass values */
#define _FPCLASS_SNAN   0x0001
#define _FPCLASS_QNAN   0x0002
#define _FPCLASS_NINF   0x0004
#define _FPCLASS_NN     0x0008
#define _FPCLASS_ND     0x0010
#define _FPCLASS_NZ     0x0020
#define _FPCLASS_PZ     0x0040
#define _FPCLASS_PD     0x0080
#define _FPCLASS_PN     0x0100
#define _FPCLASS_PINF   0x0200

WINAPI_EXPORT int _fpclass(double x)
{
    int c = fpclassify(x);
    switch (c) {
    case FP_NAN:       return _FPCLASS_QNAN;
    case FP_INFINITE:  return signbit(x) ? _FPCLASS_NINF : _FPCLASS_PINF;
    case FP_ZERO:      return signbit(x) ? _FPCLASS_NZ : _FPCLASS_PZ;
    case FP_SUBNORMAL: return signbit(x) ? _FPCLASS_ND : _FPCLASS_PD;
    case FP_NORMAL:    return signbit(x) ? _FPCLASS_NN : _FPCLASS_PN;
    default:           return _FPCLASS_QNAN;
    }
}

WINAPI_EXPORT double _ldexp(double x, int exp)
{
    return ldexp(x, exp);
}

WINAPI_EXPORT double _frexp(double x, int *expptr)
{
    return frexp(x, expptr);
}

WINAPI_EXPORT double _logb(double x)
{
    return logb(x);
}

WINAPI_EXPORT float _logbf(float x)
{
    return logbf(x);
}

WINAPI_EXPORT double _scalb(double x, long exp)
{
    return scalbn(x, (int)exp);
}

WINAPI_EXPORT double _hypot(double x, double y)
{
    return hypot(x, y);
}

WINAPI_EXPORT float _hypotf(float x, float y)
{
    return hypotf(x, y);
}

WINAPI_EXPORT double _nextafter(double x, double y)
{
    return nextafter(x, y);
}

WINAPI_EXPORT double _chgsign(double x)
{
    return -x;
}

WINAPI_EXPORT int _fpreset(void)
{
    return 0;
}

WINAPI_EXPORT unsigned int _clearfp(void)
{
    return 0;
}

WINAPI_EXPORT unsigned int _statusfp(void)
{
    return 0;
}

WINAPI_EXPORT int __fpecode(void)
{
    return 0;
}

/* _CIxxx - internal compiler intrinsics for math */
WINAPI_EXPORT double _CIacos(double x) { return acos(x); }
WINAPI_EXPORT double _CIasin(double x) { return asin(x); }
WINAPI_EXPORT double _CIatan(double x) { return atan(x); }
WINAPI_EXPORT double _CIatan2(double y, double x) { return atan2(y, x); }
WINAPI_EXPORT double _CIcos(double x) { return cos(x); }
WINAPI_EXPORT double _CIcosh(double x) { return cosh(x); }
WINAPI_EXPORT double _CIexp(double x) { return exp(x); }
WINAPI_EXPORT double _CIfmod(double x, double y) { return fmod(x, y); }
WINAPI_EXPORT double _CIlog(double x) { return log(x); }
WINAPI_EXPORT double _CIlog10(double x) { return log10(x); }
WINAPI_EXPORT double _CIpow(double x, double y) { return pow(x, y); }
WINAPI_EXPORT double _CIsin(double x) { return sin(x); }
WINAPI_EXPORT double _CIsinh(double x) { return sinh(x); }
WINAPI_EXPORT double _CIsqrt(double x) { return sqrt(x); }
WINAPI_EXPORT double _CItan(double x) { return tan(x); }
WINAPI_EXPORT double _CItanh(double x) { return tanh(x); }

/* _dclass / _fdclass - classify float/double */
WINAPI_EXPORT short _dclass(double x)
{
    return (short)fpclassify(x);
}

WINAPI_EXPORT short _fdclass(float x)
{
    return (short)fpclassify(x);
}

/* _dsign / _fdsign */
WINAPI_EXPORT int _dsign(double x)
{
    return signbit(x) ? 1 : 0;
}

WINAPI_EXPORT int _fdsign(float x)
{
    return signbit(x) ? 1 : 0;
}

/* _dpcomp / _fdpcomp - compare with NaN awareness */
WINAPI_EXPORT int _dpcomp(double x, double y)
{
    if (isnan(x) || isnan(y)) return 0;
    if (x < y) return 1;
    if (x == y) return 2;
    return 4; /* x > y */
}

WINAPI_EXPORT int _fdpcomp(float x, float y)
{
    if (isnan(x) || isnan(y)) return 0;
    if (x < y) return 1;
    if (x == y) return 2;
    return 4;
}
