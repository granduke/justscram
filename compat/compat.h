#ifndef SCRAM_COMPAT_H
#define SCRAM_COMPAT_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_EXPLICIT_BZERO
    void explicit_bzero(void *, size_t);
#endif

#ifndef HAVE_ARC4RANDOM_BUF
    uint32_t arc4random(void);
    void arc4random_buf(void *_buf, size_t n);
    uint32_t arc4random_uniform(uint32_t upper_bound);
#endif

#ifndef HAVE_FREEZERO
    void freezero(void *ptr, size_t sz);
#endif

#ifndef HAVE_GETENTROPY
    int getentropy(void *buf, size_t len);
#endif

#ifdef _WIN32
    int _vscprintf_so(const char * format, va_list pargs);
    int vasprintf(char **strp, const char *fmt, va_list ap);
    int asprintf(char *strp[], const char *fmt, ...);
    char *strndup( const char *s1, size_t n);
    char* strsep(char **stringp, const char *delim);
#endif

#ifdef __cplusplus
}
#endif

#endif
