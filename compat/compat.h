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

    char *strndup( const char *s1, size_t n) {
        char *copy= (char*)malloc( n+1 );
        memcpy( copy, s1, n );
        copy[n] = 0;
        return copy;
    };

    char* strsep(char **stringp, const char *delim) {
        char *start = *stringp, *p = start ? strpbrk(start, delim) : NULL;
        if (!p) {
            *stringp = NULL;
        } else {
            *p = 0;
            *stringp = p + 1;
        }
        return start;
    }

#ifndef _vscprintf
    int _vscprintf_so(const char * format, va_list pargs) {
        int retval;
        va_list argcopy;
        va_copy(argcopy, pargs);
        retval = vsnprintf(NULL, 0, format, argcopy);
        va_end(argcopy);
        return retval;}
#endif // _vscprintf

#ifndef vasprintf
    int vasprintf(char **strp, const char *fmt, va_list ap) {
        int len = _vscprintf_so(fmt, ap);
        if (len == -1) return -1;
        char *str = malloc((size_t) len + 1);
        if (!str) return -1;
        int r = vsnprintf(str, len + 1, fmt, ap); /* "secure" version of vsprintf */
        if (r == -1) return free(str), -1;
        *strp = str;
        return r;
    }
#endif // vasprintf

#ifndef asprintf
    int asprintf(char *strp[], const char *fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        int r = vasprintf(strp, fmt, ap);
        va_end(ap);
        return r;
    }
#endif // asprintf

#endif // _WIN32

#ifdef __cplusplus
}
#endif

#endif
