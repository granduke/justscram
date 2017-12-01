#include <stdint.h>

#ifndef SCRAM_API
#ifdef __cplusplus
#define SCRAM_API extern "C"
#else
#define SCRAM_API
#endif
#endif

#ifndef HAVE_EXPLICIT_BZERO
SCRAM_API void explicit_bzero(void *, size_t);
#endif

#ifndef HAVE_ARC4RANDOM_BUF
SCRAM_API uint32_t arc4random(void);
SCRAM_API void arc4random_buf(void *_buf, size_t n);
SCRAM_API uint32_t arc4random_uniform(uint32_t upper_bound);
#endif

#ifndef HAVE_FREEZERO
SCRAM_API void freezero(void *ptr, size_t sz);
#endif
