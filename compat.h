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
