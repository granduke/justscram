/*	$OpenBSD: sha1.h,v 1.1 2012/10/09 12:36:50 jsing Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#ifndef SCRAM_API
#ifdef __cplusplus
#define SCRAM_API extern "C"
#else
#define SCRAM_API
#endif
#endif

#include <stdint.h>

#ifndef _SHA1_H_
#define _SHA1_H_

#define	SHA1_BLOCK_LENGTH		64
#define	SHA1_DIGEST_LENGTH		20

typedef struct {
	uint32_t	state[5];
	uint64_t	count;
	unsigned char	buffer[SHA1_BLOCK_LENGTH];
} SHA1_CTX;

SCRAM_API void SHA1Init(SHA1_CTX * context);
SCRAM_API void SHA1Transform(uint32_t state[5], const unsigned char buffer[SHA1_BLOCK_LENGTH]);
SCRAM_API void SHA1Update(SHA1_CTX *context, const unsigned char *data, unsigned int len);
SCRAM_API void SHA1Final(unsigned char digest[SHA1_DIGEST_LENGTH], SHA1_CTX *context);

#endif /* _SHA1_H_ */
