//
//  MGMSHA256.m
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 2/24/10.
//  No Copyright Claimed. Public Domain.
//  C Algorithm created by Tom St Denis <tomstdenis@gmail.com> <http://libtom.org>
//

#ifdef __NEXT_RUNTIME__
#import "MGMSHA256.h"
#import "MGMTypes.h"

NSString * const MDNSHA256 = @"sha256";

@implementation NSString (MGMSHA256)
- (NSString *)SHA256 {
	NSData *MDData = [self dataUsingEncoding:NSUTF8StringEncoding];
	struct SHA256Context MDContext;
	unsigned char MDDigest[SHA256Length];
	
	SHA256Init(&MDContext);
	SHA256Update(&MDContext, [MDData bytes], [MDData length]);
	SHA256Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA256Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA256Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	NSString *hash = [NSString stringWithUTF8String:stringBuffer];
	free(stringBuffer);
	return hash;
}
- (NSString *)pathSHA256 {
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:self];
	if (file==nil)
		return nil;
	struct SHA256Context MDContext;
	unsigned char MDDigest[SHA256Length];
	
	SHA256Init(&MDContext);
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *MDData = [file readDataOfLength:MDFileReadLength];
		length = [MDData length];
		SHA256Update(&MDContext, [MDData bytes], length);
		[pool release];
	} while (length>0);
	SHA256Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA256Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA256Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	NSString *hash = [NSString stringWithUTF8String:stringBuffer];
	free(stringBuffer);
	return hash;
}
@end
#else
#include <stdio.h>
#include <string.h>
#include "MGMSHA256.h"
#include "MGMTypes.h"
#endif

const struct MGMHashDescription SHA256Desc = {
	"sha256",
    sizeof(struct SHA256Context),
    (void(*)(void *))&SHA256Init,
	(void(*)(void *, const unsigned char *, unsigned))&SHA256Update,
	(void(*)(unsigned char *, void *))&SHA256Final,
	SHA256Length
};

char *SHA256String(const char *string, int length) {
	struct SHA256Context MDContext;
	unsigned char MDDigest[SHA256Length];
	
	SHA256Init(&MDContext);
	SHA256Update(&MDContext, (const unsigned char *)string, length);
	SHA256Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA256Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA256Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}
char *SHA256File(const char *path) {
	FILE *file = fopen(path, "r");
	if (file==NULL)
		return NULL;
	struct SHA256Context MDContext;
	unsigned char MDDigest[SHA256Length];
	
	SHA256Init(&MDContext);
	int length;
	do {
		unsigned char MDData[MDFileReadLength];
		length = fread(&MDData, 1, MDFileReadLength, file);
		SHA256Update(&MDContext, MDData, length);
	} while (length>0);
	SHA256Final(MDDigest, &MDContext);
	
	fclose(file);
	
	char *stringBuffer = (char *)malloc(SHA256Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA256Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}

void SHA256Init(struct SHA256Context *context) {
	context->state[0] = INT32(0x6a09e667);
	context->state[1] = INT32(0xbb67ae85);
	context->state[2] = INT32(0x3c6ef372);
	context->state[3] = INT32(0xa54ff53a);
	context->state[4] = INT32(0x510e527f);
	context->state[5] = INT32(0x9b05688c);
	context->state[6] = INT32(0x1f83d9ab);
	context->state[7] = INT32(0x5be0cd19);
	
	context->curlen = 0;
	context->length = 0;
}

void SHA256Update(struct SHA256Context *context, const unsigned char *buf, unsigned int len) {
	if (buf==NULL)
		return;
	unsigned long n;
	while (len>0) {
		if (context->curlen == 0 && len>=SHA256BufferSize) {
			SHA256Transform(context, (unsigned char *)buf);
			context->length += SHA256BufferSize * 8;
			buf += SHA256BufferSize;
			len -= SHA256BufferSize;
		} else {
			n = MIN(len, (SHA256BufferSize-context->curlen));
			memcpy(context->buf+context->curlen, buf, (size_t)n);
			context->curlen += n;
			buf += n;
			len -= n;
			if (context->curlen == SHA256BufferSize) {
				SHA256Transform(context, context->buf);
				context->length += 8*SHA256BufferSize;
				context->curlen = 0;
			}
		}
	}
}

void SHA256Final(unsigned char digest[SHA256Length], struct SHA256Context *context) {
	context->length += context->curlen * 8;
	context->buf[context->curlen++] = (unsigned char)0x80;
	
	if (context->curlen > 56) {
		while (context->curlen < 64) {
			context->buf[context->curlen++] = (unsigned char)0;
		}
		SHA256Transform(context, context->buf);
		context->curlen = 0;
	}
	
	while (context->curlen < 56) {
		context->buf[context->curlen++] = (unsigned char)0;
	}
	
	putu64(context->length, context->buf+56);
	SHA256Transform(context, context->buf);
	
	for (int i=0; i<8; i++) {
		putu32(context->state[i], digest+(4*i));
	}
	
	memset(context, 0, sizeof(struct SHA256Context));
}

/* #define SHA256_F1(x, y, z) (x & y | ~x & z) */
#define SHA256_F1(x,y,z) (z ^ (x & (y ^ z)))
#define SHA256_F2(x,y,z) (((x | y) & z) | (x & y))
// SUM0
#define SHA256_F3(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
// SUM1
#define SHA256_F4(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
// OM0
#define SHA256_F5(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ SHR(x, 3))
// OM1
#define SHA256_F6(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ SHR(x, 10))

static const uint32_t SHA256_Key[64] = {
	INT32(0x428a2f98), INT32(0x71374491), INT32(0xb5c0fbcf), INT32(0xe9b5dba5), INT32(0x3956c25b), INT32(0x59f111f1), INT32(0x923f82a4), INT32(0xab1c5ed5),
	INT32(0xd807aa98), INT32(0x12835b01), INT32(0x243185be), INT32(0x550c7dc3), INT32(0x72be5d74), INT32(0x80deb1fe), INT32(0x9bdc06a7), INT32(0xc19bf174),
	INT32(0xe49b69c1), INT32(0xefbe4786), INT32(0x0fc19dc6), INT32(0x240ca1cc), INT32(0x2de92c6f), INT32(0x4a7484aa), INT32(0x5cb0a9dc), INT32(0x76f988da),
	INT32(0x983e5152), INT32(0xa831c66d), INT32(0xb00327c8), INT32(0xbf597fc7), INT32(0xc6e00bf3), INT32(0xd5a79147), INT32(0x06ca6351), INT32(0x14292967),
	INT32(0x27b70a85), INT32(0x2e1b2138), INT32(0x4d2c6dfc), INT32(0x53380d13), INT32(0x650a7354), INT32(0x766a0abb), INT32(0x81c2c92e), INT32(0x92722c85),
	INT32(0xa2bfe8a1), INT32(0xa81a664b), INT32(0xc24b8b70), INT32(0xc76c51a3), INT32(0xd192e819), INT32(0xd6990624), INT32(0xf40e3585), INT32(0x106aa070),
	INT32(0x19a4c116), INT32(0x1e376c08), INT32(0x2748774c), INT32(0x34b0bcb5), INT32(0x391c0cb3), INT32(0x4ed8aa4a), INT32(0x5b9cca4f), INT32(0x682e6ff3),
	INT32(0x748f82ee), INT32(0x78a5636f), INT32(0x84c87814), INT32(0x8cc70208), INT32(0x90befffa), INT32(0xa4506ceb), INT32(0xbef9a3f7), INT32(0xc67178f2)
};

#define SHA256STEP(a, b, c, d, e, f, g, h, s) \
	t1 = h + SHA256_F4(e) + SHA256_F1(e, f, g) + SHA256_Key[s] + x[s]; \
	t2 = SHA256_F3(a) + SHA256_F2(a, b, c); \
	d += t1; \
	h = t1 + t2;

void SHA256Transform(struct SHA256Context *context, unsigned char *buf) {
	uint32_t x[64], t1, t2;
	int i;
	
	uint32_t a = context->state[0];
	uint32_t b = context->state[1];
	uint32_t c = context->state[2];
	uint32_t d = context->state[3];
	uint32_t e = context->state[4];
	uint32_t f = context->state[5];
	uint32_t g = context->state[6];
	uint32_t h = context->state[7];
	
	for (i = 0; i < 16; i++)
		x[i] = getu32(buf+(4*i));
	
	for (i = 16; i < 64; i++)
		x[i] = SHA256_F6(x[i - 2]) + x[i - 7] + SHA256_F5(x[i - 15]) + x[i - 16];
	
	for (int i=0; i<64; i = i + 8) {
		SHA256STEP(a, b, c, d, e, f, g, h, i);
		SHA256STEP(h, a, b, c, d, e, f, g, i + 1);
		SHA256STEP(g, h, a, b, c, d, e, f, i + 2);
		SHA256STEP(f, g, h, a, b, c, d, e, i + 3);
		SHA256STEP(e, f, g, h, a, b, c, d, i + 4);
		SHA256STEP(d, e, f, g, h, a, b, c, i + 5);
		SHA256STEP(c, d, e, f, g, h, a, b, i + 6);
		SHA256STEP(b, c, d, e, f, g, h, a, i + 7);
	}
		
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;
}

int SHA256Test() {
	static const struct {
		char *msg;
		unsigned char hash[SHA256Length];
	} tests[] = {
		{
			"abc",
			{0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad}
		},
		{
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			{0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1}
		},
		{NULL, {0}}
	};
	
	struct SHA256Context MDContext;
	unsigned char MDDigest[SHA256Length];
	
	for (int i=0; tests[i].msg!=NULL; i++) {
		SHA256Init(&MDContext);
		SHA256Update(&MDContext, (unsigned char *)tests[i].msg, (unsigned long)strlen(tests[i].msg));
		SHA256Final(MDDigest, &MDContext);
		
		if (memcmp(MDDigest, tests[i].hash, SHA256Length))
			return 0;
	}
	
	return 1;
}