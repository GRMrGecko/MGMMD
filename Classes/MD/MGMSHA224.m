//
//  MGMSHA224.m
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 2/24/10.
//  No Copyright Claimed. Public Domain.
//  C Algorithm created by Tom St Denis <tomstdenis@gmail.com> <http://libtom.org>
//

#ifdef __NEXT_RUNTIME__
#import "MGMSHA224.h"
#import "MGMTypes.h"

NSString * const MDNSHA224 = @"sha224";

@implementation NSString (MGMSHA224)
- (NSString *)SHA224 {
	NSData *MDData = [self dataUsingEncoding:NSUTF8StringEncoding];
	struct SHA224Context MDContext;
	unsigned char MDDigest[SHA224Length];
	
	SHA224Init(&MDContext);
	SHA224Update(&MDContext, [MDData bytes], [MDData length]);
	SHA224Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA224Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA224Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	NSString *hash = [NSString stringWithUTF8String:stringBuffer];
	free(stringBuffer);
	return hash;
}
- (NSString *)pathSHA224 {
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:self];
	if (file==nil)
		return nil;
	struct SHA224Context MDContext;
	unsigned char MDDigest[SHA224Length];
	
	SHA224Init(&MDContext);
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *MDData = [file readDataOfLength:MDFileReadLength];
		length = [MDData length];
		SHA224Update(&MDContext, [MDData bytes], length);
		[pool release];
	} while (length>0);
	SHA224Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA224Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA224Length; i++) {
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
#include "MGMMD5.h"
#include "MGMTypes.h"
#endif

char *SHA224String(const char *string, int length) {
	struct SHA224Context MDContext;
	unsigned char MDDigest[SHA224Length];
	
	SHA224Init(&MDContext);
	SHA224Update(&MDContext, (const unsigned char *)string, length);
	SHA224Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA224Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA224Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}
char *SHA224File(const char *path) {
	FILE *file = fopen(path, "r");
	if (file==NULL)
		return NULL;
	struct SHA224Context MDContext;
	unsigned char MDDigest[SHA224Length];
	
	SHA224Init(&MDContext);
	int length;
	do {
		unsigned char MDData[MDFileReadLength];
		length = fread(&MDData, 1, MDFileReadLength, file);
		SHA224Update(&MDContext, MDData, length);
	} while (length>0);
	SHA224Final(MDDigest, &MDContext);
	
	fclose(file);
	
	char *stringBuffer = (char *)malloc(SHA224Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA224Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}

void SHA224Init(struct SHA224Context *context) {
	context->buf[0] = 0xc1059ed8;
	context->buf[1] = 0x367cd507;
	context->buf[2] = 0x3070dd17;
	context->buf[3] = 0xf70e5939;
	context->buf[4] = 0xffc00b31;
	context->buf[5] = 0x68581511;
	context->buf[6] = 0x64f98fa7;
	context->buf[7] = 0xbefa4fa4;
	
	context->bits[0] = 0;
	context->bits[1] = 0;
}

void SHA224Update(struct SHA224Context *context, const unsigned char *buf, unsigned int len) {
	uint32_t t;
	
	t = context->bits[0];
	if ((context->bits[0] = (t + ((uint32_t)len << 3))) < t)
		context->bits[1]++;
	context->bits[1] += len >> 29;
	
	t = (t >> 3) & 0x3f;
	
	if (t!=0) {
		unsigned char *p = context->in + t;
		
		t = 64-t;
		if (len < t) {
			memcpy(p, buf, len);
			return;
		}
		memcpy(p, buf, t);
		SHA224Transform(context->buf, context->in);
		buf += t;
		len -= t;
	}
	
	while (len >= 64) {
		memcpy(context->in, buf, 64);
		SHA224Transform(context->buf, context->in);
		buf += 64;
		len -= 64;
	}
	
	memcpy(context->in, buf, len);
}

void SHA224Final(unsigned char digest[SHA224Length], struct SHA224Context *context) {
	unsigned char bits[8];
	unsigned int count;
	
	putu32(context->bits[1], bits);
	putu32(context->bits[0], bits + 4);
	
	count = (context->bits[0] >> 3) & 0x3f;
	count = (count < 56) ? (56 - count) : (120 - count);
	SHA224Update(context, MDPadding, count);
	
	SHA224Update(context, bits, 8);
	
	for (int i=0; i<7; i++)
		putu32(context->buf[i], digest + (4 * i));
	
	memset(context, 0, sizeof(context));
}

/* #define SHA224_F1(x, y, z) (x & y | ~x & z) */
#define SHA224_F1(x,y,z) (z ^ (x & (y ^ z)))
#define SHA224_F2(x,y,z) (((x | y) & z) | (x & y))
// SUM0
#define SHA224_F3(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
// SUM1
#define SHA224_F4(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
// OM0
#define SHA224_F5(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ SHR(x, 3))
// OM1
#define SHA224_F6(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ SHR(x, 10))

static const uint32_t SHA224_Key[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define SHA224STEP(a, b, c, d, e, f, g, h, s) \
	t1 = h + SHA224_F4(e) + SHA224_F1(e, f, g) + SHA224_Key[s] + in[s]; \
	t2 = SHA224_F3(a) + SHA224_F2(a, b, c); \
	d += t1; \
	h = t1 + t2;

void SHA224Transform(uint32_t buf[SHA224BufferSize], const unsigned char inraw[64]) {
	uint32_t in[64], t1, t2;
	int i;
	
	uint32_t a = buf[0];
	uint32_t b = buf[1];
	uint32_t c = buf[2];
	uint32_t d = buf[3];
	uint32_t e = buf[4];
	uint32_t f = buf[5];
	uint32_t g = buf[6];
	uint32_t h = buf[7];
	
	for (i = 0; i < 16; i++)
		in[i] = getu32(inraw+4*i);
	
	for (i = 16; i < 64; i++)
		in[i] = SHA224_F6(in[i - 2]) + in[i - 7] + SHA224_F5(in[i - 15]) + in[i - 16];
	
	for (int i=0; i<64; i = i+8) {
		SHA224STEP(a, b, c, d, e, f, g, h, i);
		SHA224STEP(h, a, b, c, d, e, f, g, i + 1);
		SHA224STEP(g, h, a, b, c, d, e, f, i + 2);
		SHA224STEP(f, g, h, a, b, c, d, e, i + 3);
		SHA224STEP(e, f, g, h, a, b, c, d, i + 4);
		SHA224STEP(d, e, f, g, h, a, b, c, i + 5);
		SHA224STEP(c, d, e, f, g, h, a, b, i + 6);
		SHA224STEP(b, c, d, e, f, g, h, a, i + 7);
	}
		
	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
	buf[4] += e;
	buf[5] += f;
	buf[6] += g;
	buf[7] += h;
}