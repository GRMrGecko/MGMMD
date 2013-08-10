//
//  MGMRMD256.m
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 5/31/11.
//  No Copyright Claimed. Public Domain.
//  C Algorithm created by Tom St Denis <tomstdenis@gmail.com> <http://libtom.org>
//

#ifdef __NEXT_RUNTIME__
#import "MGMRMD256.h"
#import "MGMTypes.h"

NSString * const MDNRMD256 = @"rmd256";

@implementation NSString (MGMRMD256)
- (NSString *)RMD256 {
	NSData *MDData = [self dataUsingEncoding:NSUTF8StringEncoding];
	struct RMD256Context MDContext;
	unsigned char MDDigest[RMD256Length];
	
	RMD256Init(&MDContext);
	RMD256Update(&MDContext, [MDData bytes], [MDData length]);
	RMD256Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(RMD256Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD256Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	NSString *hash = [NSString stringWithUTF8String:stringBuffer];
	free(stringBuffer);
	return hash;
}
- (NSString *)pathRMD256 {
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:self];
	if (file==nil)
		return nil;
	struct RMD256Context MDContext;
	unsigned char MDDigest[RMD256Length];
	
	RMD256Init(&MDContext);
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *MDData = [file readDataOfLength:MDFileReadLength];
		length = [MDData length];
		RMD256Update(&MDContext, [MDData bytes], length);
		[pool release];
	} while (length>0);
	RMD256Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(RMD256Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD256Length; i++) {
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
#include "MGMRMD256.h"
#include "MGMTypes.h"
#endif

const struct MGMHashDescription RMD256Desc = {
	"rmd256",
    sizeof(struct RMD256Context),
    (void(*)(void *))&RMD256Init,
	(void(*)(void *, const unsigned char *, unsigned))&RMD256Update,
	(void(*)(unsigned char *, void *))&RMD256Final,
	RMD256Length
};

char *RMD256String(const char *string, int length) {
	struct RMD256Context MDContext;
	unsigned char MDDigest[RMD256Length];
	
	RMD256Init(&MDContext);
	RMD256Update(&MDContext, (const unsigned char *)string, length);
	RMD256Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(RMD256Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD256Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}
char *RMD256File(const char *path) {
	FILE *file = fopen(path, "r");
	if (file==NULL)
		return NULL;
	struct RMD256Context MDContext;
	unsigned char MDDigest[RMD256Length];
	
	RMD256Init(&MDContext);
	int length;
	do {
		unsigned char MDData[MDFileReadLength];
		length = fread(&MDData, 1, MDFileReadLength, file);
		RMD256Update(&MDContext, MDData, length);
	} while (length>0);
	RMD256Final(MDDigest, &MDContext);
	
	fclose(file);
	
	char *stringBuffer = (char *)malloc(RMD256Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD256Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}

void RMD256Init(struct RMD256Context *context) {
	context->state[0] = INT32(0x67452301);
	context->state[1] = INT32(0xefcdab89);
	context->state[2] = INT32(0x98badcfe);
	context->state[3] = INT32(0x10325476);
	context->state[4] = INT32(0x76543210);
	context->state[5] = INT32(0xfedcba98);
	context->state[6] = INT32(0x89abcdef);
	context->state[7] = INT32(0x01234567);
	context->curlen = 0;
	context->length = 0;
}

void RMD256Update(struct RMD256Context *context, const unsigned char *buf, unsigned len) {
	if (buf==NULL)
		return;
	unsigned long n;
	while (len>0) {
		if (context->curlen == 0 && len>=RMD256BufferSize) {
			RMD256Transform(context, (unsigned char *)buf);
			context->length += RMD256BufferSize * 8;
			buf += RMD256BufferSize;
			len -= RMD256BufferSize;
		} else {
			n = MIN(len, (RMD256BufferSize-context->curlen));
			memcpy(context->buf+context->curlen, buf, (size_t)n);
			context->curlen += n;
			buf += n;
			len -= n;
			if (context->curlen == RMD256BufferSize) {
				RMD256Transform(context, context->buf);
				context->length += 8*RMD256BufferSize;
				context->curlen = 0;
			}
		}
	}
}

void RMD256Final(unsigned char digest[RMD256Length], struct RMD256Context *context) {
	context->length += context->curlen * 8;
	context->buf[context->curlen++] = (unsigned char)0x80;
	
	if (context->curlen > 56) {
		while (context->curlen < 64) {
			context->buf[context->curlen++] = (unsigned char)0;
		}
		RMD256Transform(context, context->buf);
		context->curlen = 0;
	}
	
	while (context->curlen < 56) {
		context->buf[context->curlen++] = (unsigned char)0;
	}
	
	putu64l(context->length, context->buf+56);
	RMD256Transform(context, context->buf);
	
	for (int i=0; i<8; i++) {
		putu32l(context->state[i], digest+(4*i));
	}
	
	memset(context, 0, sizeof(struct RMD256Context));
}

#define RMD256_S1 0
#define RMD256_S2 INT32(0x5a827999)
#define RMD256_S3 INT32(0x6ed9eba1)
#define RMD256_S4 INT32(0x8f1bbcdc)

#define RMD256_S8 0
#define RMD256_S7 INT32(0x6d703ef3)
#define RMD256_S6 INT32(0x5c4dd124)
#define RMD256_S5 INT32(0x50a28be6)

#define RMD256_F1(x, y, z) ((x) ^ (y) ^ (z))
#define RMD256_F2(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define RMD256_F3(x, y, z) (((x) | ~(y)) ^ (z))
#define RMD256_F4(x, y, z) (((x) & (z)) | ((y) & ~(z)))

#define RMD256STEP(a, b, c, d, e, f, g, h) \
	(c) += a((d), (e), (f)) + (g) + b; (c) = ROL32((c), (h));

void RMD256Transform(struct RMD256Context *context, unsigned char *buf) {
	uint32_t x[16], tmp;
	
	uint32_t a = context->state[0];
	uint32_t b = context->state[1];
	uint32_t c = context->state[2];
	uint32_t d = context->state[3];
	uint32_t aa = context->state[4];
	uint32_t bb = context->state[5];
	uint32_t cc = context->state[6];
	uint32_t dd = context->state[7];
	
	for (int i=0; i<16; i++) {
		x[i] = getu32l(buf+(4*i));
	}
	
	/* round 1 */
	RMD256STEP(RMD256_F1, RMD256_S1, a, b, c, d, x[0], 11);
	RMD256STEP(RMD256_F1, RMD256_S1, d, a, b, c, x[1], 14);
	RMD256STEP(RMD256_F1, RMD256_S1, c, d, a, b, x[2], 15);
	RMD256STEP(RMD256_F1, RMD256_S1, b, c, d, a, x[3], 12);
	RMD256STEP(RMD256_F1, RMD256_S1, a, b, c, d, x[4], 5);
	RMD256STEP(RMD256_F1, RMD256_S1, d, a, b, c, x[5], 8);
	RMD256STEP(RMD256_F1, RMD256_S1, c, d, a, b, x[6], 7);
	RMD256STEP(RMD256_F1, RMD256_S1, b, c, d, a, x[7], 9);
	RMD256STEP(RMD256_F1, RMD256_S1, a, b, c, d, x[8], 11);
	RMD256STEP(RMD256_F1, RMD256_S1, d, a, b, c, x[9], 13);
	RMD256STEP(RMD256_F1, RMD256_S1, c, d, a, b, x[10], 14);
	RMD256STEP(RMD256_F1, RMD256_S1, b, c, d, a, x[11], 15);
	RMD256STEP(RMD256_F1, RMD256_S1, a, b, c, d, x[12], 6);
	RMD256STEP(RMD256_F1, RMD256_S1, d, a, b, c, x[13], 7);
	RMD256STEP(RMD256_F1, RMD256_S1, c, d, a, b, x[14], 9);
	RMD256STEP(RMD256_F1, RMD256_S1, b, c, d, a, x[15], 8);
	
	/* parallel round 1 */
	RMD256STEP(RMD256_F4, RMD256_S5, aa, bb, cc, dd, x[5], 8);
	RMD256STEP(RMD256_F4, RMD256_S5, dd, aa, bb, cc, x[14], 9);
	RMD256STEP(RMD256_F4, RMD256_S5, cc, dd, aa, bb, x[7], 9);
	RMD256STEP(RMD256_F4, RMD256_S5, bb, cc, dd, aa, x[0], 11);
	RMD256STEP(RMD256_F4, RMD256_S5, aa, bb, cc, dd, x[9], 13);
	RMD256STEP(RMD256_F4, RMD256_S5, dd, aa, bb, cc, x[2], 15);
	RMD256STEP(RMD256_F4, RMD256_S5, cc, dd, aa, bb, x[11], 15);
	RMD256STEP(RMD256_F4, RMD256_S5, bb, cc, dd, aa, x[4], 5);
	RMD256STEP(RMD256_F4, RMD256_S5, aa, bb, cc, dd, x[13], 7);
	RMD256STEP(RMD256_F4, RMD256_S5, dd, aa, bb, cc, x[6], 7);
	RMD256STEP(RMD256_F4, RMD256_S5, cc, dd, aa, bb, x[15], 8);
	RMD256STEP(RMD256_F4, RMD256_S5, bb, cc, dd, aa, x[8], 11);
	RMD256STEP(RMD256_F4, RMD256_S5, aa, bb, cc, dd, x[1], 14);
	RMD256STEP(RMD256_F4, RMD256_S5, dd, aa, bb, cc, x[10], 14);
	RMD256STEP(RMD256_F4, RMD256_S5, cc, dd, aa, bb, x[3], 12);
	RMD256STEP(RMD256_F4, RMD256_S5, bb, cc, dd, aa, x[12], 6);
	
	tmp = a; a = aa; aa = tmp;
	
	/* round 2 */
	RMD256STEP(RMD256_F2, RMD256_S2, a, b, c, d, x[7], 7);
	RMD256STEP(RMD256_F2, RMD256_S2, d, a, b, c, x[4], 6);
	RMD256STEP(RMD256_F2, RMD256_S2, c, d, a, b, x[13], 8);
	RMD256STEP(RMD256_F2, RMD256_S2, b, c, d, a, x[1], 13);
	RMD256STEP(RMD256_F2, RMD256_S2, a, b, c, d, x[10], 11);
	RMD256STEP(RMD256_F2, RMD256_S2, d, a, b, c, x[6], 9);
	RMD256STEP(RMD256_F2, RMD256_S2, c, d, a, b, x[15], 7);
	RMD256STEP(RMD256_F2, RMD256_S2, b, c, d, a, x[3], 15);
	RMD256STEP(RMD256_F2, RMD256_S2, a, b, c, d, x[12], 7);
	RMD256STEP(RMD256_F2, RMD256_S2, d, a, b, c, x[0], 12);
	RMD256STEP(RMD256_F2, RMD256_S2, c, d, a, b, x[9], 15);
	RMD256STEP(RMD256_F2, RMD256_S2, b, c, d, a, x[5], 9);
	RMD256STEP(RMD256_F2, RMD256_S2, a, b, c, d, x[2], 11);
	RMD256STEP(RMD256_F2, RMD256_S2, d, a, b, c, x[14], 7);
	RMD256STEP(RMD256_F2, RMD256_S2, c, d, a, b, x[11], 13);
	RMD256STEP(RMD256_F2, RMD256_S2, b, c, d, a, x[8], 12);
	
	/* parallel round 2 */
	RMD256STEP(RMD256_F3, RMD256_S6, aa, bb, cc, dd, x[6], 9);
	RMD256STEP(RMD256_F3, RMD256_S6, dd, aa, bb, cc, x[11], 13);
	RMD256STEP(RMD256_F3, RMD256_S6, cc, dd, aa, bb, x[3], 15);
	RMD256STEP(RMD256_F3, RMD256_S6, bb, cc, dd, aa, x[7], 7);
	RMD256STEP(RMD256_F3, RMD256_S6, aa, bb, cc, dd, x[0], 12);
	RMD256STEP(RMD256_F3, RMD256_S6, dd, aa, bb, cc, x[13], 8);
	RMD256STEP(RMD256_F3, RMD256_S6, cc, dd, aa, bb, x[5], 9);
	RMD256STEP(RMD256_F3, RMD256_S6, bb, cc, dd, aa, x[10], 11);
	RMD256STEP(RMD256_F3, RMD256_S6, aa, bb, cc, dd, x[14], 7);
	RMD256STEP(RMD256_F3, RMD256_S6, dd, aa, bb, cc, x[15], 7);
	RMD256STEP(RMD256_F3, RMD256_S6, cc, dd, aa, bb, x[8], 12);
	RMD256STEP(RMD256_F3, RMD256_S6, bb, cc, dd, aa, x[12], 7);
	RMD256STEP(RMD256_F3, RMD256_S6, aa, bb, cc, dd, x[4], 6);
	RMD256STEP(RMD256_F3, RMD256_S6, dd, aa, bb, cc, x[9], 15);
	RMD256STEP(RMD256_F3, RMD256_S6, cc, dd, aa, bb, x[1], 13);
	RMD256STEP(RMD256_F3, RMD256_S6, bb, cc, dd, aa, x[2], 11);
	
	tmp = b; b = bb; bb = tmp;
	
	/* round 3 */
	RMD256STEP(RMD256_F3, RMD256_S3, a, b, c, d, x[3], 11);
	RMD256STEP(RMD256_F3, RMD256_S3, d, a, b, c, x[10], 13);
	RMD256STEP(RMD256_F3, RMD256_S3, c, d, a, b, x[14], 6);
	RMD256STEP(RMD256_F3, RMD256_S3, b, c, d, a, x[4], 7);
	RMD256STEP(RMD256_F3, RMD256_S3, a, b, c, d, x[9], 14);
	RMD256STEP(RMD256_F3, RMD256_S3, d, a, b, c, x[15], 9);
	RMD256STEP(RMD256_F3, RMD256_S3, c, d, a, b, x[8], 13);
	RMD256STEP(RMD256_F3, RMD256_S3, b, c, d, a, x[1], 15);
	RMD256STEP(RMD256_F3, RMD256_S3, a, b, c, d, x[2], 14);
	RMD256STEP(RMD256_F3, RMD256_S3, d, a, b, c, x[7], 8);
	RMD256STEP(RMD256_F3, RMD256_S3, c, d, a, b, x[0], 13);
	RMD256STEP(RMD256_F3, RMD256_S3, b, c, d, a, x[6], 6);
	RMD256STEP(RMD256_F3, RMD256_S3, a, b, c, d, x[13], 5);
	RMD256STEP(RMD256_F3, RMD256_S3, d, a, b, c, x[11], 12);
	RMD256STEP(RMD256_F3, RMD256_S3, c, d, a, b, x[5], 7);
	RMD256STEP(RMD256_F3, RMD256_S3, b, c, d, a, x[12], 5);
	
	/* parallel round 3 */
	RMD256STEP(RMD256_F2, RMD256_S7, aa, bb, cc, dd, x[15], 9);
	RMD256STEP(RMD256_F2, RMD256_S7, dd, aa, bb, cc, x[5], 7);
	RMD256STEP(RMD256_F2, RMD256_S7, cc, dd, aa, bb, x[1], 15);
	RMD256STEP(RMD256_F2, RMD256_S7, bb, cc, dd, aa, x[3], 11);
	RMD256STEP(RMD256_F2, RMD256_S7, aa, bb, cc, dd, x[7], 8);
	RMD256STEP(RMD256_F2, RMD256_S7, dd, aa, bb, cc, x[14], 6);
	RMD256STEP(RMD256_F2, RMD256_S7, cc, dd, aa, bb, x[6], 6);
	RMD256STEP(RMD256_F2, RMD256_S7, bb, cc, dd, aa, x[9], 14);
	RMD256STEP(RMD256_F2, RMD256_S7, aa, bb, cc, dd, x[11], 12);
	RMD256STEP(RMD256_F2, RMD256_S7, dd, aa, bb, cc, x[8], 13);
	RMD256STEP(RMD256_F2, RMD256_S7, cc, dd, aa, bb, x[12], 5);
	RMD256STEP(RMD256_F2, RMD256_S7, bb, cc, dd, aa, x[2], 14);
	RMD256STEP(RMD256_F2, RMD256_S7, aa, bb, cc, dd, x[10], 13);
	RMD256STEP(RMD256_F2, RMD256_S7, dd, aa, bb, cc, x[0], 13);
	RMD256STEP(RMD256_F2, RMD256_S7, cc, dd, aa, bb, x[4], 7);
	RMD256STEP(RMD256_F2, RMD256_S7, bb, cc, dd, aa, x[13], 5);
	
	tmp = c; c = cc; cc = tmp;
	
	/* round 4 */
	RMD256STEP(RMD256_F4, RMD256_S4, a, b, c, d, x[1], 11);
	RMD256STEP(RMD256_F4, RMD256_S4, d, a, b, c, x[9], 12);
	RMD256STEP(RMD256_F4, RMD256_S4, c, d, a, b, x[11], 14);
	RMD256STEP(RMD256_F4, RMD256_S4, b, c, d, a, x[10], 15);
	RMD256STEP(RMD256_F4, RMD256_S4, a, b, c, d, x[0], 14);
	RMD256STEP(RMD256_F4, RMD256_S4, d, a, b, c, x[8], 15);
	RMD256STEP(RMD256_F4, RMD256_S4, c, d, a, b, x[12], 9);
	RMD256STEP(RMD256_F4, RMD256_S4, b, c, d, a, x[4], 8);
	RMD256STEP(RMD256_F4, RMD256_S4, a, b, c, d, x[13], 9);
	RMD256STEP(RMD256_F4, RMD256_S4, d, a, b, c, x[3], 14);
	RMD256STEP(RMD256_F4, RMD256_S4, c, d, a, b, x[7], 5);
	RMD256STEP(RMD256_F4, RMD256_S4, b, c, d, a, x[15], 6);
	RMD256STEP(RMD256_F4, RMD256_S4, a, b, c, d, x[14], 8);
	RMD256STEP(RMD256_F4, RMD256_S4, d, a, b, c, x[5], 6);
	RMD256STEP(RMD256_F4, RMD256_S4, c, d, a, b, x[6], 5);
	RMD256STEP(RMD256_F4, RMD256_S4, b, c, d, a, x[2], 12);
	
	/* parallel round 4 */
	RMD256STEP(RMD256_F1, RMD256_S8, aa, bb, cc, dd, x[8], 15);
	RMD256STEP(RMD256_F1, RMD256_S8, dd, aa, bb, cc, x[6], 5);
	RMD256STEP(RMD256_F1, RMD256_S8, cc, dd, aa, bb, x[4], 8);
	RMD256STEP(RMD256_F1, RMD256_S8, bb, cc, dd, aa, x[1], 11);
	RMD256STEP(RMD256_F1, RMD256_S8, aa, bb, cc, dd, x[3], 14);
	RMD256STEP(RMD256_F1, RMD256_S8, dd, aa, bb, cc, x[11], 14);
	RMD256STEP(RMD256_F1, RMD256_S8, cc, dd, aa, bb, x[15], 6);
	RMD256STEP(RMD256_F1, RMD256_S8, bb, cc, dd, aa, x[0], 14);
	RMD256STEP(RMD256_F1, RMD256_S8, aa, bb, cc, dd, x[5], 6);
	RMD256STEP(RMD256_F1, RMD256_S8, dd, aa, bb, cc, x[12], 9);
	RMD256STEP(RMD256_F1, RMD256_S8, cc, dd, aa, bb, x[2], 12);
	RMD256STEP(RMD256_F1, RMD256_S8, bb, cc, dd, aa, x[13], 9);
	RMD256STEP(RMD256_F1, RMD256_S8, aa, bb, cc, dd, x[9], 12);
	RMD256STEP(RMD256_F1, RMD256_S8, dd, aa, bb, cc, x[7], 5);
	RMD256STEP(RMD256_F1, RMD256_S8, cc, dd, aa, bb, x[10], 15);
	RMD256STEP(RMD256_F1, RMD256_S8, bb, cc, dd, aa, x[14], 8);
	
	tmp = d; d = dd; dd = tmp;
	
	/* combine results */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += aa;
	context->state[5] += bb;
	context->state[6] += cc;
	context->state[7] += dd;
}

int RMD256Test() {
	static const struct {
		char *msg;
		unsigned char hash[RMD256Length];
	} tests[] = {
		{
			"",
			{0x02,0xba,0x4c,0x4e,0x5f,0x8e,0xcd,0x18,0x77,0xfc,0x52,0xd6,0x4d,0x30,0xe3,0x7a,0x2d,0x97,0x74,0xfb,0x1e,0x5d,0x02,0x63,0x80,0xae,0x01,0x68,0xe3,0xc5,0x52,0x2d}
		},
		{
			"a",
			{0xf9,0x33,0x3e,0x45,0xd8,0x57,0xf5,0xd9,0x0a,0x91,0xba,0xb7,0x0a,0x1e,0xba,0x0c,0xfb,0x1b,0xe4,0xb0,0x78,0x3c,0x9a,0xcf,0xcd,0x88,0x3a,0x91,0x34,0x69,0x29,0x25}
		},
		{
			"abc",
			{0xaf,0xbd,0x6e,0x22,0x8b,0x9d,0x8c,0xbb,0xce,0xf5,0xca,0x2d,0x03,0xe6,0xdb,0xa1,0x0a,0xc0,0xbc,0x7d,0xcb,0xe4,0x68,0x0e,0x1e,0x42,0xd2,0xe9,0x75,0x45,0x9b,0x65}
		},
		{
			"message digest",
			{0x87,0xe9,0x71,0x75,0x9a,0x1c,0xe4,0x7a,0x51,0x4d,0x5c,0x91,0x4c,0x39,0x2c,0x90,0x18,0xc7,0xc4,0x6b,0xc1,0x44,0x65,0x55,0x4a,0xfc,0xdf,0x54,0xa5,0x07,0x0c,0x0e}
		},
		{
			"abcdefghijklmnopqrstuvwxyz",
			{0x64,0x9d,0x30,0x34,0x75,0x1e,0xa2,0x16,0x77,0x6b,0xf9,0xa1,0x8a,0xcc,0x81,0xbc,0x78,0x96,0x11,0x8a,0x51,0x97,0x96,0x87,0x82,0xdd,0x1f,0xd9,0x7d,0x8d,0x51,0x33}
		},
		{
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			{0x57,0x40,0xa4,0x08,0xac,0x16,0xb7,0x20,0xb8,0x44,0x24,0xae,0x93,0x1c,0xbb,0x1f,0xe3,0x63,0xd1,0xd0,0xbf,0x40,0x17,0xf1,0xa8,0x9f,0x7e,0xa6,0xde,0x77,0xa0,0xb8}
		},
		{NULL, {0}}
	};
	
	struct RMD256Context MDContext;
	unsigned char MDDigest[RMD256Length];
	
	for (int i=0; tests[i].msg!=NULL; i++) {
		RMD256Init(&MDContext);
		RMD256Update(&MDContext, (unsigned char *)tests[i].msg, (unsigned long)strlen(tests[i].msg));
		RMD256Final(MDDigest, &MDContext);
		
		if (memcmp(MDDigest, tests[i].hash, RMD256Length))
			return 0;
	}
	
	return 1;
}