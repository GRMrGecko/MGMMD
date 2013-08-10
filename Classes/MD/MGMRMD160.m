//
//  MGMRMD160.m
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 5/31/11.
//  No Copyright Claimed. Public Domain.
//  C Algorithm created by Tom St Denis <tomstdenis@gmail.com> <http://libtom.org>
//

#ifdef __NEXT_RUNTIME__
#import "MGMRMD160.h"
#import "MGMTypes.h"

NSString * const MDNRMD160 = @"rmd160";

@implementation NSString (MGMRMD160)
- (NSString *)RMD160 {
	NSData *MDData = [self dataUsingEncoding:NSUTF8StringEncoding];
	struct RMD160Context MDContext;
	unsigned char MDDigest[RMD160Length];
	
	RMD160Init(&MDContext);
	RMD160Update(&MDContext, [MDData bytes], [MDData length]);
	RMD160Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(RMD160Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD160Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	NSString *hash = [NSString stringWithUTF8String:stringBuffer];
	free(stringBuffer);
	return hash;
}
- (NSString *)pathRMD160 {
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:self];
	if (file==nil)
		return nil;
	struct RMD160Context MDContext;
	unsigned char MDDigest[RMD160Length];
	
	RMD160Init(&MDContext);
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *MDData = [file readDataOfLength:MDFileReadLength];
		length = [MDData length];
		RMD160Update(&MDContext, [MDData bytes], length);
		[pool release];
	} while (length>0);
	RMD160Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(RMD160Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD160Length; i++) {
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
#include "MGMRMD160.h"
#include "MGMTypes.h"
#endif

const struct MGMHashDescription RMD160Desc = {
	"rmd160",
    sizeof(struct RMD160Context),
    (void(*)(void *))&RMD160Init,
	(void(*)(void *, const unsigned char *, unsigned))&RMD160Update,
	(void(*)(unsigned char *, void *))&RMD160Final,
	RMD160Length
};

char *RMD160String(const char *string, int length) {
	struct RMD160Context MDContext;
	unsigned char MDDigest[RMD160Length];
	
	RMD160Init(&MDContext);
	RMD160Update(&MDContext, (const unsigned char *)string, length);
	RMD160Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(RMD160Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD160Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}
char *RMD160File(const char *path) {
	FILE *file = fopen(path, "r");
	if (file==NULL)
		return NULL;
	struct RMD160Context MDContext;
	unsigned char MDDigest[RMD160Length];
	
	RMD160Init(&MDContext);
	int length;
	do {
		unsigned char MDData[MDFileReadLength];
		length = fread(&MDData, 1, MDFileReadLength, file);
		RMD160Update(&MDContext, MDData, length);
	} while (length>0);
	RMD160Final(MDDigest, &MDContext);
	
	fclose(file);
	
	char *stringBuffer = (char *)malloc(RMD160Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD160Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}

void RMD160Init(struct RMD160Context *context) {
	context->state[0] = INT32(0x67452301);
	context->state[1] = INT32(0xefcdab89);
	context->state[2] = INT32(0x98badcfe);
	context->state[3] = INT32(0x10325476);
	context->state[4] = INT32(0xc3d2e1f0);
	context->curlen = 0;
	context->length = 0;
}

void RMD160Update(struct RMD160Context *context, const unsigned char *buf, unsigned len) {
	if (buf==NULL)
		return;
	unsigned long n;
	while (len>0) {
		if (context->curlen == 0 && len>=RMD160BufferSize) {
			RMD160Transform(context, (unsigned char *)buf);
			context->length += RMD160BufferSize * 8;
			buf += RMD160BufferSize;
			len -= RMD160BufferSize;
		} else {
			n = MIN(len, (RMD160BufferSize-context->curlen));
			memcpy(context->buf+context->curlen, buf, (size_t)n);
			context->curlen += n;
			buf += n;
			len -= n;
			if (context->curlen == RMD160BufferSize) {
				RMD160Transform(context, context->buf);
				context->length += 8*RMD160BufferSize;
				context->curlen = 0;
			}
		}
	}
}

void RMD160Final(unsigned char digest[RMD160Length], struct RMD160Context *context) {
	context->length += context->curlen * 8;
	context->buf[context->curlen++] = (unsigned char)0x80;
	
	if (context->curlen > 56) {
		while (context->curlen < 64) {
			context->buf[context->curlen++] = (unsigned char)0;
		}
		RMD160Transform(context, context->buf);
		context->curlen = 0;
	}
	
	while (context->curlen < 56) {
		context->buf[context->curlen++] = (unsigned char)0;
	}
	
	putu64l(context->length, context->buf+56);
	RMD160Transform(context, context->buf);
	
	for (int i=0; i<5; i++) {
		putu32l(context->state[i], digest+(4*i));
	}
	
	memset(context, 0, sizeof(struct RMD160Context));
}

#define RMD160_S1 0
#define RMD160_S2 INT32(0x5a827999)
#define RMD160_S3 INT32(0x6ed9eba1)
#define RMD160_S4 INT32(0x8f1bbcdc)
#define RMD160_S5 INT32(0xa953fd4e)

#define RMD160_S10 0
#define RMD160_S9 INT32(0x7a6d76e9)
#define RMD160_S8 INT32(0x6d703ef3)
#define RMD160_S7 INT32(0x5c4dd124)
#define RMD160_S6 INT32(0x50a28be6)

#define RMD160_F1(x, y, z) ((x) ^ (y) ^ (z))
#define RMD160_F2(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define RMD160_F3(x, y, z) (((x) | ~(y)) ^ (z))
#define RMD160_F4(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define RMD160_F5(x, y, z) ((x) ^ ((y) | ~(z)))

#define RMD160STEP(a, b, c, d, e, f, g, h, i) \
	(c) += a((d), (e), (f)) + (h) + b; (c) = ROL32((c), (i)) + (g); (e) = ROL32((e), 10);

void RMD160Transform(struct RMD160Context *context, unsigned char *buf) {
	uint32_t x[16];
	
	uint32_t a = context->state[0], aa = a;
	uint32_t b = context->state[1], bb = b;
	uint32_t c = context->state[2], cc = c;
	uint32_t d = context->state[3], dd = d;
	uint32_t e = context->state[4], ee = e;
	
	for (int i=0; i<16; i++) {
		x[i] = getu32l(buf+(4*i));
	}
	
	/* round 1 */
	RMD160STEP(RMD160_F1, RMD160_S1, a, b, c, d, e, x[0], 11);
	RMD160STEP(RMD160_F1, RMD160_S1, e, a, b, c, d, x[1], 14);
	RMD160STEP(RMD160_F1, RMD160_S1, d, e, a, b, c, x[2], 15);
	RMD160STEP(RMD160_F1, RMD160_S1, c, d, e, a, b, x[3], 12);
	RMD160STEP(RMD160_F1, RMD160_S1, b, c, d, e, a, x[4], 5);
	RMD160STEP(RMD160_F1, RMD160_S1, a, b, c, d, e, x[5], 8);
	RMD160STEP(RMD160_F1, RMD160_S1, e, a, b, c, d, x[6], 7);
	RMD160STEP(RMD160_F1, RMD160_S1, d, e, a, b, c, x[7], 9);
	RMD160STEP(RMD160_F1, RMD160_S1, c, d, e, a, b, x[8], 11);
	RMD160STEP(RMD160_F1, RMD160_S1, b, c, d, e, a, x[9], 13);
	RMD160STEP(RMD160_F1, RMD160_S1, a, b, c, d, e, x[10], 14);
	RMD160STEP(RMD160_F1, RMD160_S1, e, a, b, c, d, x[11], 15);
	RMD160STEP(RMD160_F1, RMD160_S1, d, e, a, b, c, x[12], 6);
	RMD160STEP(RMD160_F1, RMD160_S1, c, d, e, a, b, x[13], 7);
	RMD160STEP(RMD160_F1, RMD160_S1, b, c, d, e, a, x[14], 9);
	RMD160STEP(RMD160_F1, RMD160_S1, a, b, c, d, e, x[15], 8);
	
	/* round 2 */
	RMD160STEP(RMD160_F2, RMD160_S2, e, a, b, c, d, x[7], 7);
	RMD160STEP(RMD160_F2, RMD160_S2, d, e, a, b, c, x[4], 6);
	RMD160STEP(RMD160_F2, RMD160_S2, c, d, e, a, b, x[13], 8);
	RMD160STEP(RMD160_F2, RMD160_S2, b, c, d, e, a, x[1], 13);
	RMD160STEP(RMD160_F2, RMD160_S2, a, b, c, d, e, x[10], 11);
	RMD160STEP(RMD160_F2, RMD160_S2, e, a, b, c, d, x[6], 9);
	RMD160STEP(RMD160_F2, RMD160_S2, d, e, a, b, c, x[15], 7);
	RMD160STEP(RMD160_F2, RMD160_S2, c, d, e, a, b, x[3], 15);
	RMD160STEP(RMD160_F2, RMD160_S2, b, c, d, e, a, x[12], 7);
	RMD160STEP(RMD160_F2, RMD160_S2, a, b, c, d, e, x[0], 12);
	RMD160STEP(RMD160_F2, RMD160_S2, e, a, b, c, d, x[9], 15);
	RMD160STEP(RMD160_F2, RMD160_S2, d, e, a, b, c, x[5], 9);
	RMD160STEP(RMD160_F2, RMD160_S2, c, d, e, a, b, x[2], 11);
	RMD160STEP(RMD160_F2, RMD160_S2, b, c, d, e, a, x[14], 7);
	RMD160STEP(RMD160_F2, RMD160_S2, a, b, c, d, e, x[11], 13);
	RMD160STEP(RMD160_F2, RMD160_S2, e, a, b, c, d, x[8], 12);
	
	/* round 3 */
	RMD160STEP(RMD160_F3, RMD160_S3, d, e, a, b, c, x[3], 11);
	RMD160STEP(RMD160_F3, RMD160_S3, c, d, e, a, b, x[10], 13);
	RMD160STEP(RMD160_F3, RMD160_S3, b, c, d, e, a, x[14], 6);
	RMD160STEP(RMD160_F3, RMD160_S3, a, b, c, d, e, x[4], 7);
	RMD160STEP(RMD160_F3, RMD160_S3, e, a, b, c, d, x[9], 14);
	RMD160STEP(RMD160_F3, RMD160_S3, d, e, a, b, c, x[15], 9);
	RMD160STEP(RMD160_F3, RMD160_S3, c, d, e, a, b, x[8], 13);
	RMD160STEP(RMD160_F3, RMD160_S3, b, c, d, e, a, x[1], 15);
	RMD160STEP(RMD160_F3, RMD160_S3, a, b, c, d, e, x[2], 14);
	RMD160STEP(RMD160_F3, RMD160_S3, e, a, b, c, d, x[7], 8);
	RMD160STEP(RMD160_F3, RMD160_S3, d, e, a, b, c, x[0], 13);
	RMD160STEP(RMD160_F3, RMD160_S3, c, d, e, a, b, x[6], 6);
	RMD160STEP(RMD160_F3, RMD160_S3, b, c, d, e, a, x[13], 5);
	RMD160STEP(RMD160_F3, RMD160_S3, a, b, c, d, e, x[11], 12);
	RMD160STEP(RMD160_F3, RMD160_S3, e, a, b, c, d, x[5], 7);
	RMD160STEP(RMD160_F3, RMD160_S3, d, e, a, b, c, x[12], 5);
	
	/* round 4 */
	RMD160STEP(RMD160_F4, RMD160_S4, c, d, e, a, b, x[1], 11);
	RMD160STEP(RMD160_F4, RMD160_S4, b, c, d, e, a, x[9], 12);
	RMD160STEP(RMD160_F4, RMD160_S4, a, b, c, d, e, x[11], 14);
	RMD160STEP(RMD160_F4, RMD160_S4, e, a, b, c, d, x[10], 15);
	RMD160STEP(RMD160_F4, RMD160_S4, d, e, a, b, c, x[0], 14);
	RMD160STEP(RMD160_F4, RMD160_S4, c, d, e, a, b, x[8], 15);
	RMD160STEP(RMD160_F4, RMD160_S4, b, c, d, e, a, x[12], 9);
	RMD160STEP(RMD160_F4, RMD160_S4, a, b, c, d, e, x[4], 8);
	RMD160STEP(RMD160_F4, RMD160_S4, e, a, b, c, d, x[13], 9);
	RMD160STEP(RMD160_F4, RMD160_S4, d, e, a, b, c, x[3], 14);
	RMD160STEP(RMD160_F4, RMD160_S4, c, d, e, a, b, x[7], 5);
	RMD160STEP(RMD160_F4, RMD160_S4, b, c, d, e, a, x[15], 6);
	RMD160STEP(RMD160_F4, RMD160_S4, a, b, c, d, e, x[14], 8);
	RMD160STEP(RMD160_F4, RMD160_S4, e, a, b, c, d, x[5], 6);
	RMD160STEP(RMD160_F4, RMD160_S4, d, e, a, b, c, x[6], 5);
	RMD160STEP(RMD160_F4, RMD160_S4, c, d, e, a, b, x[2], 12);
	
	/* round 5 */
	RMD160STEP(RMD160_F5, RMD160_S5, b, c, d, e, a, x[4], 9);
	RMD160STEP(RMD160_F5, RMD160_S5, a, b, c, d, e, x[0], 15);
	RMD160STEP(RMD160_F5, RMD160_S5, e, a, b, c, d, x[5], 5);
	RMD160STEP(RMD160_F5, RMD160_S5, d, e, a, b, c, x[9], 11);
	RMD160STEP(RMD160_F5, RMD160_S5, c, d, e, a, b, x[7], 6);
	RMD160STEP(RMD160_F5, RMD160_S5, b, c, d, e, a, x[12], 8);
	RMD160STEP(RMD160_F5, RMD160_S5, a, b, c, d, e, x[2], 13);
	RMD160STEP(RMD160_F5, RMD160_S5, e, a, b, c, d, x[10], 12);
	RMD160STEP(RMD160_F5, RMD160_S5, d, e, a, b, c, x[14], 5);
	RMD160STEP(RMD160_F5, RMD160_S5, c, d, e, a, b, x[1], 12);
	RMD160STEP(RMD160_F5, RMD160_S5, b, c, d, e, a, x[3], 13);
	RMD160STEP(RMD160_F5, RMD160_S5, a, b, c, d, e, x[8], 14);
	RMD160STEP(RMD160_F5, RMD160_S5, e, a, b, c, d, x[11], 11);
	RMD160STEP(RMD160_F5, RMD160_S5, d, e, a, b, c, x[6], 8);
	RMD160STEP(RMD160_F5, RMD160_S5, c, d, e, a, b, x[15], 5);
	RMD160STEP(RMD160_F5, RMD160_S5, b, c, d, e, a, x[13], 6);
	
	/* parallel round 1 */
	RMD160STEP(RMD160_F5, RMD160_S6, aa, bb, cc, dd, ee, x[5], 8);
	RMD160STEP(RMD160_F5, RMD160_S6, ee, aa, bb, cc, dd, x[14], 9);
	RMD160STEP(RMD160_F5, RMD160_S6, dd, ee, aa, bb, cc, x[7], 9);
	RMD160STEP(RMD160_F5, RMD160_S6, cc, dd, ee, aa, bb, x[0], 11);
	RMD160STEP(RMD160_F5, RMD160_S6, bb, cc, dd, ee, aa, x[9], 13);
	RMD160STEP(RMD160_F5, RMD160_S6, aa, bb, cc, dd, ee, x[2], 15);
	RMD160STEP(RMD160_F5, RMD160_S6, ee, aa, bb, cc, dd, x[11], 15);
	RMD160STEP(RMD160_F5, RMD160_S6, dd, ee, aa, bb, cc, x[4], 5);
	RMD160STEP(RMD160_F5, RMD160_S6, cc, dd, ee, aa, bb, x[13], 7);
	RMD160STEP(RMD160_F5, RMD160_S6, bb, cc, dd, ee, aa, x[6], 7);
	RMD160STEP(RMD160_F5, RMD160_S6, aa, bb, cc, dd, ee, x[15], 8);
	RMD160STEP(RMD160_F5, RMD160_S6, ee, aa, bb, cc, dd, x[8], 11);
	RMD160STEP(RMD160_F5, RMD160_S6, dd, ee, aa, bb, cc, x[1], 14);
	RMD160STEP(RMD160_F5, RMD160_S6, cc, dd, ee, aa, bb, x[10], 14);
	RMD160STEP(RMD160_F5, RMD160_S6, bb, cc, dd, ee, aa, x[3], 12);
	RMD160STEP(RMD160_F5, RMD160_S6, aa, bb, cc, dd, ee, x[12], 6);
	
	/* parallel round 2 */
	RMD160STEP(RMD160_F4, RMD160_S7, ee, aa, bb, cc, dd, x[6], 9); 
	RMD160STEP(RMD160_F4, RMD160_S7, dd, ee, aa, bb, cc, x[11], 13);
	RMD160STEP(RMD160_F4, RMD160_S7, cc, dd, ee, aa, bb, x[3], 15);
	RMD160STEP(RMD160_F4, RMD160_S7, bb, cc, dd, ee, aa, x[7], 7);
	RMD160STEP(RMD160_F4, RMD160_S7, aa, bb, cc, dd, ee, x[0], 12);
	RMD160STEP(RMD160_F4, RMD160_S7, ee, aa, bb, cc, dd, x[13], 8);
	RMD160STEP(RMD160_F4, RMD160_S7, dd, ee, aa, bb, cc, x[5], 9);
	RMD160STEP(RMD160_F4, RMD160_S7, cc, dd, ee, aa, bb, x[10], 11);
	RMD160STEP(RMD160_F4, RMD160_S7, bb, cc, dd, ee, aa, x[14], 7);
	RMD160STEP(RMD160_F4, RMD160_S7, aa, bb, cc, dd, ee, x[15], 7);
	RMD160STEP(RMD160_F4, RMD160_S7, ee, aa, bb, cc, dd, x[8], 12);
	RMD160STEP(RMD160_F4, RMD160_S7, dd, ee, aa, bb, cc, x[12], 7);
	RMD160STEP(RMD160_F4, RMD160_S7, cc, dd, ee, aa, bb, x[4], 6);
	RMD160STEP(RMD160_F4, RMD160_S7, bb, cc, dd, ee, aa, x[9], 15);
	RMD160STEP(RMD160_F4, RMD160_S7, aa, bb, cc, dd, ee, x[1], 13);
	RMD160STEP(RMD160_F4, RMD160_S7, ee, aa, bb, cc, dd, x[2], 11);
	
	/* parallel round 3 */
	RMD160STEP(RMD160_F3, RMD160_S8, dd, ee, aa, bb, cc, x[15], 9);
	RMD160STEP(RMD160_F3, RMD160_S8, cc, dd, ee, aa, bb, x[5], 7);
	RMD160STEP(RMD160_F3, RMD160_S8, bb, cc, dd, ee, aa, x[1], 15);
	RMD160STEP(RMD160_F3, RMD160_S8, aa, bb, cc, dd, ee, x[3], 11);
	RMD160STEP(RMD160_F3, RMD160_S8, ee, aa, bb, cc, dd, x[7], 8);
	RMD160STEP(RMD160_F3, RMD160_S8, dd, ee, aa, bb, cc, x[14], 6);
	RMD160STEP(RMD160_F3, RMD160_S8, cc, dd, ee, aa, bb, x[6], 6);
	RMD160STEP(RMD160_F3, RMD160_S8, bb, cc, dd, ee, aa, x[9], 14);
	RMD160STEP(RMD160_F3, RMD160_S8, aa, bb, cc, dd, ee, x[11], 12);
	RMD160STEP(RMD160_F3, RMD160_S8, ee, aa, bb, cc, dd, x[8], 13);
	RMD160STEP(RMD160_F3, RMD160_S8, dd, ee, aa, bb, cc, x[12], 5);
	RMD160STEP(RMD160_F3, RMD160_S8, cc, dd, ee, aa, bb, x[2], 14);
	RMD160STEP(RMD160_F3, RMD160_S8, bb, cc, dd, ee, aa, x[10], 13);
	RMD160STEP(RMD160_F3, RMD160_S8, aa, bb, cc, dd, ee, x[0], 13);
	RMD160STEP(RMD160_F3, RMD160_S8, ee, aa, bb, cc, dd, x[4], 7);
	RMD160STEP(RMD160_F3, RMD160_S8, dd, ee, aa, bb, cc, x[13], 5);
	
	/* parallel round 4 */   
	RMD160STEP(RMD160_F2, RMD160_S9, cc, dd, ee, aa, bb, x[8], 15);
	RMD160STEP(RMD160_F2, RMD160_S9, bb, cc, dd, ee, aa, x[6], 5);
	RMD160STEP(RMD160_F2, RMD160_S9, aa, bb, cc, dd, ee, x[4], 8);
	RMD160STEP(RMD160_F2, RMD160_S9, ee, aa, bb, cc, dd, x[1], 11);
	RMD160STEP(RMD160_F2, RMD160_S9, dd, ee, aa, bb, cc, x[3], 14);
	RMD160STEP(RMD160_F2, RMD160_S9, cc, dd, ee, aa, bb, x[11], 14);
	RMD160STEP(RMD160_F2, RMD160_S9, bb, cc, dd, ee, aa, x[15], 6);
	RMD160STEP(RMD160_F2, RMD160_S9, aa, bb, cc, dd, ee, x[0], 14);
	RMD160STEP(RMD160_F2, RMD160_S9, ee, aa, bb, cc, dd, x[5], 6);
	RMD160STEP(RMD160_F2, RMD160_S9, dd, ee, aa, bb, cc, x[12], 9);
	RMD160STEP(RMD160_F2, RMD160_S9, cc, dd, ee, aa, bb, x[2], 12);
	RMD160STEP(RMD160_F2, RMD160_S9, bb, cc, dd, ee, aa, x[13], 9);
	RMD160STEP(RMD160_F2, RMD160_S9, aa, bb, cc, dd, ee, x[9], 12);
	RMD160STEP(RMD160_F2, RMD160_S9, ee, aa, bb, cc, dd, x[7], 5);
	RMD160STEP(RMD160_F2, RMD160_S9, dd, ee, aa, bb, cc, x[10], 15);
	RMD160STEP(RMD160_F2, RMD160_S9, cc, dd, ee, aa, bb, x[14], 8);
	
	/* parallel round 5 */
	RMD160STEP(RMD160_F1, RMD160_S10, bb, cc, dd, ee, aa, x[12], 8);
	RMD160STEP(RMD160_F1, RMD160_S10, aa, bb, cc, dd, ee, x[15], 5);
	RMD160STEP(RMD160_F1, RMD160_S10, ee, aa, bb, cc, dd, x[10], 12);
	RMD160STEP(RMD160_F1, RMD160_S10, dd, ee, aa, bb, cc, x[4], 9);
	RMD160STEP(RMD160_F1, RMD160_S10, cc, dd, ee, aa, bb, x[1], 12);
	RMD160STEP(RMD160_F1, RMD160_S10, bb, cc, dd, ee, aa, x[5], 5);
	RMD160STEP(RMD160_F1, RMD160_S10, aa, bb, cc, dd, ee, x[8], 14);
	RMD160STEP(RMD160_F1, RMD160_S10, ee, aa, bb, cc, dd, x[7], 6);
	RMD160STEP(RMD160_F1, RMD160_S10, dd, ee, aa, bb, cc, x[6], 8);
	RMD160STEP(RMD160_F1, RMD160_S10, cc, dd, ee, aa, bb, x[2], 13);
	RMD160STEP(RMD160_F1, RMD160_S10, bb, cc, dd, ee, aa, x[13], 6);
	RMD160STEP(RMD160_F1, RMD160_S10, aa, bb, cc, dd, ee, x[14], 5);
	RMD160STEP(RMD160_F1, RMD160_S10, ee, aa, bb, cc, dd, x[0], 15);
	RMD160STEP(RMD160_F1, RMD160_S10, dd, ee, aa, bb, cc, x[3], 13);
	RMD160STEP(RMD160_F1, RMD160_S10, cc, dd, ee, aa, bb, x[9], 11);
	RMD160STEP(RMD160_F1, RMD160_S10, bb, cc, dd, ee, aa, x[11], 11);
	
	dd += c + context->state[1];
	context->state[1] = context->state[2] + d + ee;
	context->state[2] = context->state[3] + e + aa;
	context->state[3] = context->state[4] + a + bb;
	context->state[4] = context->state[0] + b + cc;
	context->state[0] = dd;
}

int RMD160Test() {
	static const struct {
		char *msg;
		unsigned char hash[RMD160Length];
	} tests[] = {
		{
			"",
			{0x9c,0x11,0x85,0xa5,0xc5,0xe9,0xfc,0x54,0x61,0x28,0x08,0x97,0x7e,0xe8,0xf5,0x48,0xb2,0x25,0x8d,0x31}
		},
		{
			"a",
			{0x0b,0xdc,0x9d,0x2d,0x25,0x6b,0x3e,0xe9,0xda,0xae,0x34,0x7b,0xe6,0xf4,0xdc,0x83,0x5a,0x46,0x7f,0xfe}
		},
		{
			"abc",
			{0x8e,0xb2,0x08,0xf7,0xe0,0x5d,0x98,0x7a,0x9b,0x04,0x4a,0x8e,0x98,0xc6,0xb0,0x87,0xf1,0x5a,0x0b,0xfc}
		},
		{
			"message digest",
			{0x5d,0x06,0x89,0xef,0x49,0xd2,0xfa,0xe5,0x72,0xb8,0x81,0xb1,0x23,0xa8,0x5f,0xfa,0x21,0x59,0x5f,0x36}
		},
		{
			"abcdefghijklmnopqrstuvwxyz",
			{0xf7,0x1c,0x27,0x10,0x9c,0x69,0x2c,0x1b,0x56,0xbb,0xdc,0xeb,0x5b,0x9d,0x28,0x65,0xb3,0x70,0x8d,0xbc}
		},
		{
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			{0x12,0xa0,0x53,0x38,0x4a,0x9c,0x0c,0x88,0xe4,0x05,0xa0,0x6c,0x27,0xdc,0xf4,0x9a,0xda,0x62,0xeb,0x2b}
		},
		{NULL, {0}}
	};
	
	struct RMD160Context MDContext;
	unsigned char MDDigest[RMD160Length];
	
	for (int i=0; tests[i].msg!=NULL; i++) {
		RMD160Init(&MDContext);
		RMD160Update(&MDContext, (unsigned char *)tests[i].msg, (unsigned long)strlen(tests[i].msg));
		RMD160Final(MDDigest, &MDContext);
		
		if (memcmp(MDDigest, tests[i].hash, RMD160Length))
			return 0;
	}
	
	return 1;
}