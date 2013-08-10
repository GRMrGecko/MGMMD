//
//  MGMRMD320.m
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 5/31/11.
//  No Copyright Claimed. Public Domain.
//  C Algorithm created by Tom St Denis <tomstdenis@gmail.com> <http://libtom.org>
//

#ifdef __NEXT_RUNTIME__
#import "MGMRMD320.h"
#import "MGMTypes.h"

NSString * const MDNRMD320 = @"rmd320";

@implementation NSString (MGMRMD320)
- (NSString *)RMD320 {
	NSData *MDData = [self dataUsingEncoding:NSUTF8StringEncoding];
	struct RMD320Context MDContext;
	unsigned char MDDigest[RMD320Length];
	
	RMD320Init(&MDContext);
	RMD320Update(&MDContext, [MDData bytes], [MDData length]);
	RMD320Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(RMD320Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD320Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	NSString *hash = [NSString stringWithUTF8String:stringBuffer];
	free(stringBuffer);
	return hash;
}
- (NSString *)pathRMD320 {
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:self];
	if (file==nil)
		return nil;
	struct RMD320Context MDContext;
	unsigned char MDDigest[RMD320Length];
	
	RMD320Init(&MDContext);
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *MDData = [file readDataOfLength:MDFileReadLength];
		length = [MDData length];
		RMD320Update(&MDContext, [MDData bytes], length);
		[pool release];
	} while (length>0);
	RMD320Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(RMD320Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD320Length; i++) {
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
#include "MGMRMD320.h"
#include "MGMTypes.h"
#endif

const struct MGMHashDescription RMD320Desc = {
	"rmd320",
    sizeof(struct RMD320Context),
    (void(*)(void *))&RMD320Init,
	(void(*)(void *, const unsigned char *, unsigned))&RMD320Update,
	(void(*)(unsigned char *, void *))&RMD320Final,
	RMD320Length
};

char *RMD320String(const char *string, int length) {
	struct RMD320Context MDContext;
	unsigned char MDDigest[RMD320Length];
	
	RMD320Init(&MDContext);
	RMD320Update(&MDContext, (const unsigned char *)string, length);
	RMD320Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(RMD320Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD320Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}
char *RMD320File(const char *path) {
	FILE *file = fopen(path, "r");
	if (file==NULL)
		return NULL;
	struct RMD320Context MDContext;
	unsigned char MDDigest[RMD320Length];
	
	RMD320Init(&MDContext);
	int length;
	do {
		unsigned char MDData[MDFileReadLength];
		length = fread(&MDData, 1, MDFileReadLength, file);
		RMD320Update(&MDContext, MDData, length);
	} while (length>0);
	RMD320Final(MDDigest, &MDContext);
	
	fclose(file);
	
	char *stringBuffer = (char *)malloc(RMD320Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD320Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}

void RMD320Init(struct RMD320Context *context) {
	context->state[0] = INT32(0x67452301);
	context->state[1] = INT32(0xefcdab89);
	context->state[2] = INT32(0x98badcfe);
	context->state[3] = INT32(0x10325476);
	context->state[4] = INT32(0xc3d2e1f0);
	context->state[5] = INT32(0x76543210);
	context->state[6] = INT32(0xfedcba98);
	context->state[7] = INT32(0x89abcdef);
	context->state[8] = INT32(0x01234567);
	context->state[9] = INT32(0x3c2d1e0f);
	context->curlen = 0;
	context->length = 0;
}

void RMD320Update(struct RMD320Context *context, const unsigned char *buf, unsigned len) {
	if (buf==NULL)
		return;
	unsigned long n;
	while (len>0) {
		if (context->curlen == 0 && len>=RMD320BufferSize) {
			RMD320Transform(context, (unsigned char *)buf);
			context->length += RMD320BufferSize * 8;
			buf += RMD320BufferSize;
			len -= RMD320BufferSize;
		} else {
			n = MIN(len, (RMD320BufferSize-context->curlen));
			memcpy(context->buf+context->curlen, buf, (size_t)n);
			context->curlen += n;
			buf += n;
			len -= n;
			if (context->curlen == RMD320BufferSize) {
				RMD320Transform(context, context->buf);
				context->length += 8*RMD320BufferSize;
				context->curlen = 0;
			}
		}
	}
}

void RMD320Final(unsigned char digest[RMD320Length], struct RMD320Context *context) {
	context->length += context->curlen * 8;
	context->buf[context->curlen++] = (unsigned char)0x80;
	
	if (context->curlen > 56) {
		while (context->curlen < 64) {
			context->buf[context->curlen++] = (unsigned char)0;
		}
		RMD320Transform(context, context->buf);
		context->curlen = 0;
	}
	
	while (context->curlen < 56) {
		context->buf[context->curlen++] = (unsigned char)0;
	}
	
	putu64l(context->length, context->buf+56);
	RMD320Transform(context, context->buf);
	
	for (int i=0; i<10; i++) {
		putu32l(context->state[i], digest+(4*i));
	}
	
	memset(context, 0, sizeof(struct RMD320Context));
}

#define RMD320_S1 0
#define RMD320_S2 INT32(0x5a827999)
#define RMD320_S3 INT32(0x6ed9eba1)
#define RMD320_S4 INT32(0x8f1bbcdc)
#define RMD320_S5 INT32(0xa953fd4e)

#define RMD320_S10 0
#define RMD320_S9 INT32(0x7a6d76e9)
#define RMD320_S8 INT32(0x6d703ef3)
#define RMD320_S7 INT32(0x5c4dd124)
#define RMD320_S6 INT32(0x50a28be6)

#define RMD320_F1(x, y, z) ((x) ^ (y) ^ (z))
#define RMD320_F2(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define RMD320_F3(x, y, z) (((x) | ~(y)) ^ (z))
#define RMD320_F4(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define RMD320_F5(x, y, z) ((x) ^ ((y) | ~(z)))

#define RMD320STEP(a, b, c, d, e, f, g, h, i) \
	(c) += a((d), (e), (f)) + (h) + b; (c) = ROL32((c), (i)) + (g); (e) = ROL32((e), 10);

void RMD320Transform(struct RMD320Context *context, unsigned char *buf) {
	uint32_t x[16], tmp;
	
	uint32_t a = context->state[0];
	uint32_t b = context->state[1];
	uint32_t c = context->state[2];
	uint32_t d = context->state[3];
	uint32_t e = context->state[4];
	uint32_t aa = context->state[5];
	uint32_t bb = context->state[6];
	uint32_t cc = context->state[7];
	uint32_t dd = context->state[8];
	uint32_t ee = context->state[9];
	
	for (int i=0; i<16; i++) {
		x[i] = getu32l(buf+(4*i));
	}
	
	/* round 1 */
	RMD320STEP(RMD320_F1, RMD320_S1, a, b, c, d, e, x[0], 11);
	RMD320STEP(RMD320_F1, RMD320_S1, e, a, b, c, d, x[1], 14);
	RMD320STEP(RMD320_F1, RMD320_S1, d, e, a, b, c, x[2], 15);
	RMD320STEP(RMD320_F1, RMD320_S1, c, d, e, a, b, x[3], 12);
	RMD320STEP(RMD320_F1, RMD320_S1, b, c, d, e, a, x[4], 5);
	RMD320STEP(RMD320_F1, RMD320_S1, a, b, c, d, e, x[5], 8);
	RMD320STEP(RMD320_F1, RMD320_S1, e, a, b, c, d, x[6], 7);
	RMD320STEP(RMD320_F1, RMD320_S1, d, e, a, b, c, x[7], 9);
	RMD320STEP(RMD320_F1, RMD320_S1, c, d, e, a, b, x[8], 11);
	RMD320STEP(RMD320_F1, RMD320_S1, b, c, d, e, a, x[9], 13);
	RMD320STEP(RMD320_F1, RMD320_S1, a, b, c, d, e, x[10], 14);
	RMD320STEP(RMD320_F1, RMD320_S1, e, a, b, c, d, x[11], 15);
	RMD320STEP(RMD320_F1, RMD320_S1, d, e, a, b, c, x[12], 6);
	RMD320STEP(RMD320_F1, RMD320_S1, c, d, e, a, b, x[13], 7);
	RMD320STEP(RMD320_F1, RMD320_S1, b, c, d, e, a, x[14], 9);
	RMD320STEP(RMD320_F1, RMD320_S1, a, b, c, d, e, x[15], 8);
	
	/* parallel round 1 */
	RMD320STEP(RMD320_F5, RMD320_S6, aa, bb, cc, dd, ee, x[5], 8);
	RMD320STEP(RMD320_F5, RMD320_S6, ee, aa, bb, cc, dd, x[14], 9);
	RMD320STEP(RMD320_F5, RMD320_S6, dd, ee, aa, bb, cc, x[7], 9);
	RMD320STEP(RMD320_F5, RMD320_S6, cc, dd, ee, aa, bb, x[0], 11);
	RMD320STEP(RMD320_F5, RMD320_S6, bb, cc, dd, ee, aa, x[9], 13);
	RMD320STEP(RMD320_F5, RMD320_S6, aa, bb, cc, dd, ee, x[2], 15);
	RMD320STEP(RMD320_F5, RMD320_S6, ee, aa, bb, cc, dd, x[11], 15);
	RMD320STEP(RMD320_F5, RMD320_S6, dd, ee, aa, bb, cc, x[4], 5);
	RMD320STEP(RMD320_F5, RMD320_S6, cc, dd, ee, aa, bb, x[13], 7);
	RMD320STEP(RMD320_F5, RMD320_S6, bb, cc, dd, ee, aa, x[6], 7);
	RMD320STEP(RMD320_F5, RMD320_S6, aa, bb, cc, dd, ee, x[15], 8);
	RMD320STEP(RMD320_F5, RMD320_S6, ee, aa, bb, cc, dd, x[8], 11);
	RMD320STEP(RMD320_F5, RMD320_S6, dd, ee, aa, bb, cc, x[1], 14);
	RMD320STEP(RMD320_F5, RMD320_S6, cc, dd, ee, aa, bb, x[10], 14);
	RMD320STEP(RMD320_F5, RMD320_S6, bb, cc, dd, ee, aa, x[3], 12);
	RMD320STEP(RMD320_F5, RMD320_S6, aa, bb, cc, dd, ee, x[12], 6);
	
	tmp = a; a = aa; aa = tmp;
	
	/* round 2 */
	RMD320STEP(RMD320_F2, RMD320_S2, e, a, b, c, d, x[7], 7);
	RMD320STEP(RMD320_F2, RMD320_S2, d, e, a, b, c, x[4], 6);
	RMD320STEP(RMD320_F2, RMD320_S2, c, d, e, a, b, x[13], 8);
	RMD320STEP(RMD320_F2, RMD320_S2, b, c, d, e, a, x[1], 13);
	RMD320STEP(RMD320_F2, RMD320_S2, a, b, c, d, e, x[10], 11);
	RMD320STEP(RMD320_F2, RMD320_S2, e, a, b, c, d, x[6], 9);
	RMD320STEP(RMD320_F2, RMD320_S2, d, e, a, b, c, x[15], 7);
	RMD320STEP(RMD320_F2, RMD320_S2, c, d, e, a, b, x[3], 15);
	RMD320STEP(RMD320_F2, RMD320_S2, b, c, d, e, a, x[12], 7);
	RMD320STEP(RMD320_F2, RMD320_S2, a, b, c, d, e, x[0], 12);
	RMD320STEP(RMD320_F2, RMD320_S2, e, a, b, c, d, x[9], 15);
	RMD320STEP(RMD320_F2, RMD320_S2, d, e, a, b, c, x[5], 9);
	RMD320STEP(RMD320_F2, RMD320_S2, c, d, e, a, b, x[2], 11);
	RMD320STEP(RMD320_F2, RMD320_S2, b, c, d, e, a, x[14], 7);
	RMD320STEP(RMD320_F2, RMD320_S2, a, b, c, d, e, x[11], 13);
	RMD320STEP(RMD320_F2, RMD320_S2, e, a, b, c, d, x[8], 12);
	
	/* parallel round 2 */
	RMD320STEP(RMD320_F4, RMD320_S7, ee, aa, bb, cc, dd, x[6], 9);
	RMD320STEP(RMD320_F4, RMD320_S7, dd, ee, aa, bb, cc, x[11], 13);
	RMD320STEP(RMD320_F4, RMD320_S7, cc, dd, ee, aa, bb, x[3], 15);
	RMD320STEP(RMD320_F4, RMD320_S7, bb, cc, dd, ee, aa, x[7], 7);
	RMD320STEP(RMD320_F4, RMD320_S7, aa, bb, cc, dd, ee, x[0], 12);
	RMD320STEP(RMD320_F4, RMD320_S7, ee, aa, bb, cc, dd, x[13], 8);
	RMD320STEP(RMD320_F4, RMD320_S7, dd, ee, aa, bb, cc, x[5], 9);
	RMD320STEP(RMD320_F4, RMD320_S7, cc, dd, ee, aa, bb, x[10], 11);
	RMD320STEP(RMD320_F4, RMD320_S7, bb, cc, dd, ee, aa, x[14], 7);
	RMD320STEP(RMD320_F4, RMD320_S7, aa, bb, cc, dd, ee, x[15], 7);
	RMD320STEP(RMD320_F4, RMD320_S7, ee, aa, bb, cc, dd, x[8], 12);
	RMD320STEP(RMD320_F4, RMD320_S7, dd, ee, aa, bb, cc, x[12], 7);
	RMD320STEP(RMD320_F4, RMD320_S7, cc, dd, ee, aa, bb, x[4], 6);
	RMD320STEP(RMD320_F4, RMD320_S7, bb, cc, dd, ee, aa, x[9], 15);
	RMD320STEP(RMD320_F4, RMD320_S7, aa, bb, cc, dd, ee, x[1], 13);
	RMD320STEP(RMD320_F4, RMD320_S7, ee, aa, bb, cc, dd, x[2], 11);
	
	tmp = b; b = bb; bb = tmp;
	
	/* round 3 */
	RMD320STEP(RMD320_F3, RMD320_S3, d, e, a, b, c, x[3], 11);
	RMD320STEP(RMD320_F3, RMD320_S3, c, d, e, a, b, x[10], 13);
	RMD320STEP(RMD320_F3, RMD320_S3, b, c, d, e, a, x[14], 6);
	RMD320STEP(RMD320_F3, RMD320_S3, a, b, c, d, e, x[4], 7);
	RMD320STEP(RMD320_F3, RMD320_S3, e, a, b, c, d, x[9], 14);
	RMD320STEP(RMD320_F3, RMD320_S3, d, e, a, b, c, x[15], 9);
	RMD320STEP(RMD320_F3, RMD320_S3, c, d, e, a, b, x[8], 13);
	RMD320STEP(RMD320_F3, RMD320_S3, b, c, d, e, a, x[1], 15);
	RMD320STEP(RMD320_F3, RMD320_S3, a, b, c, d, e, x[2], 14);
	RMD320STEP(RMD320_F3, RMD320_S3, e, a, b, c, d, x[7], 8);
	RMD320STEP(RMD320_F3, RMD320_S3, d, e, a, b, c, x[0], 13);
	RMD320STEP(RMD320_F3, RMD320_S3, c, d, e, a, b, x[6], 6);
	RMD320STEP(RMD320_F3, RMD320_S3, b, c, d, e, a, x[13], 5);
	RMD320STEP(RMD320_F3, RMD320_S3, a, b, c, d, e, x[11], 12);
	RMD320STEP(RMD320_F3, RMD320_S3, e, a, b, c, d, x[5], 7);
	RMD320STEP(RMD320_F3, RMD320_S3, d, e, a, b, c, x[12], 5);
	
	/* parallel round 3 */
	RMD320STEP(RMD320_F3, RMD320_S8, dd, ee, aa, bb, cc, x[15], 9);
	RMD320STEP(RMD320_F3, RMD320_S8, cc, dd, ee, aa, bb, x[5], 7);
	RMD320STEP(RMD320_F3, RMD320_S8, bb, cc, dd, ee, aa, x[1], 15);
	RMD320STEP(RMD320_F3, RMD320_S8, aa, bb, cc, dd, ee, x[3], 11);
	RMD320STEP(RMD320_F3, RMD320_S8, ee, aa, bb, cc, dd, x[7], 8);
	RMD320STEP(RMD320_F3, RMD320_S8, dd, ee, aa, bb, cc, x[14], 6);
	RMD320STEP(RMD320_F3, RMD320_S8, cc, dd, ee, aa, bb, x[6], 6);
	RMD320STEP(RMD320_F3, RMD320_S8, bb, cc, dd, ee, aa, x[9], 14);
	RMD320STEP(RMD320_F3, RMD320_S8, aa, bb, cc, dd, ee, x[11], 12);
	RMD320STEP(RMD320_F3, RMD320_S8, ee, aa, bb, cc, dd, x[8], 13);
	RMD320STEP(RMD320_F3, RMD320_S8, dd, ee, aa, bb, cc, x[12], 5);
	RMD320STEP(RMD320_F3, RMD320_S8, cc, dd, ee, aa, bb, x[2], 14);
	RMD320STEP(RMD320_F3, RMD320_S8, bb, cc, dd, ee, aa, x[10], 13);
	RMD320STEP(RMD320_F3, RMD320_S8, aa, bb, cc, dd, ee, x[0], 13);
	RMD320STEP(RMD320_F3, RMD320_S8, ee, aa, bb, cc, dd, x[4], 7);
	RMD320STEP(RMD320_F3, RMD320_S8, dd, ee, aa, bb, cc, x[13], 5);
	
	tmp = c; c = cc; cc = tmp;
	
	/* round 4 */
	RMD320STEP(RMD320_F4, RMD320_S4, c, d, e, a, b, x[1], 11);
	RMD320STEP(RMD320_F4, RMD320_S4, b, c, d, e, a, x[9], 12);
	RMD320STEP(RMD320_F4, RMD320_S4, a, b, c, d, e, x[11], 14);
	RMD320STEP(RMD320_F4, RMD320_S4, e, a, b, c, d, x[10], 15);
	RMD320STEP(RMD320_F4, RMD320_S4, d, e, a, b, c, x[0], 14);
	RMD320STEP(RMD320_F4, RMD320_S4, c, d, e, a, b, x[8], 15);
	RMD320STEP(RMD320_F4, RMD320_S4, b, c, d, e, a, x[12], 9);
	RMD320STEP(RMD320_F4, RMD320_S4, a, b, c, d, e, x[4], 8);
	RMD320STEP(RMD320_F4, RMD320_S4, e, a, b, c, d, x[13], 9);
	RMD320STEP(RMD320_F4, RMD320_S4, d, e, a, b, c, x[3], 14);
	RMD320STEP(RMD320_F4, RMD320_S4, c, d, e, a, b, x[7], 5);
	RMD320STEP(RMD320_F4, RMD320_S4, b, c, d, e, a, x[15], 6);
	RMD320STEP(RMD320_F4, RMD320_S4, a, b, c, d, e, x[14], 8);
	RMD320STEP(RMD320_F4, RMD320_S4, e, a, b, c, d, x[5], 6);
	RMD320STEP(RMD320_F4, RMD320_S4, d, e, a, b, c, x[6], 5);
	RMD320STEP(RMD320_F4, RMD320_S4, c, d, e, a, b, x[2], 12);
	
	/* parallel round 4 */
	RMD320STEP(RMD320_F2, RMD320_S9, cc, dd, ee, aa, bb, x[8], 15);
	RMD320STEP(RMD320_F2, RMD320_S9, bb, cc, dd, ee, aa, x[6], 5);
	RMD320STEP(RMD320_F2, RMD320_S9, aa, bb, cc, dd, ee, x[4], 8);
	RMD320STEP(RMD320_F2, RMD320_S9, ee, aa, bb, cc, dd, x[1], 11);
	RMD320STEP(RMD320_F2, RMD320_S9, dd, ee, aa, bb, cc, x[3], 14);
	RMD320STEP(RMD320_F2, RMD320_S9, cc, dd, ee, aa, bb, x[11], 14);
	RMD320STEP(RMD320_F2, RMD320_S9, bb, cc, dd, ee, aa, x[15], 6);
	RMD320STEP(RMD320_F2, RMD320_S9, aa, bb, cc, dd, ee, x[0], 14);
	RMD320STEP(RMD320_F2, RMD320_S9, ee, aa, bb, cc, dd, x[5], 6);
	RMD320STEP(RMD320_F2, RMD320_S9, dd, ee, aa, bb, cc, x[12], 9);
	RMD320STEP(RMD320_F2, RMD320_S9, cc, dd, ee, aa, bb, x[2], 12);
	RMD320STEP(RMD320_F2, RMD320_S9, bb, cc, dd, ee, aa, x[13], 9);
	RMD320STEP(RMD320_F2, RMD320_S9, aa, bb, cc, dd, ee, x[9], 12);
	RMD320STEP(RMD320_F2, RMD320_S9, ee, aa, bb, cc, dd, x[7], 5);
	RMD320STEP(RMD320_F2, RMD320_S9, dd, ee, aa, bb, cc, x[10], 15);
	RMD320STEP(RMD320_F2, RMD320_S9, cc, dd, ee, aa, bb, x[14], 8);
	
	tmp = d; d = dd; dd = tmp;
	
	/* round 5 */
	RMD320STEP(RMD320_F5, RMD320_S5, b, c, d, e, a, x[4], 9);
	RMD320STEP(RMD320_F5, RMD320_S5, a, b, c, d, e, x[0], 15);
	RMD320STEP(RMD320_F5, RMD320_S5, e, a, b, c, d, x[5], 5);
	RMD320STEP(RMD320_F5, RMD320_S5, d, e, a, b, c, x[9], 11);
	RMD320STEP(RMD320_F5, RMD320_S5, c, d, e, a, b, x[7], 6);
	RMD320STEP(RMD320_F5, RMD320_S5, b, c, d, e, a, x[12], 8);
	RMD320STEP(RMD320_F5, RMD320_S5, a, b, c, d, e, x[2], 13);
	RMD320STEP(RMD320_F5, RMD320_S5, e, a, b, c, d, x[10], 12);
	RMD320STEP(RMD320_F5, RMD320_S5, d, e, a, b, c, x[14], 5);
	RMD320STEP(RMD320_F5, RMD320_S5, c, d, e, a, b, x[1], 12);
	RMD320STEP(RMD320_F5, RMD320_S5, b, c, d, e, a, x[3], 13);
	RMD320STEP(RMD320_F5, RMD320_S5, a, b, c, d, e, x[8], 14);
	RMD320STEP(RMD320_F5, RMD320_S5, e, a, b, c, d, x[11], 11);
	RMD320STEP(RMD320_F5, RMD320_S5, d, e, a, b, c, x[6], 8);
	RMD320STEP(RMD320_F5, RMD320_S5, c, d, e, a, b, x[15], 5);
	RMD320STEP(RMD320_F5, RMD320_S5, b, c, d, e, a, x[13], 6);
	
	/* parallel round 5 */
	RMD320STEP(RMD320_F1, RMD320_S10, bb, cc, dd, ee, aa, x[12], 8);
	RMD320STEP(RMD320_F1, RMD320_S10, aa, bb, cc, dd, ee, x[15], 5);
	RMD320STEP(RMD320_F1, RMD320_S10, ee, aa, bb, cc, dd, x[10], 12);
	RMD320STEP(RMD320_F1, RMD320_S10, dd, ee, aa, bb, cc, x[4], 9);
	RMD320STEP(RMD320_F1, RMD320_S10, cc, dd, ee, aa, bb, x[1], 12);
	RMD320STEP(RMD320_F1, RMD320_S10, bb, cc, dd, ee, aa, x[5], 5);
	RMD320STEP(RMD320_F1, RMD320_S10, aa, bb, cc, dd, ee, x[8], 14);
	RMD320STEP(RMD320_F1, RMD320_S10, ee, aa, bb, cc, dd, x[7], 6);
	RMD320STEP(RMD320_F1, RMD320_S10, dd, ee, aa, bb, cc, x[6], 8);
	RMD320STEP(RMD320_F1, RMD320_S10, cc, dd, ee, aa, bb, x[2], 13);
	RMD320STEP(RMD320_F1, RMD320_S10, bb, cc, dd, ee, aa, x[13], 6);
	RMD320STEP(RMD320_F1, RMD320_S10, aa, bb, cc, dd, ee, x[14], 5);
	RMD320STEP(RMD320_F1, RMD320_S10, ee, aa, bb, cc, dd, x[0], 15);
	RMD320STEP(RMD320_F1, RMD320_S10, dd, ee, aa, bb, cc, x[3], 13);
	RMD320STEP(RMD320_F1, RMD320_S10, cc, dd, ee, aa, bb, x[9], 11);
	RMD320STEP(RMD320_F1, RMD320_S10, bb, cc, dd, ee, aa, x[11], 11);
	
	tmp = e; e = ee; ee = tmp;
	
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += aa;
	context->state[6] += bb;
	context->state[7] += cc;
	context->state[8] += dd;
	context->state[9] += ee;
}

int RMD320Test() {
	static const struct {
		char *msg;
		unsigned char hash[RMD320Length];
	} tests[] = {
		{
			"",
			{0x22,0xd6,0x5d,0x56,0x61,0x53,0x6c,0xdc,0x75,0xc1,0xfd,0xf5,0xc6,0xde,0x7b,0x41,0xb9,0xf2,0x73,0x25,0xeb,0xc6,0x1e,0x85,0x57,0x17,0x7d,0x70,0x5a,0x0e,0xc8,0x80,0x15,0x1c,0x3a,0x32,0xa0,0x08,0x99,0xb8}
		},
		{
			"a",
			{0xce,0x78,0x85,0x06,0x38,0xf9,0x26,0x58,0xa5,0xa5,0x85,0x09,0x75,0x79,0x92,0x6d,0xda,0x66,0x7a,0x57,0x16,0x56,0x2c,0xfc,0xf6,0xfb,0xe7,0x7f,0x63,0x54,0x2f,0x99,0xb0,0x47,0x05,0xd6,0x97,0x0d,0xff,0x5d}
		},
		{
			"abc",
			{0xde,0x4c,0x01,0xb3,0x05,0x4f,0x89,0x30,0xa7,0x9d,0x09,0xae,0x73,0x8e,0x92,0x30,0x1e,0x5a,0x17,0x08,0x5b,0xef,0xfd,0xc1,0xb8,0xd1,0x16,0x71,0x3e,0x74,0xf8,0x2f,0xa9,0x42,0xd6,0x4c,0xdb,0xc4,0x68,0x2d}
		},
		{
			"message digest",
			{0x3a,0x8e,0x28,0x50,0x2e,0xd4,0x5d,0x42,0x2f,0x68,0x84,0x4f,0x9d,0xd3,0x16,0xe7,0xb9,0x85,0x33,0xfa,0x3f,0x2a,0x91,0xd2,0x9f,0x84,0xd4,0x25,0xc8,0x8d,0x6b,0x4e,0xff,0x72,0x7d,0xf6,0x6a,0x7c,0x01,0x97}
		},
		{
			"abcdefghijklmnopqrstuvwxyz",
			{0xca,0xbd,0xb1,0x81,0x0b,0x92,0x47,0x0a,0x20,0x93,0xaa,0x6b,0xce,0x05,0x95,0x2c,0x28,0x34,0x8c,0xf4,0x3f,0xf6,0x08,0x41,0x97,0x51,0x66,0xbb,0x40,0xed,0x23,0x40,0x04,0xb8,0x82,0x44,0x63,0xe6,0xb0,0x09}
		},
		{
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			{0xd0,0x34,0xa7,0x95,0x0c,0xf7,0x22,0x02,0x1b,0xa4,0xb8,0x4d,0xf7,0x69,0xa5,0xde,0x20,0x60,0xe2,0x59,0xdf,0x4c,0x9b,0xb4,0xa4,0x26,0x8c,0x0e,0x93,0x5b,0xbc,0x74,0x70,0xa9,0x69,0xc9,0xd0,0x72,0xa1,0xac}
		},
		{NULL, {0}}
	};
	
	struct RMD320Context MDContext;
	unsigned char MDDigest[RMD320Length];
	
	for (int i=0; tests[i].msg!=NULL; i++) {
		RMD320Init(&MDContext);
		RMD320Update(&MDContext, (unsigned char *)tests[i].msg, (unsigned long)strlen(tests[i].msg));
		RMD320Final(MDDigest, &MDContext);
		
		if (memcmp(MDDigest, tests[i].hash, RMD320Length))
			return 0;
	}
	
	return 1;
}