//
//  MGMRMD128.m
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 5/31/11.
//  No Copyright Claimed. Public Domain.
//  C Algorithm created by Tom St Denis <tomstdenis@gmail.com> <http://libtom.org>
//

#ifdef __NEXT_RUNTIME__
#import "MGMRMD128.h"
#import "MGMTypes.h"

NSString * const MDNRMD128 = @"rmd128";

@implementation NSString (MGMRMD128)
- (NSString *)RMD128 {
	NSData *MDData = [self dataUsingEncoding:NSUTF8StringEncoding];
	struct RMD128Context MDContext;
	unsigned char MDDigest[RMD128Length];
	
	RMD128Init(&MDContext);
	RMD128Update(&MDContext, [MDData bytes], [MDData length]);
	RMD128Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(RMD128Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD128Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	NSString *hash = [NSString stringWithUTF8String:stringBuffer];
	free(stringBuffer);
	return hash;
}
- (NSString *)pathRMD128 {
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:self];
	if (file==nil)
		return nil;
	struct RMD128Context MDContext;
	unsigned char MDDigest[RMD128Length];
	
	RMD128Init(&MDContext);
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *MDData = [file readDataOfLength:MDFileReadLength];
		length = [MDData length];
		RMD128Update(&MDContext, [MDData bytes], length);
		[pool release];
	} while (length>0);
	RMD128Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(RMD128Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD128Length; i++) {
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
#include "MGMRMD128.h"
#include "MGMTypes.h"
#endif

const struct MGMHashDescription RMD128Desc = {
	"rmd128",
    sizeof(struct RMD128Context),
    (void(*)(void *))&RMD128Init,
	(void(*)(void *, const unsigned char *, unsigned))&RMD128Update,
	(void(*)(unsigned char *, void *))&RMD128Final,
	RMD128Length
};

char *RMD128String(const char *string, int length) {
	struct RMD128Context MDContext;
	unsigned char MDDigest[RMD128Length];
	
	RMD128Init(&MDContext);
	RMD128Update(&MDContext, (const unsigned char *)string, length);
	RMD128Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(RMD128Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD128Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}
char *RMD128File(const char *path) {
	FILE *file = fopen(path, "r");
	if (file==NULL)
		return NULL;
	struct RMD128Context MDContext;
	unsigned char MDDigest[RMD128Length];
	
	RMD128Init(&MDContext);
	int length;
	do {
		unsigned char MDData[MDFileReadLength];
		length = fread(&MDData, 1, MDFileReadLength, file);
		RMD128Update(&MDContext, MDData, length);
	} while (length>0);
	RMD128Final(MDDigest, &MDContext);
	
	fclose(file);
	
	char *stringBuffer = (char *)malloc(RMD128Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<RMD128Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}

void RMD128Init(struct RMD128Context *context) {
	context->state[0] = INT32(0x67452301);
	context->state[1] = INT32(0xefcdab89);
	context->state[2] = INT32(0x98badcfe);
	context->state[3] = INT32(0x10325476);
	context->curlen = 0;
	context->length = 0;
}

void RMD128Update(struct RMD128Context *context, const unsigned char *buf, unsigned len) {
	if (buf==NULL)
		return;
	unsigned long n;
	while (len>0) {
		if (context->curlen == 0 && len>=RMD128BufferSize) {
			RMD128Transform(context, (unsigned char *)buf);
			context->length += RMD128BufferSize * 8;
			buf += RMD128BufferSize;
			len -= RMD128BufferSize;
		} else {
			n = MIN(len, (RMD128BufferSize-context->curlen));
			memcpy(context->buf+context->curlen, buf, (size_t)n);
			context->curlen += n;
			buf += n;
			len -= n;
			if (context->curlen == RMD128BufferSize) {
				RMD128Transform(context, context->buf);
				context->length += 8*RMD128BufferSize;
				context->curlen = 0;
			}
		}
	}
}

void RMD128Final(unsigned char digest[RMD128Length], struct RMD128Context *context) {
	context->length += context->curlen * 8;
	context->buf[context->curlen++] = (unsigned char)0x80;
	
	if (context->curlen > 56) {
		while (context->curlen < 64) {
			context->buf[context->curlen++] = (unsigned char)0;
		}
		RMD128Transform(context, context->buf);
		context->curlen = 0;
	}
	
	while (context->curlen < 56) {
		context->buf[context->curlen++] = (unsigned char)0;
	}
	
	putu64l(context->length, context->buf+56);
	RMD128Transform(context, context->buf);
	
	for (int i=0; i<4; i++) {
		putu32l(context->state[i], digest+(4*i));
	}
	
	memset(context, 0, sizeof(struct RMD128Context));
}

#define RMD128_S1 0
#define RMD128_S2 INT32(0x5a827999)
#define RMD128_S3 INT32(0x6ed9eba1)
#define RMD128_S4 INT32(0x8f1bbcdc)

#define RMD128_S8 0
#define RMD128_S7 INT32(0x6d703ef3)
#define RMD128_S6 INT32(0x5c4dd124)
#define RMD128_S5 INT32(0x50a28be6)

#define RMD128_F1(x, y, z) ((x) ^ (y) ^ (z)) 
#define RMD128_F2(x, y, z) (((x) & (y)) | (~(x) & (z))) 
#define RMD128_F3(x, y, z) (((x) | ~(y)) ^ (z))
#define RMD128_F4(x, y, z) (((x) & (z)) | ((y) & ~(z))) 

#define RMD128STEP(a, b, c, d, e, f, g, h) \
	(c) += a((d), (e), (f)) + (g) + b; (c) = ROL32((c), (h));

void RMD128Transform(struct RMD128Context *context, unsigned char *buf) {
	uint32_t x[16];
	
	uint32_t a = context->state[0], aa = a;
	uint32_t b = context->state[1], bb = b;
	uint32_t c = context->state[2], cc = c;
	uint32_t d = context->state[3], dd = d;
	
	for (int i=0; i<16; i++) {
		x[i] = getu32l(buf+(4*i));
	}
	
	/* round 1 */
	RMD128STEP(RMD128_F1, RMD128_S1, a, b, c, d, x[0], 11);
	RMD128STEP(RMD128_F1, RMD128_S1, d, a, b, c, x[1], 14);
	RMD128STEP(RMD128_F1, RMD128_S1, c, d, a, b, x[2], 15);
	RMD128STEP(RMD128_F1, RMD128_S1, b, c, d, a, x[3], 12);
	RMD128STEP(RMD128_F1, RMD128_S1, a, b, c, d, x[4], 5);
	RMD128STEP(RMD128_F1, RMD128_S1, d, a, b, c, x[5], 8);
	RMD128STEP(RMD128_F1, RMD128_S1, c, d, a, b, x[6], 7);
	RMD128STEP(RMD128_F1, RMD128_S1, b, c, d, a, x[7], 9);
	RMD128STEP(RMD128_F1, RMD128_S1, a, b, c, d, x[8], 11);
	RMD128STEP(RMD128_F1, RMD128_S1, d, a, b, c, x[9], 13);
	RMD128STEP(RMD128_F1, RMD128_S1, c, d, a, b, x[10], 14);
	RMD128STEP(RMD128_F1, RMD128_S1, b, c, d, a, x[11], 15);
	RMD128STEP(RMD128_F1, RMD128_S1, a, b, c, d, x[12], 6);
	RMD128STEP(RMD128_F1, RMD128_S1, d, a, b, c, x[13], 7);
	RMD128STEP(RMD128_F1, RMD128_S1, c, d, a, b, x[14], 9);
	RMD128STEP(RMD128_F1, RMD128_S1, b, c, d, a, x[15], 8);
	
	/* round 2 */
	RMD128STEP(RMD128_F2, RMD128_S2, a, b, c, d, x[7], 7);
	RMD128STEP(RMD128_F2, RMD128_S2, d, a, b, c, x[4], 6);
	RMD128STEP(RMD128_F2, RMD128_S2, c, d, a, b, x[13], 8);
	RMD128STEP(RMD128_F2, RMD128_S2, b, c, d, a, x[1], 13);
	RMD128STEP(RMD128_F2, RMD128_S2, a, b, c, d, x[10], 11);
	RMD128STEP(RMD128_F2, RMD128_S2, d, a, b, c, x[6], 9);
	RMD128STEP(RMD128_F2, RMD128_S2, c, d, a, b, x[15], 7);
	RMD128STEP(RMD128_F2, RMD128_S2, b, c, d, a, x[3], 15);
	RMD128STEP(RMD128_F2, RMD128_S2, a, b, c, d, x[12], 7);
	RMD128STEP(RMD128_F2, RMD128_S2, d, a, b, c, x[0], 12);
	RMD128STEP(RMD128_F2, RMD128_S2, c, d, a, b, x[9], 15);
	RMD128STEP(RMD128_F2, RMD128_S2, b, c, d, a, x[5], 9);
	RMD128STEP(RMD128_F2, RMD128_S2, a, b, c, d, x[2], 11);
	RMD128STEP(RMD128_F2, RMD128_S2, d, a, b, c, x[14], 7);
	RMD128STEP(RMD128_F2, RMD128_S2, c, d, a, b, x[11], 13);
	RMD128STEP(RMD128_F2, RMD128_S2, b, c, d, a, x[8], 12);
	
	/* round 3 */
	RMD128STEP(RMD128_F3, RMD128_S3, a, b, c, d, x[3], 11);
	RMD128STEP(RMD128_F3, RMD128_S3, d, a, b, c, x[10], 13);
	RMD128STEP(RMD128_F3, RMD128_S3, c, d, a, b, x[14], 6);
	RMD128STEP(RMD128_F3, RMD128_S3, b, c, d, a, x[4], 7);
	RMD128STEP(RMD128_F3, RMD128_S3, a, b, c, d, x[9], 14);
	RMD128STEP(RMD128_F3, RMD128_S3, d, a, b, c, x[15], 9);
	RMD128STEP(RMD128_F3, RMD128_S3, c, d, a, b, x[8], 13);
	RMD128STEP(RMD128_F3, RMD128_S3, b, c, d, a, x[1], 15);
	RMD128STEP(RMD128_F3, RMD128_S3, a, b, c, d, x[2], 14);
	RMD128STEP(RMD128_F3, RMD128_S3, d, a, b, c, x[7], 8);
	RMD128STEP(RMD128_F3, RMD128_S3, c, d, a, b, x[0], 13);
	RMD128STEP(RMD128_F3, RMD128_S3, b, c, d, a, x[6], 6);
	RMD128STEP(RMD128_F3, RMD128_S3, a, b, c, d, x[13], 5);
	RMD128STEP(RMD128_F3, RMD128_S3, d, a, b, c, x[11], 12);
	RMD128STEP(RMD128_F3, RMD128_S3, c, d, a, b, x[5], 7);
	RMD128STEP(RMD128_F3, RMD128_S3, b, c, d, a, x[12], 5);
	
	/* round 4 */
	RMD128STEP(RMD128_F4, RMD128_S4, a, b, c, d, x[1], 11);
	RMD128STEP(RMD128_F4, RMD128_S4, d, a, b, c, x[9], 12);
	RMD128STEP(RMD128_F4, RMD128_S4, c, d, a, b, x[11], 14);
	RMD128STEP(RMD128_F4, RMD128_S4, b, c, d, a, x[10], 15);
	RMD128STEP(RMD128_F4, RMD128_S4, a, b, c, d, x[0], 14);
	RMD128STEP(RMD128_F4, RMD128_S4, d, a, b, c, x[8], 15);
	RMD128STEP(RMD128_F4, RMD128_S4, c, d, a, b, x[12], 9);
	RMD128STEP(RMD128_F4, RMD128_S4, b, c, d, a, x[4], 8);
	RMD128STEP(RMD128_F4, RMD128_S4, a, b, c, d, x[13], 9);
	RMD128STEP(RMD128_F4, RMD128_S4, d, a, b, c, x[3], 14);
	RMD128STEP(RMD128_F4, RMD128_S4, c, d, a, b, x[7], 5);
	RMD128STEP(RMD128_F4, RMD128_S4, b, c, d, a, x[15], 6);
	RMD128STEP(RMD128_F4, RMD128_S4, a, b, c, d, x[14], 8);
	RMD128STEP(RMD128_F4, RMD128_S4, d, a, b, c, x[5], 6);
	RMD128STEP(RMD128_F4, RMD128_S4, c, d, a, b, x[6], 5);
	RMD128STEP(RMD128_F4, RMD128_S4, b, c, d, a, x[2], 12);
	
	/* parallel round 1 */
	RMD128STEP(RMD128_F4, RMD128_S5, aa, bb, cc, dd, x[5], 8); 
	RMD128STEP(RMD128_F4, RMD128_S5, dd, aa, bb, cc, x[14], 9);
	RMD128STEP(RMD128_F4, RMD128_S5, cc, dd, aa, bb, x[7], 9);
	RMD128STEP(RMD128_F4, RMD128_S5, bb, cc, dd, aa, x[0], 11);
	RMD128STEP(RMD128_F4, RMD128_S5, aa, bb, cc, dd, x[9], 13);
	RMD128STEP(RMD128_F4, RMD128_S5, dd, aa, bb, cc, x[2], 15);
	RMD128STEP(RMD128_F4, RMD128_S5, cc, dd, aa, bb, x[11], 15);
	RMD128STEP(RMD128_F4, RMD128_S5, bb, cc, dd, aa, x[4], 5);
	RMD128STEP(RMD128_F4, RMD128_S5, aa, bb, cc, dd, x[13], 7);
	RMD128STEP(RMD128_F4, RMD128_S5, dd, aa, bb, cc, x[6], 7);
	RMD128STEP(RMD128_F4, RMD128_S5, cc, dd, aa, bb, x[15], 8);
	RMD128STEP(RMD128_F4, RMD128_S5, bb, cc, dd, aa, x[8], 11);
	RMD128STEP(RMD128_F4, RMD128_S5, aa, bb, cc, dd, x[1], 14);
	RMD128STEP(RMD128_F4, RMD128_S5, dd, aa, bb, cc, x[10], 14);
	RMD128STEP(RMD128_F4, RMD128_S5, cc, dd, aa, bb, x[3], 12);
	RMD128STEP(RMD128_F4, RMD128_S5, bb, cc, dd, aa, x[12], 6);
	
	/* parallel round 2 */
	RMD128STEP(RMD128_F3, RMD128_S6, aa, bb, cc, dd, x[6], 9);
	RMD128STEP(RMD128_F3, RMD128_S6, dd, aa, bb, cc, x[11], 13);
	RMD128STEP(RMD128_F3, RMD128_S6, cc, dd, aa, bb, x[3], 15);
	RMD128STEP(RMD128_F3, RMD128_S6, bb, cc, dd, aa, x[7], 7);
	RMD128STEP(RMD128_F3, RMD128_S6, aa, bb, cc, dd, x[0], 12);
	RMD128STEP(RMD128_F3, RMD128_S6, dd, aa, bb, cc, x[13], 8);
	RMD128STEP(RMD128_F3, RMD128_S6, cc, dd, aa, bb, x[5], 9);
	RMD128STEP(RMD128_F3, RMD128_S6, bb, cc, dd, aa, x[10], 11);
	RMD128STEP(RMD128_F3, RMD128_S6, aa, bb, cc, dd, x[14], 7);
	RMD128STEP(RMD128_F3, RMD128_S6, dd, aa, bb, cc, x[15], 7);
	RMD128STEP(RMD128_F3, RMD128_S6, cc, dd, aa, bb, x[8], 12);
	RMD128STEP(RMD128_F3, RMD128_S6, bb, cc, dd, aa, x[12], 7);
	RMD128STEP(RMD128_F3, RMD128_S6, aa, bb, cc, dd, x[4], 6);
	RMD128STEP(RMD128_F3, RMD128_S6, dd, aa, bb, cc, x[9], 15);
	RMD128STEP(RMD128_F3, RMD128_S6, cc, dd, aa, bb, x[1], 13);
	RMD128STEP(RMD128_F3, RMD128_S6, bb, cc, dd, aa, x[2], 11);
	
	/* parallel round 3 */   
	RMD128STEP(RMD128_F2, RMD128_S7, aa, bb, cc, dd, x[15], 9);
	RMD128STEP(RMD128_F2, RMD128_S7, dd, aa, bb, cc, x[5], 7);
	RMD128STEP(RMD128_F2, RMD128_S7, cc, dd, aa, bb, x[1], 15);
	RMD128STEP(RMD128_F2, RMD128_S7, bb, cc, dd, aa, x[3], 11);
	RMD128STEP(RMD128_F2, RMD128_S7, aa, bb, cc, dd, x[7], 8);
	RMD128STEP(RMD128_F2, RMD128_S7, dd, aa, bb, cc, x[14], 6);
	RMD128STEP(RMD128_F2, RMD128_S7, cc, dd, aa, bb, x[6], 6);
	RMD128STEP(RMD128_F2, RMD128_S7, bb, cc, dd, aa, x[9], 14);
	RMD128STEP(RMD128_F2, RMD128_S7, aa, bb, cc, dd, x[11], 12);
	RMD128STEP(RMD128_F2, RMD128_S7, dd, aa, bb, cc, x[8], 13);
	RMD128STEP(RMD128_F2, RMD128_S7, cc, dd, aa, bb, x[12], 5);
	RMD128STEP(RMD128_F2, RMD128_S7, bb, cc, dd, aa, x[2], 14);
	RMD128STEP(RMD128_F2, RMD128_S7, aa, bb, cc, dd, x[10], 13);
	RMD128STEP(RMD128_F2, RMD128_S7, dd, aa, bb, cc, x[0], 13);
	RMD128STEP(RMD128_F2, RMD128_S7, cc, dd, aa, bb, x[4], 7);
	RMD128STEP(RMD128_F2, RMD128_S7, bb, cc, dd, aa, x[13], 5);
	
	/* parallel round 4 */
	RMD128STEP(RMD128_F1, RMD128_S8, aa, bb, cc, dd, x[8], 15);
	RMD128STEP(RMD128_F1, RMD128_S8, dd, aa, bb, cc, x[6], 5);
	RMD128STEP(RMD128_F1, RMD128_S8, cc, dd, aa, bb, x[4], 8);
	RMD128STEP(RMD128_F1, RMD128_S8, bb, cc, dd, aa, x[1], 11);
	RMD128STEP(RMD128_F1, RMD128_S8, aa, bb, cc, dd, x[3], 14);
	RMD128STEP(RMD128_F1, RMD128_S8, dd, aa, bb, cc, x[11], 14);
	RMD128STEP(RMD128_F1, RMD128_S8, cc, dd, aa, bb, x[15], 6);
	RMD128STEP(RMD128_F1, RMD128_S8, bb, cc, dd, aa, x[0], 14);
	RMD128STEP(RMD128_F1, RMD128_S8, aa, bb, cc, dd, x[5], 6);
	RMD128STEP(RMD128_F1, RMD128_S8, dd, aa, bb, cc, x[12], 9);
	RMD128STEP(RMD128_F1, RMD128_S8, cc, dd, aa, bb, x[2], 12);
	RMD128STEP(RMD128_F1, RMD128_S8, bb, cc, dd, aa, x[13], 9);
	RMD128STEP(RMD128_F1, RMD128_S8, aa, bb, cc, dd, x[9], 12);
	RMD128STEP(RMD128_F1, RMD128_S8, dd, aa, bb, cc, x[7], 5);
	RMD128STEP(RMD128_F1, RMD128_S8, cc, dd, aa, bb, x[10], 15);
	RMD128STEP(RMD128_F1, RMD128_S8, bb, cc, dd, aa, x[14], 8);
	
	dd += c + context->state[1];
	context->state[1] = context->state[2] + d + aa;
	context->state[2] = context->state[3] + a + bb;
	context->state[3] = context->state[0] + b + cc;
	context->state[0] = dd;
}

int RMD128Test() {
	static const struct {
		char *msg;
		unsigned char hash[RMD128Length];
	} tests[] = {
		{
			"",
			{0xcd,0xf2,0x62,0x13,0xa1,0x50,0xdc,0x3e,0xcb,0x61,0x0f,0x18,0xf6,0xb3,0x8b,0x46}
		},
		{
			"a",
			{0x86,0xbe,0x7a,0xfa,0x33,0x9d,0x0f,0xc7,0xcf,0xc7,0x85,0xe7,0x2f,0x57,0x8d,0x33}
		},
		{
			"abc",
			{0xc1,0x4a,0x12,0x19,0x9c,0x66,0xe4,0xba,0x84,0x63,0x6b,0x0f,0x69,0x14,0x4c,0x77}
		},
		{
			"message digest",
			{0x9e,0x32,0x7b,0x3d,0x6e,0x52,0x30,0x62,0xaf,0xc1,0x13,0x2d,0x7d,0xf9,0xd1,0xb8}
		},
		{
			"abcdefghijklmnopqrstuvwxyz",
			{0xfd,0x2a,0xa6,0x07,0xf7,0x1d,0xc8,0xf5,0x10,0x71,0x49,0x22,0xb3,0x71,0x83,0x4e}
		},
		{
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			{0xd1,0xe9,0x59,0xeb,0x17,0x9c,0x91,0x1f,0xae,0xa4,0x62,0x4c,0x60,0xc5,0xc7,0x02}
		},
		{NULL, {0}}
	};
	
	struct RMD128Context MDContext;
	unsigned char MDDigest[RMD128Length];
	
	for (int i=0; tests[i].msg!=NULL; i++) {
		RMD128Init(&MDContext);
		RMD128Update(&MDContext, (unsigned char *)tests[i].msg, (unsigned long)strlen(tests[i].msg));
		RMD128Final(MDDigest, &MDContext);
		
		if (memcmp(MDDigest, tests[i].hash, RMD128Length))
			return 0;
	}
	
	return 1;
}