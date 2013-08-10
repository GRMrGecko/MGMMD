//
//  MGMMD4.m
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 5/27/11.
//  No Copyright Claimed. Public Domain.
//  C Algorithm created by Tom St Denis <tomstdenis@gmail.com> <http://libtom.org>
//

#ifdef __NEXT_RUNTIME__
#import "MGMMD4.h"
#import "MGMTypes.h"

NSString * const MDNMD4 = @"md4";

@implementation NSString (MGMMD4)
- (NSString *)MD4 {
	NSData *MDData = [self dataUsingEncoding:NSUTF8StringEncoding];
	struct MD4Context MDContext;
	unsigned char MDDigest[MD4Length];
	
	MD4Init(&MDContext);
	MD4Update(&MDContext, [MDData bytes], [MDData length]);
	MD4Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(MD4Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<MD4Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	NSString *hash = [NSString stringWithUTF8String:stringBuffer];
	free(stringBuffer);
	return hash;
}
- (NSString *)pathMD4 {
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:self];
	if (file==nil)
		return nil;
	struct MD4Context MDContext;
	unsigned char MDDigest[MD4Length];
	
	MD4Init(&MDContext);
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *MDData = [file readDataOfLength:MDFileReadLength];
		length = [MDData length];
		MD4Update(&MDContext, [MDData bytes], length);
		[pool release];
	} while (length>0);
	MD4Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(MD4Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<MD4Length; i++) {
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
#include "MGMMD4.h"
#include "MGMTypes.h"
#endif

const struct MGMHashDescription MD4Desc = {
	"md4",
    sizeof(struct MD4Context),
    (void(*)(void *))&MD4Init,
	(void(*)(void *, const unsigned char *, unsigned))&MD4Update,
	(void(*)(unsigned char *, void *))&MD4Final,
	MD4Length
};

char *MD4String(const char *string, int length) {
	struct MD4Context MDContext;
	unsigned char MDDigest[MD4Length];
	
	MD4Init(&MDContext);
	MD4Update(&MDContext, (const unsigned char *)string, length);
	MD4Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(MD4Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<MD4Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}
char *MD4File(const char *path) {
	FILE *file = fopen(path, "r");
	if (file==NULL)
		return NULL;
	struct MD4Context MDContext;
	unsigned char MDDigest[MD4Length];
	
	MD4Init(&MDContext);
	int length;
	do {
		unsigned char MDData[MDFileReadLength];
		length = fread(&MDData, 1, MDFileReadLength, file);
		MD4Update(&MDContext, MDData, length);
	} while (length>0);
	MD4Final(MDDigest, &MDContext);
	
	fclose(file);
	
	char *stringBuffer = (char *)malloc(MD4Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<MD4Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}

void MD4Init(struct MD4Context *context) {
	context->state[0] = INT32(0x67452301);
	context->state[1] = INT32(0xefcdab89);
	context->state[2] = INT32(0x98badcfe);
	context->state[3] = INT32(0x10325476);
	context->length = 0;
	context->curlen = 0;
}

void MD4Update(struct MD4Context *context, const unsigned char *buf, unsigned len) {
	if (buf==NULL)
		return;
	unsigned long n;
	while (len>0) {
		if (context->curlen == 0 && len>=MD4BufferSize) {
			MD4Transform(context, (unsigned char *)buf);
			context->length += MD4BufferSize * 8;
			buf += MD4BufferSize;
			len -= MD4BufferSize;
		} else {
			n = MIN(len, (MD4BufferSize-context->curlen));
			memcpy(context->buf+context->curlen, buf, (size_t)n);
			context->curlen += n;
			buf += n;
			len -= n;
			if (context->curlen == MD4BufferSize) {
				MD4Transform(context, context->buf);
				context->length += 8*MD4BufferSize;
				context->curlen = 0;
			}
		}
	}
}

void MD4Final(unsigned char digest[MD4Length], struct MD4Context *context) {
	context->length += context->curlen * 8;
	context->buf[context->curlen++] = (unsigned char)0x80;
	
	if (context->curlen > 56) {
		while (context->curlen < MD4BufferSize) {
			context->buf[context->curlen++] = (unsigned char)0;
		}
		MD4Transform(context, context->buf);
		context->curlen = 0;
	}
	
	while (context->curlen < 56) {
		context->buf[context->curlen++] = (unsigned char)0;
	}
	
	putu64l(context->length, context->buf+56);
	MD4Transform(context, context->buf);
	
	for (int i=0; i<4; i++) {
		putu32l(context->state[i], digest+(4*i));
	}
	
	memset(context, 0, sizeof(struct MD4Context));
}

#define MD4_S1 0
#define MD4_S2 INT32(0x5a827999)
#define MD4_S3 INT32(0x6ed9eba1)

#define MD4_F1(x, y, z) (z ^ (x & (y ^ z)))
#define MD4_F2(x, y, z) ((x & y) | (z & (x | y)))
#define MD4_F3(x, y, z) ((x) ^ (y) ^ (z))

#define MD4STEP(a, b, c, d, e, f, g, h) \
	(c) += a((d), (e), (f)) + (g) + b; (c) = ROL32((c), (h));

void MD4Transform(struct MD4Context *context, unsigned char *buf) {
	uint32_t x[16];
	
	uint32_t a = context->state[0];
	uint32_t b = context->state[1];
	uint32_t c = context->state[2];
	uint32_t d = context->state[3];
	
	for (int i=0; i<16; i++) {
		x[i] = getu32l(buf+(4*i));
	}
	
	/* Round 1 */
	MD4STEP(MD4_F1, MD4_S1, a, b, c, d, x[0], 3);
	MD4STEP(MD4_F1, MD4_S1, d, a, b, c, x[1], 7);
	MD4STEP(MD4_F1, MD4_S1, c, d, a, b, x[2], 11);
	MD4STEP(MD4_F1, MD4_S1, b, c, d, a, x[3], 19);
	MD4STEP(MD4_F1, MD4_S1, a, b, c, d, x[4], 3);
	MD4STEP(MD4_F1, MD4_S1, d, a, b, c, x[5], 7);
	MD4STEP(MD4_F1, MD4_S1, c, d, a, b, x[6], 11);
	MD4STEP(MD4_F1, MD4_S1, b, c, d, a, x[7], 19);
	MD4STEP(MD4_F1, MD4_S1, a, b, c, d, x[8], 3);
	MD4STEP(MD4_F1, MD4_S1, d, a, b, c, x[9], 7);
	MD4STEP(MD4_F1, MD4_S1, c, d, a, b, x[10], 11);
	MD4STEP(MD4_F1, MD4_S1, b, c, d, a, x[11], 19);
	MD4STEP(MD4_F1, MD4_S1, a, b, c, d, x[12], 3);
	MD4STEP(MD4_F1, MD4_S1, d, a, b, c, x[13], 7);
	MD4STEP(MD4_F1, MD4_S1, c, d, a, b, x[14], 11);
	MD4STEP(MD4_F1, MD4_S1, b, c, d, a, x[15], 19);
	
	/* Round 2 */
	MD4STEP(MD4_F2, MD4_S2, a, b, c, d, x[0], 3);
	MD4STEP(MD4_F2, MD4_S2, d, a, b, c, x[4], 5);
	MD4STEP(MD4_F2, MD4_S2, c, d, a, b, x[8], 9);
	MD4STEP(MD4_F2, MD4_S2, b, c, d, a, x[12], 13);
	MD4STEP(MD4_F2, MD4_S2, a, b, c, d, x[1], 3);
	MD4STEP(MD4_F2, MD4_S2, d, a, b, c, x[5], 5);
	MD4STEP(MD4_F2, MD4_S2, c, d, a, b, x[9], 9);
	MD4STEP(MD4_F2, MD4_S2, b, c, d, a, x[13], 13);
	MD4STEP(MD4_F2, MD4_S2, a, b, c, d, x[2], 3);
	MD4STEP(MD4_F2, MD4_S2, d, a, b, c, x[6], 5);
	MD4STEP(MD4_F2, MD4_S2, c, d, a, b, x[10], 9);
	MD4STEP(MD4_F2, MD4_S2, b, c, d, a, x[14], 13);
	MD4STEP(MD4_F2, MD4_S2, a, b, c, d, x[3], 3);
	MD4STEP(MD4_F2, MD4_S2, d, a, b, c, x[7], 5);
	MD4STEP(MD4_F2, MD4_S2, c, d, a, b, x[11], 9);
	MD4STEP(MD4_F2, MD4_S2, b, c, d, a, x[15], 13);
	
	/* Round 3 */
	MD4STEP(MD4_F3, MD4_S3, a, b, c, d, x[0], 3);
	MD4STEP(MD4_F3, MD4_S3, d, a, b, c, x[8], 9);
	MD4STEP(MD4_F3, MD4_S3, c, d, a, b, x[4], 11);
	MD4STEP(MD4_F3, MD4_S3, b, c, d, a, x[12], 15);
	MD4STEP(MD4_F3, MD4_S3, a, b, c, d, x[2], 3);
	MD4STEP(MD4_F3, MD4_S3, d, a, b, c, x[10], 9);
	MD4STEP(MD4_F3, MD4_S3, c, d, a, b, x[6], 11);
	MD4STEP(MD4_F3, MD4_S3, b, c, d, a, x[14], 15);
	MD4STEP(MD4_F3, MD4_S3, a, b, c, d, x[1], 3);
	MD4STEP(MD4_F3, MD4_S3, d, a, b, c, x[9], 9);
	MD4STEP(MD4_F3, MD4_S3, c, d, a, b, x[5], 11);
	MD4STEP(MD4_F3, MD4_S3, b, c, d, a, x[13], 15);
	MD4STEP(MD4_F3, MD4_S3, a, b, c, d, x[3], 3);
	MD4STEP(MD4_F3, MD4_S3, d, a, b, c, x[11], 9);
	MD4STEP(MD4_F3, MD4_S3, c, d, a, b, x[7], 11);
	MD4STEP(MD4_F3, MD4_S3, b, c, d, a, x[15], 15);
	
	context->state[0] = context->state[0] + a;
	context->state[1] = context->state[1] + b;
	context->state[2] = context->state[2] + c;
	context->state[3] = context->state[3] + d;
}

int MD4Test() {
	static const struct {
		char *msg;
		unsigned char hash[MD4Length];
	} tests[] = {
		{
			"",
			{0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0}
		},
		{
			"a",
			{0xbd,0xe5,0x2c,0xb3,0x1d,0xe3,0x3e,0x46,0x24,0x5e,0x05,0xfb,0xdb,0xd6,0xfb,0x24}
		},
		{
			"abc",
			{0xa4,0x48,0x01,0x7a,0xaf,0x21,0xd8,0x52,0x5f,0xc1,0x0a,0xe8,0x7a,0xa6,0x72,0x9d}
		},
		{
			"message digest", 
			{0xd9,0x13,0x0a,0x81,0x64,0x54,0x9f,0xe8,0x18,0x87,0x48,0x06,0xe1,0xc7,0x01,0x4b}
		},
		{
			"abcdefghijklmnopqrstuvwxyz", 
			{0xd7,0x9e,0x1c,0x30,0x8a,0xa5,0xbb,0xcd,0xee,0xa8,0xed,0x63,0xdf,0x41,0x2d,0xa9}
		},
		{
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 
			{0x04,0x3f,0x85,0x82,0xf2,0x41,0xdb,0x35,0x1c,0xe6,0x27,0xe1,0x53,0xe7,0xf0,0xe4}
		},
		{
			"12345678901234567890123456789012345678901234567890123456789012345678901234567890", 
			{0xe3,0x3b,0x4d,0xdc,0x9c,0x38,0xf2,0x19,0x9c,0x3e,0x7b,0x16,0x4f,0xcc,0x05,0x36}
		},
		{NULL, {0}}
	};
	
	struct MD4Context MDContext;
	unsigned char MDDigest[MD4Length];
	
	for (int i=0; tests[i].msg!=NULL; i++) {
		MD4Init(&MDContext);
		MD4Update(&MDContext, (unsigned char *)tests[i].msg, (unsigned long)strlen(tests[i].msg));
		MD4Final(MDDigest, &MDContext);
		
		if (memcmp(MDDigest, tests[i].hash, MD4Length))
			return 0;
	}
	
	return 1;
}