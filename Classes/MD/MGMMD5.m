//
//  MGMMD5.m
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 1/6/10.
//  No Copyright Claimed. Public Domain.
//  C Algorithm created by Tom St Denis <tomstdenis@gmail.com> <http://libtom.org>
//

#ifdef __NEXT_RUNTIME__
#import "MGMMD5.h"
#import "MGMTypes.h"

NSString * const MDNMD5 = @"md5";

@implementation NSString (MGMMD5)
- (NSString *)MD5 {
	NSData *MDData = [self dataUsingEncoding:NSUTF8StringEncoding];
	struct MD5Context MDContext;
	unsigned char MDDigest[MD5Length];
	
	MD5Init(&MDContext);
	MD5Update(&MDContext, [MDData bytes], [MDData length]);
	MD5Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(MD5Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<MD5Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	NSString *hash = [NSString stringWithUTF8String:stringBuffer];
	free(stringBuffer);
	return hash;
}
- (NSString *)pathMD5 {
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:self];
	if (file==nil)
		return nil;
	struct MD5Context MDContext;
	unsigned char MDDigest[MD5Length];
	
	MD5Init(&MDContext);
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *MDData = [file readDataOfLength:MDFileReadLength];
		length = [MDData length];
		MD5Update(&MDContext, [MDData bytes], length);
		[pool release];
	} while (length>0);
	MD5Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(MD5Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<MD5Length; i++) {
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

const struct MGMHashDescription MD5Desc = {
	"md5",
    sizeof(struct MD5Context),
    (void(*)(void *))&MD5Init,
	(void(*)(void *, const unsigned char *, unsigned))&MD5Update,
	(void(*)(unsigned char *, void *))&MD5Final,
	MD5Length
};

char *MD5String(const char *string, int length) {
	struct MD5Context MDContext;
	unsigned char MDDigest[MD5Length];
	
	MD5Init(&MDContext);
	MD5Update(&MDContext, (const unsigned char *)string, length);
	MD5Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(MD5Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<MD5Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}
char *MD5File(const char *path) {
	FILE *file = fopen(path, "r");
	if (file==NULL)
		return NULL;
	struct MD5Context MDContext;
	unsigned char MDDigest[MD5Length];
	
	MD5Init(&MDContext);
	int length;
	do {
		unsigned char MDData[MDFileReadLength];
		length = fread(&MDData, 1, MDFileReadLength, file);
		MD5Update(&MDContext, MDData, length);
	} while (length>0);
	MD5Final(MDDigest, &MDContext);
	
	fclose(file);
	
	char *stringBuffer = (char *)malloc(MD5Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<MD5Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}

void MD5Init(struct MD5Context *context) {
	context->state[0] = INT32(0x67452301);
	context->state[1] = INT32(0xefcdab89);
	context->state[2] = INT32(0x98badcfe);
	context->state[3] = INT32(0x10325476);
	context->curlen = 0;
	context->length = 0;
}

void MD5Update(struct MD5Context *context, const unsigned char *buf, unsigned len) {
	if (buf==NULL)
		return;
	unsigned long n;
	while (len>0) {
		if (context->curlen == 0 && len>=MD5BufferSize) {
			MD5Transform(context, (unsigned char *)buf);
			context->length += MD5BufferSize * 8;
			buf += MD5BufferSize;
			len -= MD5BufferSize;
		} else {
			n = MIN(len, (MD5BufferSize-context->curlen));
			memcpy(context->buf+context->curlen, buf, (size_t)n);
			context->curlen += n;
			buf += n;
			len -= n;
			if (context->curlen == MD5BufferSize) {
				MD5Transform(context, context->buf);
				context->length += 8*MD5BufferSize;
				context->curlen = 0;
			}
		}
	}
}

void MD5Final(unsigned char digest[MD5Length], struct MD5Context *context) {
	context->length += context->curlen * 8;
	context->buf[context->curlen++] = (unsigned char)0x80;
	
	if (context->curlen > 56) {
		while (context->curlen < 64) {
			context->buf[context->curlen++] = (unsigned char)0;
		}
		MD5Transform(context, context->buf);
		context->curlen = 0;
	}
	
	while (context->curlen < 56) {
		context->buf[context->curlen++] = (unsigned char)0;
	}
	
	putu64l(context->length, context->buf+56);
	MD5Transform(context, context->buf);
	
	for (int i=0; i<4; i++) {
		putu32l(context->state[i], digest+(4*i));
	}
	
	memset(context, 0, sizeof(struct MD5Context));
}

/* #define MD5_F1(x, y, z) (x & y | ~x & z) */
#define MD5_F1(x, y, z) (z ^ (x & (y ^ z)))
#define MD5_F2(x, y, z) MD5_F1(z, x, y)
#define MD5_F3(x, y, z) (x ^ y ^ z)
#define MD5_F4(x, y, z) (y ^ (x | ~z))

#define MD5STEP(f, w, x, y, z, data, s) \
	( w += f(x, y, z) + data, w &= INT32(0xffffffff), w = w<<s | w>>(32-s), w += x )

void MD5Transform(struct MD5Context *context, unsigned char *buf) {
	uint32_t x[16];
	int i;
	
	for (i = 0; i < 16; ++i) {
		x[i] = getu32l(buf+(4*i));
	}
	
	uint32_t a = context->state[0];
	uint32_t b = context->state[1];
	uint32_t c = context->state[2];
	uint32_t d = context->state[3];
	
	// Round 1
	MD5STEP(MD5_F1, a, b, c, d, x[0]+INT32(0xd76aa478), 7);
	MD5STEP(MD5_F1, d, a, b, c, x[1]+INT32(0xe8c7b756), 12);
	MD5STEP(MD5_F1, c, d, a, b, x[2]+INT32(0x242070db), 17);
	MD5STEP(MD5_F1, b, c, d, a, x[3]+INT32(0xc1bdceee), 22);
	MD5STEP(MD5_F1, a, b, c, d, x[4]+INT32(0xf57c0faf), 7);
	MD5STEP(MD5_F1, d, a, b, c, x[5]+INT32(0x4787c62a), 12);
	MD5STEP(MD5_F1, c, d, a, b, x[6]+INT32(0xa8304613), 17);
	MD5STEP(MD5_F1, b, c, d, a, x[7]+INT32(0xfd469501), 22);
	MD5STEP(MD5_F1, a, b, c, d, x[8]+INT32(0x698098d8), 7);
	MD5STEP(MD5_F1, d, a, b, c, x[9]+INT32(0x8b44f7af), 12);
	MD5STEP(MD5_F1, c, d, a, b, x[10]+INT32(0xffff5bb1), 17);
	MD5STEP(MD5_F1, b, c, d, a, x[11]+INT32(0x895cd7be), 22);
	MD5STEP(MD5_F1, a, b, c, d, x[12]+INT32(0x6b901122), 7);
	MD5STEP(MD5_F1, d, a, b, c, x[13]+INT32(0xfd987193), 12);
	MD5STEP(MD5_F1, c, d, a, b, x[14]+INT32(0xa679438e), 17);
	MD5STEP(MD5_F1, b, c, d, a, x[15]+INT32(0x49b40821), 22);
		
	// Round 2
	MD5STEP(MD5_F2, a, b, c, d, x[1]+INT32(0xf61e2562), 5);
	MD5STEP(MD5_F2, d, a, b, c, x[6]+INT32(0xc040b340), 9);
	MD5STEP(MD5_F2, c, d, a, b, x[11]+INT32(0x265e5a51), 14);
	MD5STEP(MD5_F2, b, c, d, a, x[0]+INT32(0xe9b6c7aa), 20);
	MD5STEP(MD5_F2, a, b, c, d, x[5]+INT32(0xd62f105d), 5);
	MD5STEP(MD5_F2, d, a, b, c, x[10]+INT32(0x02441453), 9);
	MD5STEP(MD5_F2, c, d, a, b, x[15]+INT32(0xd8a1e681), 14);
	MD5STEP(MD5_F2, b, c, d, a, x[4]+INT32(0xe7d3fbc8), 20);
	MD5STEP(MD5_F2, a, b, c, d, x[9]+INT32(0x21e1cde6), 5);
	MD5STEP(MD5_F2, d, a, b, c, x[14]+INT32(0xc33707d6), 9);
	MD5STEP(MD5_F2, c, d, a, b, x[3]+INT32(0xf4d50d87), 14);
	MD5STEP(MD5_F2, b, c, d, a, x[8]+INT32(0x455a14ed), 20);
	MD5STEP(MD5_F2, a, b, c, d, x[13]+INT32(0xa9e3e905), 5);
	MD5STEP(MD5_F2, d, a, b, c, x[2]+INT32(0xfcefa3f8), 9);
	MD5STEP(MD5_F2, c, d, a, b, x[7]+INT32(0x676f02d9), 14);
	MD5STEP(MD5_F2, b, c, d, a, x[12]+INT32(0x8d2a4c8a), 20);
		
	// Round 3
	MD5STEP(MD5_F3, a, b, c, d, x[5]+INT32(0xfffa3942), 4);
	MD5STEP(MD5_F3, d, a, b, c, x[8]+INT32(0x8771f681), 11);
	MD5STEP(MD5_F3, c, d, a, b, x[11]+INT32(0x6d9d6122), 16);
	MD5STEP(MD5_F3, b, c, d, a, x[14]+INT32(0xfde5380c), 23);
	MD5STEP(MD5_F3, a, b, c, d, x[1]+INT32(0xa4beea44), 4);
	MD5STEP(MD5_F3, d, a, b, c, x[4]+INT32(0x4bdecfa9), 11);
	MD5STEP(MD5_F3, c, d, a, b, x[7]+INT32(0xf6bb4b60), 16);
	MD5STEP(MD5_F3, b, c, d, a, x[10]+INT32(0xbebfbc70), 23);
	MD5STEP(MD5_F3, a, b, c, d, x[13]+INT32(0x289b7ec6), 4);
	MD5STEP(MD5_F3, d, a, b, c, x[0]+INT32(0xeaa127fa), 11);
	MD5STEP(MD5_F3, c, d, a, b, x[3]+INT32(0xd4ef3085), 16);
	MD5STEP(MD5_F3, b, c, d, a, x[6]+INT32(0x04881d05), 23);
	MD5STEP(MD5_F3, a, b, c, d, x[9]+INT32(0xd9d4d039), 4);
	MD5STEP(MD5_F3, d, a, b, c, x[12]+INT32(0xe6db99e5), 11);
	MD5STEP(MD5_F3, c, d, a, b, x[15]+INT32(0x1fa27cf8), 16);
	MD5STEP(MD5_F3, b, c, d, a, x[2]+INT32(0xc4ac5665), 23);
		
	// Round 4
	MD5STEP(MD5_F4, a, b, c, d, x[0]+INT32(0xf4292244), 6);
	MD5STEP(MD5_F4, d, a, b, c, x[7]+INT32(0x432aff97), 10);
	MD5STEP(MD5_F4, c, d, a, b, x[14]+INT32(0xab9423a7), 15);
	MD5STEP(MD5_F4, b, c, d, a, x[5]+INT32(0xfc93a039), 21);
	MD5STEP(MD5_F4, a, b, c, d, x[12]+INT32(0x655b59c3), 6);
	MD5STEP(MD5_F4, d, a, b, c, x[3]+INT32(0x8f0ccc92), 10);
	MD5STEP(MD5_F4, c, d, a, b, x[10]+INT32(0xffeff47d), 15);
	MD5STEP(MD5_F4, b, c, d, a, x[1]+INT32(0x85845dd1), 21);
	MD5STEP(MD5_F4, a, b, c, d, x[8]+INT32(0x6fa87e4f), 6);
	MD5STEP(MD5_F4, d, a, b, c, x[15]+INT32(0xfe2ce6e0), 10);
	MD5STEP(MD5_F4, c, d, a, b, x[6]+INT32(0xa3014314), 15);
	MD5STEP(MD5_F4, b, c, d, a, x[13]+INT32(0x4e0811a1), 21);
	MD5STEP(MD5_F4, a, b, c, d, x[4]+INT32(0xf7537e82), 6);
	MD5STEP(MD5_F4, d, a, b, c, x[11]+INT32(0xbd3af235), 10);
	MD5STEP(MD5_F4, c, d, a, b, x[2]+INT32(0x2ad7d2bb), 15);
	MD5STEP(MD5_F4, b, c, d, a, x[9]+INT32(0xeb86d391), 21);
	
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
}

int MD5Test() {
	static const struct {
		char *msg;
		unsigned char hash[MD5Length];
	} tests[] = {
		{
			"",
			{0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e}
		},
		{
			"a",
			{0x0c,0xc1,0x75,0xb9,0xc0,0xf1,0xb6,0xa8,0x31,0xc3,0x99,0xe2,0x69,0x77,0x26,0x61}
		},
		{
			"abc",
			{0x90,0x01,0x50,0x98,0x3c,0xd2,0x4f,0xb0,0xd6,0x96,0x3f,0x7d,0x28,0xe1,0x7f,0x72}
		},
		{
			"message digest",
			{0xf9,0x6b,0x69,0x7d,0x7c,0xb7,0x93,0x8d,0x52,0x5a,0x2f,0x31,0xaa,0xf1,0x61,0xd0}
		},
		{
			"abcdefghijklmnopqrstuvwxyz",
			{0xc3,0xfc,0xd3,0xd7,0x61,0x92,0xe4,0x00,0x7d,0xfb,0x49,0x6c,0xca,0x67,0xe1,0x3b}
		},
		{
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			{0xd1,0x74,0xab,0x98,0xd2,0x77,0xd9,0xf5,0xa5,0x61,0x1c,0x2c,0x9f,0x41,0x9d,0x9f}
		},
		{
			"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
			{0x57,0xed,0xf4,0xa2,0x2b,0xe3,0xc9,0x55,0xac,0x49,0xda,0x2e,0x21,0x07,0xb6,0x7a}
		},
		{NULL, {0}}
	};
	
	struct MD5Context MDContext;
	unsigned char MDDigest[MD5Length];
	
	for (int i=0; tests[i].msg!=NULL; i++) {
		MD5Init(&MDContext);
		MD5Update(&MDContext, (unsigned char *)tests[i].msg, (unsigned long)strlen(tests[i].msg));
		MD5Final(MDDigest, &MDContext);
		
		if (memcmp(MDDigest, tests[i].hash, MD5Length))
			return 0;
	}
	
	return 1;
}