//
//  MGMSHA1.m
//  MGMMD
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 8/23/10.
//  No Copyright Claimed. Public Domain.
//  C Algorithm created by Steve Reid <steve@edmweb.com>
//

#ifdef __NEXT_RUNTIME__
#import "MGMSHA1.h"
#import "MGMTypes.h"

NSString * const MDNSHA1 = @"sha1";

@implementation NSString (MGMSHA1)
- (NSString *)SHA1 {
	NSData *MDData = [self dataUsingEncoding:NSUTF8StringEncoding];
	struct SHA1Context MDContext;
	unsigned char MDDigest[SHA1Length];
	
	SHA1Init(&MDContext);
	SHA1Update(&MDContext, [MDData bytes], [MDData length]);
	SHA1Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA1Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA1Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	NSString *hash = [NSString stringWithUTF8String:stringBuffer];
	free(stringBuffer);
	return hash;
}
- (NSString *)pathSHA1 {
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:self];
	if (file==nil)
		return nil;
	struct SHA1Context MDContext;
	unsigned char MDDigest[SHA1Length];
	
	SHA1Init(&MDContext);
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *MDData = [file readDataOfLength:MDFileReadLength];
		length = [MDData length];
		SHA1Update(&MDContext, [MDData bytes], length);
		[pool release];
	} while (length>0);
	SHA1Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA1Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA1Length; i++) {
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
#include "MGMSHA1.h"
#include "MGMTypes.h"
#endif

const struct MGMHashDescription SHA1Desc = {
	"sha1",
    sizeof(struct SHA1Context),
    (void(*)(void *))&SHA1Init,
	(void(*)(void *, const unsigned char *, unsigned))&SHA1Update,
	(void(*)(unsigned char *, void *))&SHA1Final,
	SHA1Length
};

char *SHA1String(const char *string, int length) {
	struct SHA1Context MDContext;
	unsigned char MDDigest[SHA1Length];
	
	SHA1Init(&MDContext);
	SHA1Update(&MDContext, (const unsigned char *)string, length);
	SHA1Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA1Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA1Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}
char *SHA1File(const char *path) {
	FILE *file = fopen(path, "r");
	if (file==NULL)
		return NULL;
	struct SHA1Context MDContext;
	unsigned char MDDigest[SHA1Length];
	
	SHA1Init(&MDContext);
	int length;
	do {
		unsigned char MDData[MDFileReadLength];
		length = fread(&MDData, 1, MDFileReadLength, file);
		SHA1Update(&MDContext, MDData, length);
	} while (length>0);
	SHA1Final(MDDigest, &MDContext);
	
	fclose(file);
	
	char *stringBuffer = (char *)malloc(SHA1Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA1Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}

void SHA1Init(struct SHA1Context *context) {
	context->state[0] = INT32(0x67452301);
	context->state[1] = INT32(0xEFCDAB89);
	context->state[2] = INT32(0x98BADCFE);
	context->state[3] = INT32(0x10325476);
	context->state[4] = INT32(0xC3D2E1F0);
	
	context->curlen = 0;
	context->length = 0;
}

void SHA1Update(struct SHA1Context *context, const unsigned char *buf, unsigned len) {
	if (buf==NULL)
		return;
	unsigned long n;
	while (len>0) {
		if (context->curlen == 0 && len>=SHA1BufferSize) {
			SHA1Transform(context, (unsigned char *)buf);
			context->length += SHA1BufferSize * 8;
			buf += SHA1BufferSize;
			len -= SHA1BufferSize;
		} else {
			n = MIN(len, (SHA1BufferSize-context->curlen));
			memcpy(context->buf+context->curlen, buf, (size_t)n);
			context->curlen += n;
			buf += n;
			len -= n;
			if (context->curlen == SHA1BufferSize) {
				SHA1Transform(context, context->buf);
				context->length += 8*SHA1BufferSize;
				context->curlen = 0;
			}
		}
	}
}

void SHA1Final(unsigned char digest[SHA1Length], struct SHA1Context *context) {
	context->length += context->curlen * 8;
	context->buf[context->curlen++] = (unsigned char)0x80;
	
	if (context->curlen > 56) {
		while (context->curlen < 64) {
			context->buf[context->curlen++] = (unsigned char)0;
		}
		SHA1Transform(context, context->buf);
		context->curlen = 0;
	}
	
	while (context->curlen < 56) {
		context->buf[context->curlen++] = (unsigned char)0;
	}
	
	putu64(context->length, context->buf+56);
	SHA1Transform(context, context->buf);
	
	for (int i=0; i<5; i++) {
		putu32(context->state[i], digest+(4*i));
	}
	
	memset(context, 0, sizeof(struct SHA1Context));
}

#define SHA1_rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#if BYTE_ORDER == LITTLE_ENDIAN
#define SHA1_blk0(i) (block->l[i] = (SHA1_rol(block->l[i], 24)&INT32(0xFF00FF00)) |(SHA1_rol(block->l[i], 8)&INT32(0x00FF00FF)))
#elif BYTE_ORDER == BIG_ENDIAN
#define SHA1_blk0(i) block->l[i]
#else
#error "Endianness not defined!"
#endif
#define SHA1_blk(i) (block->l[i&15] = SHA1_rol(block->l[(i+13)&15]^block->l[(i+8)&15] ^block->l[(i+2)&15]^block->l[i&15], 1))

#define SHA1_R0(v, w, x, y, z, i) z+=((w&(x^y))^y)+SHA1_blk0(i)+INT32(0x5A827999)+SHA1_rol(v, 5);w=SHA1_rol(w, 30);
#define SHA1_R1(v, w, x, y, z, i) z+=((w&(x^y))^y)+SHA1_blk(i)+INT32(0x5A827999)+SHA1_rol(v, 5);w=SHA1_rol(w, 30);
#define SHA1_R2(v, w, x, y, z, i) z+=(w^x^y)+SHA1_blk(i)+INT32(0x6ED9EBA1)+SHA1_rol(v, 5);w=SHA1_rol(w, 30);
#define SHA1_R3(v, w, x, y, z, i) z+=(((w|x)&y)|(w&x))+SHA1_blk(i)+INT32(0x8F1BBCDC)+SHA1_rol(v, 5);w=SHA1_rol(w, 30);
#define SHA1_R4(v, w, x, y, z, i) z+=(w^x^y)+SHA1_blk(i)+INT32(0xCA62C1D6)+SHA1_rol(v, 5);w=SHA1_rol(w, 30);

#define SHA1STEP(v, w, x, y, z, i) \
	if (i<16) {SHA1_R0(v, w, x, y, z, i);} else \
	if (i<20) {SHA1_R1(v, w, x, y, z, i);} else \
	if (i<40) {SHA1_R2(v, w, x, y, z, i);} else \
	if (i<60) {SHA1_R3(v, w, x, y, z, i);} else \
	if (i<80) {SHA1_R4(v, w, x, y, z, i);}

void SHA1Transform(struct SHA1Context *context, unsigned char *buf) {
	typedef union {
		char c[64];
		u_int32_t l[16];
	} SHA1LONG;
	SHA1LONG *block = (SHA1LONG *)buf;
	
	u_int32_t a = context->state[0];
	u_int32_t b = context->state[1];
	u_int32_t c = context->state[2];
	u_int32_t d = context->state[3];
	u_int32_t e = context->state[4];
	
	for (int i=0; i<79; i = i+5) {
		SHA1STEP(a, b, c, d, e, i);
		SHA1STEP(e, a, b, c, d, i + 1);
		SHA1STEP(d, e, a, b, c, i + 2);
		SHA1STEP(c, d, e, a, b, i + 3);
		SHA1STEP(b, c, d, e, a, i + 4);
	}
	
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
}

int SHA1Test() {
	static const struct {
		char *msg;
		unsigned char hash[SHA1Length];
	} tests[] = {
		{
			"abc",
			{0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d}
		},
		{
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			{0x84,0x98,0x3E,0x44,0x1C,0x3B,0xD2,0x6E,0xBA,0xAE,0x4A,0xA1,0xF9,0x51,0x29,0xE5,0xE5,0x46,0x70,0xF1}
		},
		{NULL, {0}}
	};
	
	struct SHA1Context MDContext;
	unsigned char MDDigest[SHA1Length];
	
	for (int i=0; tests[i].msg!=NULL; i++) {
		SHA1Init(&MDContext);
		SHA1Update(&MDContext, (unsigned char *)tests[i].msg, (unsigned long)strlen(tests[i].msg));
		SHA1Final(MDDigest, &MDContext);
		
		if (memcmp(MDDigest, tests[i].hash, SHA1Length))
			return 0;
	}
	
	return 1;
}