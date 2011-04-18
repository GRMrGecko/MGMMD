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
#include "MGMMD5.h"
#include "MGMTypes.h"
#endif

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
	context->buf[0] = 0x67452301;
	context->buf[1] = 0xEFCDAB89;
	context->buf[2] = 0x98BADCFE;
	context->buf[3] = 0x10325476;
	context->buf[4] = 0xC3D2E1F0;
	
	context->bits[0] = 0;
	context->bits[1] = 0;
}

void SHA1Update(struct SHA1Context *context, const unsigned char *buf, unsigned len) {
	u_int32_t i, j;
	
	j = context->bits[0];
	if ((context->bits[0] += len << 3) < j)
		context->bits[1]++;
	context->bits[1] += (len>>29);
	j = (j >> 3) & 63;
	if ((j + len) > 63) {
		memcpy(&context->in[j], buf, (i = 64-j));
		SHA1Transform(context->buf, context->in);
		for ( ; i + 63 < len; i += 64) {
			SHA1Transform(context->buf, &buf[i]);
		}
		j = 0;
	}
	else i = 0;
	memcpy(&context->in[j], &buf[i], len - i);
}

void SHA1Final(unsigned char digest[SHA1Length], struct SHA1Context *context) {
	unsigned char bits[8];
	unsigned int count;
	
	putu32(context->bits[1], bits);
	putu32(context->bits[0], bits + 4);
	
	count = (context->bits[0] >> 3) & 0x3f;
	count = (count < 56) ? (56 - count) : (120 - count);
	SHA1Update(context, MDPadding, count);
	
	SHA1Update(context, bits, 8);
	
	for (int i=0; i<5; i++)
		putu32(context->buf[i], digest + (4 * i));
	
	memset(context, 0, sizeof(context));
}

#define SHA1_rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#if BYTE_ORDER == LITTLE_ENDIAN
#define SHA1_blk0(i) (block->l[i] = (SHA1_rol(block->l[i], 24)&0xFF00FF00) |(SHA1_rol(block->l[i], 8)&0x00FF00FF))
#elif BYTE_ORDER == BIG_ENDIAN
#define SHA1_blk0(i) block->l[i]
#else
#error "Endianness not defined!"
#endif
#define SHA1_blk(i) (block->l[i&15] = SHA1_rol(block->l[(i+13)&15]^block->l[(i+8)&15] ^block->l[(i+2)&15]^block->l[i&15], 1))

#define SHA1_R0(v, w, x, y, z, i) z+=((w&(x^y))^y)+SHA1_blk0(i)+0x5A827999+SHA1_rol(v, 5);w=SHA1_rol(w, 30);
#define SHA1_R1(v, w, x, y, z, i) z+=((w&(x^y))^y)+SHA1_blk(i)+0x5A827999+SHA1_rol(v, 5);w=SHA1_rol(w, 30);
#define SHA1_R2(v, w, x, y, z, i) z+=(w^x^y)+SHA1_blk(i)+0x6ED9EBA1+SHA1_rol(v, 5);w=SHA1_rol(w, 30);
#define SHA1_R3(v, w, x, y, z, i) z+=(((w|x)&y)|(w&x))+SHA1_blk(i)+0x8F1BBCDC+SHA1_rol(v, 5);w=SHA1_rol(w, 30);
#define SHA1_R4(v, w, x, y, z, i) z+=(w^x^y)+SHA1_blk(i)+0xCA62C1D6+SHA1_rol(v, 5);w=SHA1_rol(w, 30);

#define SHA1STEP(v, w, x, y, z, i) \
	if (i<16) {SHA1_R0(v, w, x, y, z, i);} else \
	if (i<20) {SHA1_R1(v, w, x, y, z, i);} else \
	if (i<40) {SHA1_R2(v, w, x, y, z, i);} else \
	if (i<60) {SHA1_R3(v, w, x, y, z, i);} else \
	if (i<80) {SHA1_R4(v, w, x, y, z, i);}

void SHA1Transform(uint32_t buf[SHA1BufferSize], const unsigned char inraw[64]) {
	typedef union {
		char c[64];
		u_int32_t l[16];
	} SHA1LONG;
	SHA1LONG *block = (SHA1LONG *)inraw;
	
	u_int32_t a = buf[0];
	u_int32_t b = buf[1];
	u_int32_t c = buf[2];
	u_int32_t d = buf[3];
	u_int32_t e = buf[4];
	
	for (int i=0; i<79; i = i+5) {
		SHA1STEP(a, b, c, d, e, i);
		SHA1STEP(e, a, b, c, d, i + 1);
		SHA1STEP(d, e, a, b, c, i + 2);
		SHA1STEP(c, d, e, a, b, i + 3);
		SHA1STEP(b, c, d, e, a, i + 4);
	}
	
	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
	buf[4] += e;
}