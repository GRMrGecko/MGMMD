//
//  MGMMD2.m
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 5/27/11.
//  No Copyright Claimed. Public Domain.
//  C Algorithm created by Tom St Denis <tomstdenis@gmail.com> <http://libtom.org>
//

#ifdef __NEXT_RUNTIME__
#import "MGMMD2.h"
#import "MGMTypes.h"

NSString * const MDNMD2 = @"md2";

@implementation NSString (MGMMD2)
- (NSString *)MD2 {
	NSData *MDData = [self dataUsingEncoding:NSUTF8StringEncoding];
	struct MD2Context MDContext;
	unsigned char MDDigest[MD2Length];
	
	MD2Init(&MDContext);
	MD2Update(&MDContext, [MDData bytes], [MDData length]);
	MD2Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(MD2Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<MD2Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	NSString *hash = [NSString stringWithUTF8String:stringBuffer];
	free(stringBuffer);
	return hash;
}
- (NSString *)pathMD2 {
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:self];
	if (file==nil)
		return nil;
	struct MD2Context MDContext;
	unsigned char MDDigest[MD2Length];
	
	MD2Init(&MDContext);
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *MDData = [file readDataOfLength:MDFileReadLength];
		length = [MDData length];
		MD2Update(&MDContext, [MDData bytes], length);
		[pool release];
	} while (length>0);
	MD2Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(MD2Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<MD2Length; i++) {
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
#include "MGMMD2.h"
#include "MGMTypes.h"
#endif

const struct MGMHashDescription MD2Desc = {
	"md2",
    sizeof(struct MD2Context),
    (void(*)(void *))&MD2Init,
	(void(*)(void *, const unsigned char *, unsigned))&MD2Update,
	(void(*)(unsigned char *, void *))&MD2Final,
	MD2Length
};

char *MD2String(const char *string, int length) {
	struct MD2Context MDContext;
	unsigned char MDDigest[MD2Length];
	
	MD2Init(&MDContext);
	MD2Update(&MDContext, (const unsigned char *)string, length);
	MD2Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(MD2Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<MD2Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}
char *MD2File(const char *path) {
	FILE *file = fopen(path, "r");
	if (file==NULL)
		return NULL;
	struct MD2Context MDContext;
	unsigned char MDDigest[MD2Length];
	
	MD2Init(&MDContext);
	int length;
	do {
		unsigned char MDData[MDFileReadLength];
		length = fread(&MDData, 1, MDFileReadLength, file);
		MD2Update(&MDContext, MDData, length);
	} while (length>0);
	MD2Final(MDDigest, &MDContext);
	
	fclose(file);
	
	char *stringBuffer = (char *)malloc(MD2Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<MD2Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}

void MD2Init(struct MD2Context *context) {
	memset(context->X, 0, sizeof(context->X));
	memset(context->checksum, 0, sizeof(context->checksum));
	memset(context->buf, 0, sizeof(context->buf));
	context->curlen = 0;
}

static const unsigned char MD2PI_SUBST[256] = {
	41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
	19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
	76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
	138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
	245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
	39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
	181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
	150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
	112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
	96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
	234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
	129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
	8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
	203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
	31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};

void MD2Update(struct MD2Context *context, const unsigned char *buf, unsigned len) {
	if (buf==NULL)
		return;
	unsigned long n;
	if (context->curlen > sizeof(context->buf))
		return;
	while (len>0) {
		n = MIN(len, (16 - context->curlen));
		memcpy(context->buf + context->curlen, buf, (size_t)n);
		context->curlen += n;
		buf += n;
		len -= n;
		
		if (context->curlen == MD2Length) {
			MD2Transform(context);
			MD2UpdateCheckSum(context);
			context->curlen = 0;
		}
	}
}

void MD2Final(unsigned char digest[MD2Length], struct MD2Context *context) {
	
	if (context->curlen >= sizeof(context->buf))
		return;
	
	/* pad the message */
	unsigned long k = MD2Length - context->curlen;
	for (unsigned long i=context->curlen; i<MD2Length; i++) {
		context->buf[i] = (unsigned char)k;
	}
	
	/* hash and update */
	MD2Transform(context);
	MD2UpdateCheckSum(context);
	
	/* hash checksum */
	memcpy(context->buf, context->checksum, MD2Length);
	MD2Transform(context);
	
	memcpy(digest, context->X, MD2Length);
	
	memset(context, 0, sizeof(struct MD2Context));
}

void MD2UpdateCheckSum(struct MD2Context *context) {
	unsigned char L = context->checksum[15];
	for (int j=0; j<MD2Length; j++) {
		L = (context->checksum[j] ^= MD2PI_SUBST[(int)(context->buf[j] ^ L)] & 255);
	}
}

void MD2Transform(struct MD2Context *context) {
	for (int j=0; j<MD2Length; j++) {
		context->X[16+j] = context->buf[j];
		context->X[32+j] = context->X[j] ^ context->X[16+j];
	}
	
	unsigned char t = 0;
	
	for (int j=0; j<18; j++) {
		for (int k=0; k<48; k++) {
			t = (context->X[k] ^= MD2PI_SUBST[(int)(t & 255)]);
		}
		t = (t + (unsigned char)j) & 255;
	}
}

int MD2Test() {
	static const struct {
		char *msg;
		unsigned char hash[MD2Length];
	} tests[] = {
		{
			"",
			{0x83,0x50,0xe5,0xa3,0xe2,0x4c,0x15,0x3d,0xf2,0x27,0x5c,0x9f,0x80,0x69,0x27,0x73}
		},
		{
			"a",
			{0x32,0xec,0x01,0xec,0x4a,0x6d,0xac,0x72,0xc0,0xab,0x96,0xfb,0x34,0xc0,0xb5,0xd1}
		},
		{
			"message digest",
			{0xab,0x4f,0x49,0x6b,0xfb,0x2a,0x53,0x0b,0x21,0x9f,0xf3,0x30,0x31,0xfe,0x06,0xb0}
		},
		{
			"abcdefghijklmnopqrstuvwxyz",
			{0x4e,0x8d,0xdf,0xf3,0x65,0x02,0x92,0xab,0x5a,0x41,0x08,0xc3,0xaa,0x47,0x94,0x0b}
		},
		{
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			{0xda,0x33,0xde,0xf2,0xa4,0x2d,0xf1,0x39,0x75,0x35,0x28,0x46,0xc3,0x03,0x38,0xcd}
		},
		{
			"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
			{0xd5,0x97,0x6f,0x79,0xd8,0x3d,0x3a,0x0d,0xc9,0x80,0x6c,0x3c,0x66,0xf3,0xef,0xd8}
		},
		{NULL, {0}}
	};
	
	struct MD2Context MDContext;
	unsigned char MDDigest[MD2Length];
	
	for (int i=0; tests[i].msg!=NULL; i++) {
		MD2Init(&MDContext);
		MD2Update(&MDContext, (unsigned char *)tests[i].msg, (unsigned long)strlen(tests[i].msg));
		MD2Final(MDDigest, &MDContext);
		
		if (memcmp(MDDigest, tests[i].hash, MD2Length))
			return 0;
	}
	
	return 1;
}