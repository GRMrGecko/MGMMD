//
//  MGMSHA512.m
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 2/24/10.
//  No Copyright Claimed. Public Domain.
//  C Algorithm created by Tom St Denis <tomstdenis@gmail.com> <http://libtom.org>
//

#ifdef __NEXT_RUNTIME__
#import "MGMSHA512.h"
#import "MGMTypes.h"

NSString * const MDNSHA512 = @"sha512";

@implementation NSString (MGMSHA512)
- (NSString *)SHA512 {
	NSData *MDData = [self dataUsingEncoding:NSUTF8StringEncoding];
	struct SHA512Context MDContext;
	unsigned char MDDigest[SHA512Length];
	
	SHA512Init(&MDContext);
	SHA512Update(&MDContext, [MDData bytes], [MDData length]);
	SHA512Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA512Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA512Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	NSString *hash = [NSString stringWithUTF8String:stringBuffer];
	free(stringBuffer);
	return hash;
}
- (NSString *)pathSHA512 {
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:self];
	if (file==nil)
		return nil;
	struct SHA512Context MDContext;
	unsigned char MDDigest[SHA512Length];
	
	SHA512Init(&MDContext);
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *MDData = [file readDataOfLength:MDFileReadLength];
		length = [MDData length];
		SHA512Update(&MDContext, [MDData bytes], length);
		[pool release];
	} while (length>0);
	SHA512Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA512Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA512Length; i++) {
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
#include "MGMSHA512.h"
#include "MGMTypes.h"
#endif

const struct MGMHashDescription SHA512Desc = {
	"sha512",
    sizeof(struct SHA512Context),
    (void(*)(void *))&SHA512Init,
	(void(*)(void *, const unsigned char *, unsigned))&SHA512Update,
	(void(*)(unsigned char *, void *))&SHA512Final,
	SHA512Length
};

char *SHA512String(const char *string, int length) {
	struct SHA512Context MDContext;
	unsigned char MDDigest[SHA512Length];
	
	SHA512Init(&MDContext);
	SHA512Update(&MDContext, (const unsigned char *)string, length);
	SHA512Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA512Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA512Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}
char *SHA512File(const char *path) {
	FILE *file = fopen(path, "r");
	if (file==NULL)
		return NULL;
	struct SHA512Context MDContext;
	unsigned char MDDigest[SHA512Length];
	
	SHA512Init(&MDContext);
	int length;
	do {
		unsigned char MDData[MDFileReadLength];
		length = fread(&MDData, 1, MDFileReadLength, file);
		SHA512Update(&MDContext, MDData, length);
	} while (length>0);
	SHA512Final(MDDigest, &MDContext);
	
	fclose(file);
	
	char *stringBuffer = (char *)malloc(SHA512Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA512Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}

void SHA512Init(struct SHA512Context *context) {
	context->state[0] = INT64(0x6a09e667f3bcc908);
	context->state[1] = INT64(0xbb67ae8584caa73b);
	context->state[2] = INT64(0x3c6ef372fe94f82b);
	context->state[3] = INT64(0xa54ff53a5f1d36f1);
	context->state[4] = INT64(0x510e527fade682d1);
	context->state[5] = INT64(0x9b05688c2b3e6c1f);
	context->state[6] = INT64(0x1f83d9abfb41bd6b);
	context->state[7] = INT64(0x5be0cd19137e2179);
	
	context->curlen = 0;
	context->length = 0;
}

void SHA512Update(struct SHA512Context *context, const unsigned char *buf, uint64_t len) {
	if (buf==NULL)
		return;
	unsigned long n;
	while (len>0) {
		if (context->curlen == 0 && len>=SHA512BufferSize) {
			SHA512Transform(context, (unsigned char *)buf);
			context->length += SHA512BufferSize * 8;
			buf += SHA512BufferSize;
			len -= SHA512BufferSize;
		} else {
			n = MIN(len, (SHA512BufferSize-context->curlen));
			memcpy(context->buf+context->curlen, buf, (size_t)n);
			context->curlen += n;
			buf += n;
			len -= n;
			if (context->curlen == SHA512BufferSize) {
				SHA512Transform(context, context->buf);
				context->length += 8*SHA512BufferSize;
				context->curlen = 0;
			}
		}
	}
}

void SHA512Final(unsigned char digest[SHA512Length], struct SHA512Context *context) {
	context->length += context->curlen * INT64(8);
	context->buf[context->curlen++] = (unsigned char)0x80;
	
	if (context->curlen > 112) {
		while (context->curlen < 128) {
			context->buf[context->curlen++] = (unsigned char)0;
		}
		SHA512Transform(context, context->buf);
		context->curlen = 0;
	}
	
	while (context->curlen < 120) {
		context->buf[context->curlen++] = (unsigned char)0;
	}
	
	putu64(context->length, context->buf+120);
	SHA512Transform(context, context->buf);
	
	for (int i=0; i<8; i++) {
		putu64(context->state[i], digest+(8*i));
	}
	
	memset(context, 0, sizeof(struct SHA512Context));
}

/* #define SHA512_F1(x, y, z) (x & y | ~x & z) */
#define SHA512_F1(x,y,z) (z ^ (x & (y ^ z)))
#define SHA512_F2(x,y,z) (((x | y) & z) | (x & y))
// SUM0
#define SHA512_F3(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
// SUM1
#define SHA512_F4(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
// OM0
#define SHA512_F5(x) (ROR64(x, 1) ^ ROR64(x, 8) ^ SHR(x, 7))
// OM1
#define SHA512_F6(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ SHR(x, 6))

static const uint64_t SHA512_Key[128] = {
	INT64(0x428a2f98d728ae22), INT64(0x7137449123ef65cd), INT64(0xb5c0fbcfec4d3b2f), INT64(0xe9b5dba58189dbbc),
	INT64(0x3956c25bf348b538), INT64(0x59f111f1b605d019), INT64(0x923f82a4af194f9b), INT64(0xab1c5ed5da6d8118),
	INT64(0xd807aa98a3030242), INT64(0x12835b0145706fbe), INT64(0x243185be4ee4b28c), INT64(0x550c7dc3d5ffb4e2),
	INT64(0x72be5d74f27b896f), INT64(0x80deb1fe3b1696b1), INT64(0x9bdc06a725c71235), INT64(0xc19bf174cf692694),
	INT64(0xe49b69c19ef14ad2), INT64(0xefbe4786384f25e3), INT64(0x0fc19dc68b8cd5b5), INT64(0x240ca1cc77ac9c65),
	INT64(0x2de92c6f592b0275), INT64(0x4a7484aa6ea6e483), INT64(0x5cb0a9dcbd41fbd4), INT64(0x76f988da831153b5),
	INT64(0x983e5152ee66dfab), INT64(0xa831c66d2db43210), INT64(0xb00327c898fb213f), INT64(0xbf597fc7beef0ee4),
	INT64(0xc6e00bf33da88fc2), INT64(0xd5a79147930aa725), INT64(0x06ca6351e003826f), INT64(0x142929670a0e6e70),
	INT64(0x27b70a8546d22ffc), INT64(0x2e1b21385c26c926), INT64(0x4d2c6dfc5ac42aed), INT64(0x53380d139d95b3df),
	INT64(0x650a73548baf63de), INT64(0x766a0abb3c77b2a8), INT64(0x81c2c92e47edaee6), INT64(0x92722c851482353b),
	INT64(0xa2bfe8a14cf10364), INT64(0xa81a664bbc423001), INT64(0xc24b8b70d0f89791), INT64(0xc76c51a30654be30),
	INT64(0xd192e819d6ef5218), INT64(0xd69906245565a910), INT64(0xf40e35855771202a), INT64(0x106aa07032bbd1b8),
	INT64(0x19a4c116b8d2d0c8), INT64(0x1e376c085141ab53), INT64(0x2748774cdf8eeb99), INT64(0x34b0bcb5e19b48a8),
	INT64(0x391c0cb3c5c95a63), INT64(0x4ed8aa4ae3418acb), INT64(0x5b9cca4f7763e373), INT64(0x682e6ff3d6b2b8a3),
	INT64(0x748f82ee5defb2fc), INT64(0x78a5636f43172f60), INT64(0x84c87814a1f0ab72), INT64(0x8cc702081a6439ec),
	INT64(0x90befffa23631e28), INT64(0xa4506cebde82bde9), INT64(0xbef9a3f7b2c67915), INT64(0xc67178f2e372532b),
	INT64(0xca273eceea26619c), INT64(0xd186b8c721c0c207), INT64(0xeada7dd6cde0eb1e), INT64(0xf57d4f7fee6ed178),
	INT64(0x06f067aa72176fba), INT64(0x0a637dc5a2c898a6), INT64(0x113f9804bef90dae), INT64(0x1b710b35131c471b),
	INT64(0x28db77f523047d84), INT64(0x32caab7b40c72493), INT64(0x3c9ebe0a15c9bebc), INT64(0x431d67c49c100d4c),
	INT64(0x4cc5d4becb3e42b6), INT64(0x597f299cfc657e2a), INT64(0x5fcb6fab3ad6faec), INT64(0x6c44198c4a475817)
};

#define SHA512STEP(a, b, c, d, e, f, g, h, s) \
	t1 = h + SHA512_F4(e) + SHA512_F1(e, f, g) + SHA512_Key[s] + x[s]; \
	t2 = SHA512_F3(a) + SHA512_F2(a, b, c); \
	d += t1; \
	h = t1 + t2;

void SHA512Transform(struct SHA512Context *context, unsigned char *buf) {
	uint64_t x[80], t1, t2;
	int i;
	
	uint64_t a = context->state[0];
	uint64_t b = context->state[1];
	uint64_t c = context->state[2];
	uint64_t d = context->state[3];
	uint64_t e = context->state[4];
	uint64_t f = context->state[5];
	uint64_t g = context->state[6];
	uint64_t h = context->state[7];
	
	for (i = 0; i < 16; i++)
		x[i] = getu64(buf+(8*i));
	
	for (i = 16; i < 80; i++)
		x[i] = SHA512_F6(x[i - 2]) + x[i - 7] + SHA512_F5(x[i - 15]) + x[i - 16];
	
	for (int i=0; i<80; i = i + 8) {
		SHA512STEP(a, b, c, d, e, f, g, h, i);
		SHA512STEP(h, a, b, c, d, e, f, g, i + 1);
		SHA512STEP(g, h, a, b, c, d, e, f, i + 2);
		SHA512STEP(f, g, h, a, b, c, d, e, i + 3);
		SHA512STEP(e, f, g, h, a, b, c, d, i + 4);
		SHA512STEP(d, e, f, g, h, a, b, c, i + 5);
		SHA512STEP(c, d, e, f, g, h, a, b, i + 6);
		SHA512STEP(b, c, d, e, f, g, h, a, i + 7);
	}
		
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;
}

int SHA512Test() {
	static const struct {
		char *msg;
		unsigned char hash[SHA512Length];
	} tests[] = {
		{
			"abc",
			{0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f}
		},
		{
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			{0x8e,0x95,0x9b,0x75,0xda,0xe3,0x13,0xda,0x8c,0xf4,0xf7,0x28,0x14,0xfc,0x14,0x3f,0x8f,0x77,0x79,0xc6,0xeb,0x9f,0x7f,0xa1,0x72,0x99,0xae,0xad,0xb6,0x88,0x90,0x18,0x50,0x1d,0x28,0x9e,0x49,0x00,0xf7,0xe4,0x33,0x1b,0x99,0xde,0xc4,0xb5,0x43,0x3a,0xc7,0xd3,0x29,0xee,0xb6,0xdd,0x26,0x54,0x5e,0x96,0xe5,0x5b,0x87,0x4b,0xe9,0x09}
		},
		{NULL, {0}}
	};
	
	struct SHA512Context MDContext;
	unsigned char MDDigest[SHA512Length];
	
	for (int i=0; tests[i].msg!=NULL; i++) {
		SHA512Init(&MDContext);
		SHA512Update(&MDContext, (unsigned char *)tests[i].msg, (unsigned long)strlen(tests[i].msg));
		SHA512Final(MDDigest, &MDContext);
		
		if (memcmp(MDDigest, tests[i].hash, SHA512Length))
			return 0;
	}
	
	return 1;
}