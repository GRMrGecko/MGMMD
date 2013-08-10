//
//  MGMSHA384.m
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 2/24/10.
//  No Copyright Claimed. Public Domain.
//  C Algorithm created by Tom St Denis <tomstdenis@gmail.com> <http://libtom.org>
//

#ifdef __NEXT_RUNTIME__
#import "MGMSHA384.h"
#import "MGMTypes.h"

NSString * const MDNSHA384 = @"sha384";

@implementation NSString (MGMSHA384)
- (NSString *)SHA384 {
	NSData *MDData = [self dataUsingEncoding:NSUTF8StringEncoding];
	struct SHA384Context MDContext;
	unsigned char MDDigest[SHA384Length];
	
	SHA384Init(&MDContext);
	SHA384Update(&MDContext, [MDData bytes], [MDData length]);
	SHA384Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA384Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA384Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	NSString *hash = [NSString stringWithUTF8String:stringBuffer];
	free(stringBuffer);
	return hash;
}
- (NSString *)pathSHA384 {
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:self];
	if (file==nil)
		return nil;
	struct SHA384Context MDContext;
	unsigned char MDDigest[SHA384Length];
	
	SHA384Init(&MDContext);
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *MDData = [file readDataOfLength:MDFileReadLength];
		length = [MDData length];
		SHA384Update(&MDContext, [MDData bytes], length);
		[pool release];
	} while (length>0);
	SHA384Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA384Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA384Length; i++) {
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
#include "MGMSHA384.h"
#include "MGMTypes.h"
#endif

const struct MGMHashDescription SHA384Desc = {
	"sha384",
    sizeof(struct SHA384Context),
    (void(*)(void *))&SHA384Init,
	(void(*)(void *, const unsigned char *, unsigned))&SHA384Update,
	(void(*)(unsigned char *, void *))&SHA384Final,
	SHA384Length
};

char *SHA384String(const char *string, int length) {
	struct SHA384Context MDContext;
	unsigned char MDDigest[SHA384Length];
	
	SHA384Init(&MDContext);
	SHA384Update(&MDContext, (const unsigned char *)string, length);
	SHA384Final(MDDigest, &MDContext);
	
	char *stringBuffer = (char *)malloc(SHA384Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA384Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}
char *SHA384File(const char *path) {
	FILE *file = fopen(path, "r");
	if (file==NULL)
		return NULL;
	struct SHA384Context MDContext;
	unsigned char MDDigest[SHA384Length];
	
	SHA384Init(&MDContext);
	int length;
	do {
		unsigned char MDData[MDFileReadLength];
		length = fread(&MDData, 1, MDFileReadLength, file);
		SHA384Update(&MDContext, MDData, length);
	} while (length>0);
	SHA384Final(MDDigest, &MDContext);
	
	fclose(file);
	
	char *stringBuffer = (char *)malloc(SHA384Length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<SHA384Length; i++) {
		*hexBuffer++ = hexdigits[(MDDigest[i] >> 4) & 0xF];
		*hexBuffer++ = hexdigits[MDDigest[i] & 0xF];
	}
	*hexBuffer = '\0';
	
	return stringBuffer;
}

void SHA384Init(struct SHA384Context *context) {
	context->state[0] = INT64(0xcbbb9d5dc1059ed8);
	context->state[1] = INT64(0x629a292a367cd507);
	context->state[2] = INT64(0x9159015a3070dd17);
	context->state[3] = INT64(0x152fecd8f70e5939);
	context->state[4] = INT64(0x67332667ffc00b31);
	context->state[5] = INT64(0x8eb44a8768581511);
	context->state[6] = INT64(0xdb0c2e0d64f98fa7);
	context->state[7] = INT64(0x47b5481dbefa4fa4);
	
	context->curlen = 0;
	context->length = 0;
}

void SHA384Update(struct SHA384Context *context, const unsigned char *buf, uint64_t len) {
	if (buf==NULL)
		return;
	
	unsigned long n;
	while (len>0) {
		if (context->curlen == 0 && len>=SHA384BufferSize) {
			SHA384Transform(context, (unsigned char *)buf);
			context->length += SHA384BufferSize * 8;
			buf += SHA384BufferSize;
			len -= SHA384BufferSize;
		} else {
			n = MIN(len, (SHA384BufferSize-context->curlen));
			memcpy(context->buf+context->curlen, buf, (size_t)n);
			context->curlen += n;
			buf += n;
			len -= n;
			if (context->curlen == SHA384BufferSize) {
				SHA384Transform(context, context->buf);
				context->length += 8*SHA384BufferSize;
				context->curlen = 0;
			}
		}
	}
}

void SHA384Final(unsigned char digest[SHA384Length], struct SHA384Context *context) {
	context->length += context->curlen * INT64(8);
	context->buf[context->curlen++] = (unsigned char)0x80;
	
	if (context->curlen > 112) {
		while (context->curlen < 128) {
			context->buf[context->curlen++] = (unsigned char)0;
		}
		SHA384Transform(context, context->buf);
		context->curlen = 0;
	}
	
	while (context->curlen < 120) {
		context->buf[context->curlen++] = (unsigned char)0;
	}
	
	putu64(context->length, context->buf+120);
	SHA384Transform(context, context->buf);
	
	for (int i=0; i<8; i++) {
		putu64(context->state[i], digest+(8*i));
	}
	
	memset(context, 0, sizeof(struct SHA384Context));
}

/* #define SHA384_F1(x, y, z) (x & y | ~x & z) */
#define SHA384_F1(x,y,z) (z ^ (x & (y ^ z)))
#define SHA384_F2(x,y,z) (((x | y) & z) | (x & y))
// SUM0
#define SHA384_F3(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
// SUM1
#define SHA384_F4(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
// OM0
#define SHA384_F5(x) (ROR64(x, 1) ^ ROR64(x, 8) ^ SHR(x, 7))
// OM1
#define SHA384_F6(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ SHR(x, 6))

static const uint64_t SHA384_Key[128] = {
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

#define SHA384STEP(a, b, c, d, e, f, g, h, s) \
	t1 = h + SHA384_F4(e) + SHA384_F1(e, f, g) + SHA384_Key[s] + x[s]; \
	t2 = SHA384_F3(a) + SHA384_F2(a, b, c); \
	d += t1; \
	h = t1 + t2;

void SHA384Transform(struct SHA384Context *context, unsigned char *buf) {
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
		x[i] = SHA384_F6(x[i - 2]) + x[i - 7] + SHA384_F5(x[i - 15]) + x[i - 16];
	
	for (int i=0; i<80; i = i + 8) {
		SHA384STEP(a, b, c, d, e, f, g, h, i);
		SHA384STEP(h, a, b, c, d, e, f, g, i + 1);
		SHA384STEP(g, h, a, b, c, d, e, f, i + 2);
		SHA384STEP(f, g, h, a, b, c, d, e, i + 3);
		SHA384STEP(e, f, g, h, a, b, c, d, i + 4);
		SHA384STEP(d, e, f, g, h, a, b, c, i + 5);
		SHA384STEP(c, d, e, f, g, h, a, b, i + 6);
		SHA384STEP(b, c, d, e, f, g, h, a, i + 7);
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

int SHA384Test() {
	static const struct {
		char *msg;
		unsigned char hash[SHA384Length];
	} tests[] = {
		{
			"abc",
			{0xcb,0x00,0x75,0x3f,0x45,0xa3,0x5e,0x8b,0xb5,0xa0,0x3d,0x69,0x9a,0xc6,0x50,0x07,0x27,0x2c,0x32,0xab,0x0e,0xde,0xd1,0x63,0x1a,0x8b,0x60,0x5a,0x43,0xff,0x5b,0xed,0x80,0x86,0x07,0x2b,0xa1,0xe7,0xcc,0x23,0x58,0xba,0xec,0xa1,0x34,0xc8,0x25,0xa7}
		},
		{
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			{0x09,0x33,0x0c,0x33,0xf7,0x11,0x47,0xe8,0x3d,0x19,0x2f,0xc7,0x82,0xcd,0x1b,0x47,0x53,0x11,0x1b,0x17,0x3b,0x3b,0x05,0xd2,0x2f,0xa0,0x80,0x86,0xe3,0xb0,0xf7,0x12,0xfc,0xc7,0xc7,0x1a,0x55,0x7e,0x2d,0xb9,0x66,0xc3,0xe9,0xfa,0x91,0x74,0x60,0x39}
		},
		{NULL, {0}}
	};
	
	struct SHA384Context MDContext;
	unsigned char MDDigest[SHA384Length];
	
	for (int i=0; tests[i].msg!=NULL; i++) {
		SHA384Init(&MDContext);
		SHA384Update(&MDContext, (unsigned char *)tests[i].msg, (unsigned long)strlen(tests[i].msg));
		SHA384Final(MDDigest, &MDContext);
		
		if (memcmp(MDDigest, tests[i].hash, SHA384Length))
			return 0;
	}
	
	return 1;
}