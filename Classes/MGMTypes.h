//
//  MGMTypes.h
//
//  Created by Mr. Gecko on 2/24/10.
//  No Copyright Claimed. Public Domain.
//

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>
#endif

struct MGMHashDescription {
	char *name;
	int contextSize;
	void (*init)(void *);
	void (*update)(void *, const unsigned char *, unsigned);
	void (*final)(unsigned char *, void *);
	int length;
};

#if !defined(MIN)
	#define MIN(A,B)	({ __typeof__(A) __a = (A); __typeof__(B) __b = (B); __a < __b ? __a : __b; })
#endif

#define INT32(n) n ## UL
#define INT64(n) n ## ULL

#define ROR32(x, b) ((x >> b) | (x << (32 - b)))
#define ROR64(x, b) ((x >> b) | (x << (64 - b)))
#define ROL32(x, b) ((x << b) | (x >> (32 - b)))
#define ROL64(x, b) ((x << b) | (x >> (64 - b)))
#define SHR(x, b) (x >> b)

#define byte(x, n) (((x) >> (8 * (n))) & 255)

#define MDFileReadLength 1048576

static const char hexdigits[] = "0123456789abcdef";

static const unsigned char MDPadding[128] =
{
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static uint32_t getu32(const uint8_t *addr) {
	return ((uint32_t)addr[0] << 24)
	| ((uint32_t)addr[1] << 16)
	| ((uint32_t)addr[2] << 8)
	| ((uint32_t)addr[3]);
}
static void putu32(uint32_t data, uint8_t *addr) {
	addr[0] = (uint8_t)(data >> 24);
	addr[1] = (uint8_t)(data >> 16);
	addr[2] = (uint8_t)(data >> 8);
	addr[3] = (uint8_t)data;
}

static uint64_t getu64(const uint8_t *addr) {
	return ((uint64_t)addr[0] << 56)
	| ((uint64_t)addr[1] << 48)
	| ((uint64_t)addr[2] << 40)
	| ((uint64_t)addr[3] << 32)
	| ((uint64_t)addr[4] << 24)
	| ((uint64_t)addr[5] << 16)
	| ((uint64_t)addr[6] << 8)
	| ((uint64_t)addr[7]);
}
static void putu64(uint64_t data, uint8_t *addr) {
	addr[0] = (uint8_t)(data >> 56);
	addr[1] = (uint8_t)(data >> 48);
	addr[2] = (uint8_t)(data >> 40);
	addr[3] = (uint8_t)(data >> 32);
	addr[4] = (uint8_t)(data >> 24);
	addr[5] = (uint8_t)(data >> 16);
	addr[6] = (uint8_t)(data >> 8);
	addr[7] = (uint8_t)data;
}

static uint32_t getu32l(const uint8_t *addr) {
	return ((uint32_t)addr[0])
	| ((uint32_t)addr[1] << 8)
	| ((uint32_t)addr[2] << 16)
	| ((uint32_t)addr[3] << 24);
}
static void putu32l(uint32_t data, uint8_t *addr) {
	addr[0] = (uint8_t)data;
	addr[1] = (uint8_t)(data >> 8);
	addr[2] = (uint8_t)(data >> 16);
	addr[3] = (uint8_t)(data >> 24);
}

static uint64_t getu64l(const uint8_t *addr) {
	return ((uint64_t)addr[0])
	| ((uint64_t)addr[1] << 8)
	| ((uint64_t)addr[2] << 16)
	| ((uint64_t)addr[3] << 24)
	| ((uint64_t)addr[4] << 32)
	| ((uint64_t)addr[5] << 40)
	| ((uint64_t)addr[6] << 48)
	| ((uint64_t)addr[7] << 56);
}
static void putu64l(uint64_t data, uint8_t *addr) {
	addr[0] = (uint8_t)data;
	addr[1] = (uint8_t)(data >> 8);
	addr[2] = (uint8_t)(data >> 16);
	addr[3] = (uint8_t)(data >> 24);
	addr[4] = (uint8_t)(data >> 32);
	addr[5] = (uint8_t)(data >> 40);
	addr[6] = (uint8_t)(data >> 48);
	addr[7] = (uint8_t)(data >> 56);
}