//
//  MGMSHA224.h
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 2/24/10.
//  No Copyright Claimed. Public Domain.
//

#ifndef _MD_SHA224
#define _MD_SHA224

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>

extern NSString * const MDNSHA224;

@interface NSString (MGMSHA224)
- (NSString *)SHA224;
- (NSString *)pathSHA224;
@end
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern const struct MGMHashDescription SHA224Desc;

char *SHA224String(const char *string, int length);
char *SHA224File(const char *path);

#define SHA224Length 28
#define SHA224BufferSize 64

struct SHA224Context {
	uint64_t length;
	uint32_t state[8], curlen;
	unsigned char buf[SHA224BufferSize];
};

void SHA224Init(struct SHA224Context *context);
void SHA224Update(struct SHA224Context *context, const unsigned char *buf, unsigned int len);
void SHA224Final(unsigned char digest[SHA224Length], struct SHA224Context *context);
void SHA224Transform(struct SHA224Context *context, unsigned char *buf);
int SHA224Test();

#ifdef __cplusplus
}
#endif

#endif