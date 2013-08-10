//
//  MGMSHA256.h
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 2/24/10.
//  No Copyright Claimed. Public Domain.
//

#ifndef _MD_SHA256
#define _MD_SHA256

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>

extern NSString * const MDNSHA256;

@interface NSString (MGMSHA256)
- (NSString *)SHA256;
- (NSString *)pathSHA256;
@end
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern const struct MGMHashDescription SHA256Desc;

char *SHA256String(const char *string, int length);
char *SHA256File(const char *path);

#define SHA256Length 32
#define SHA256BufferSize 64

struct SHA256Context {
	uint64_t length;
	uint32_t state[8], curlen;
	unsigned char buf[SHA256BufferSize];
};

void SHA256Init(struct SHA256Context *context);
void SHA256Update(struct SHA256Context *context, const unsigned char *buf, unsigned int len);
void SHA256Final(unsigned char digest[SHA256Length], struct SHA256Context *context);
void SHA256Transform(struct SHA256Context *context, unsigned char *buf);
int SHA256Test();

#ifdef __cplusplus
}
#endif

#endif