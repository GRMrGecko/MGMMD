//
//  MGMSHA1.h
//  MGMMD
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 8/23/10.
//  No Copyright Claimed. Public Domain.
//

#ifndef _MD_SHA1
#define _MD_SHA1

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>

extern NSString * const MDNSHA1;

@interface NSString (MGMSHA1)
- (NSString *)SHA1;
- (NSString *)pathSHA1;
@end
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern const struct MGMHashDescription SHA1Desc;

char *SHA1String(const char *string, int length);
char *SHA1File(const char *path);

#define SHA1Length 20
#define SHA1BufferSize 64

struct SHA1Context {
	u_int64_t length;
	u_int32_t state[5], curlen;
	unsigned char buf[SHA1BufferSize];
};

void SHA1Init(struct SHA1Context *context);
void SHA1Update(struct SHA1Context *context, const unsigned char *buf, unsigned len);
void SHA1Final(unsigned char digest[SHA1Length], struct SHA1Context *context);
void SHA1Transform(struct SHA1Context *context, unsigned char *buf);
int SHA1Test();
	
#ifdef __cplusplus
}
#endif

#endif