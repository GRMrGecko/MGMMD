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

char *SHA1String(const char *string, int length);
char *SHA1File(const char *path);

#define SHA1Length 20
#define SHA1BufferSize 5

struct SHA1Context {
	uint32_t buf[SHA1BufferSize];
	uint32_t bits[2];
	unsigned char in[64];
};

void SHA1Init(struct SHA1Context *context);
void SHA1Update(struct SHA1Context *context, const unsigned char *buf, unsigned len);
void SHA1Final(unsigned char digest[SHA1Length], struct SHA1Context *context);
void SHA1Transform(uint32_t buf[SHA1BufferSize], const unsigned char inraw[64]);
	
#ifdef __cplusplus
}
#endif

#endif