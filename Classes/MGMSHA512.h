//
//  MGMSHA512.h
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 2/24/10.
//  No Copyright Claimed. Public Domain.
//

#ifndef _MD_SHA512
#define _MD_SHA512

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>

extern NSString * const MDNSHA512;

@interface NSString (MGMSHA512)
- (NSString *)SHA512;
- (NSString *)pathSHA512;
@end
#endif

#ifdef __cplusplus
extern "C" {
#endif

char *SHA512String(const char *string, int length);
char *SHA512File(const char *path);

#define SHA512Length 64
#define SHA512BufferSize 8

struct SHA512Context {
    uint64_t buf[SHA512BufferSize];
    uint64_t bits[2];
    unsigned char in[128];	
};

void SHA512Init(struct SHA512Context *context);
void SHA512Update(struct SHA512Context *context, const unsigned char *buf, uint64_t len);
void SHA512Final(unsigned char digest[SHA512Length], struct SHA512Context *context);
void SHA512Transform(uint64_t buf[SHA512BufferSize], const unsigned char inraw[80]);

#ifdef __cplusplus
}
#endif

#endif