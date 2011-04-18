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

char *SHA224String(const char *string, int length);
char *SHA224File(const char *path);

#define SHA224Length 28
#define SHA224BufferSize 8

struct SHA224Context {
    uint32_t buf[SHA224BufferSize];
    uint32_t bits[2];
    unsigned char in[64];	
};

void SHA224Init(struct SHA224Context *context);
void SHA224Update(struct SHA224Context *context, const unsigned char *buf, unsigned int len);
void SHA224Final(unsigned char digest[SHA224Length], struct SHA224Context *context);
void SHA224Transform(uint32_t buf[SHA224BufferSize], const unsigned char inraw[64]);

#ifdef __cplusplus
}
#endif

#endif