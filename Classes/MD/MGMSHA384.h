//
//  MGMSHA384.h
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 2/24/10.
//  No Copyright Claimed. Public Domain.
//

#ifndef _MD_SHA384
#define _MD_SHA384

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>

extern NSString * const MDNSHA384;

@interface NSString (MGMSHA384)
- (NSString *)SHA384;
- (NSString *)pathSHA384;
@end
#endif

#ifdef __cplusplus
extern "C" {
#endif

char *SHA384String(const char *string, int length);
char *SHA384File(const char *path);

#define SHA384Length 48
#define SHA384BufferSize 8

struct SHA384Context {
    uint64_t buf[SHA384BufferSize];
    uint64_t bits[2];
    unsigned char in[128];	
};

void SHA384Init(struct SHA384Context *context);
void SHA384Update(struct SHA384Context *context, const unsigned char *buf, uint64_t len);
void SHA384Final(unsigned char digest[SHA384Length], struct SHA384Context *context);
void SHA384Transform(uint64_t buf[SHA384BufferSize], const unsigned char inraw[80]);

#ifdef __cplusplus
}
#endif

#endif