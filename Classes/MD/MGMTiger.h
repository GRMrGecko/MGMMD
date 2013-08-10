//
//  MGMTiger.h
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 5/31/11.
//  No Copyright Claimed. Public Domain.
//

#ifndef _MD_Tiger
#define _MD_Tiger

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>


extern NSString * const MDNTiger;

@interface NSString (MGMTiger)
- (NSString *)tiger;
- (NSString *)pathTiger;
@end
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern const struct MGMHashDescription tigerDesc;

char *tigerString(const char *string, int length);
char *tigerFile(const char *path);

#define tigerLength 24
#define tigerBufferSize 64

struct tigerContext {
	uint64_t state[3], length;
	unsigned long curlen;
	unsigned char buf[tigerBufferSize];
};

void tigerInit(struct tigerContext *context);
void tigerUpdate(struct tigerContext *context, const unsigned char *buf, unsigned len);
void tigerFinal(unsigned char digest[tigerLength], struct tigerContext *context);
void tigerTransform(struct tigerContext *context, unsigned char *buf);
int tigerTest();

#ifdef __cplusplus
}
#endif

#endif