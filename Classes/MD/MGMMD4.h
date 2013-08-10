//
//  MGMMD4.h
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 5/27/11.
//  No Copyright Claimed. Public Domain.
//

#ifndef _MD_MD4
#define _MD_MD4

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>


extern NSString * const MDNMD4;

@interface NSString (MGMMD4)
- (NSString *)MD4;
- (NSString *)pathMD4;
@end
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern const struct MGMHashDescription MD4Desc;

char *MD4String(const char *string, int length);
char *MD4File(const char *path);

#define MD4Length 16
#define MD4BufferSize 64

struct MD4Context {
	uint64_t length;
	uint32_t state[4], curlen;
	unsigned char buf[MD4BufferSize];
};

void MD4Init(struct MD4Context *context);
void MD4Update(struct MD4Context *context, const unsigned char *buf, unsigned len);
void MD4Final(unsigned char digest[MD4Length], struct MD4Context *context);
void MD4Transform(struct MD4Context *context, unsigned char *buf);
int MD4Test();

#ifdef __cplusplus
}
#endif

#endif