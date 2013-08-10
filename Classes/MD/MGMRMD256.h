//
//  MGMRMD256.h
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 5/31/11.
//  No Copyright Claimed. Public Domain.
//

#ifndef _MD_RMD256
#define _MD_RMD256

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>


extern NSString * const MDNRMD256;

@interface NSString (MGMRMD256)
- (NSString *)RMD256;
- (NSString *)pathRMD256;
@end
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern const struct MGMHashDescription RMD256Desc;

char *RMD256String(const char *string, int length);
char *RMD256File(const char *path);

#define RMD256Length 32
#define RMD256BufferSize 64

struct RMD256Context {
	uint64_t length;
	unsigned char buf[RMD256BufferSize];
	uint32_t curlen, state[8];
};

void RMD256Init(struct RMD256Context *context);
void RMD256Update(struct RMD256Context *context, const unsigned char *buf, unsigned len);
void RMD256Final(unsigned char digest[RMD256Length], struct RMD256Context *context);
void RMD256Transform(struct RMD256Context *context, unsigned char *buf);
int RMD256Test();

#ifdef __cplusplus
}
#endif

#endif