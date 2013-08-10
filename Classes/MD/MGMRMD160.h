//
//  MGMRMD160.h
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 5/31/11.
//  No Copyright Claimed. Public Domain.
//

#ifndef _MD_RMD160
#define _MD_RMD160

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>


extern NSString * const MDNRMD160;

@interface NSString (MGMRMD160)
- (NSString *)RMD160;
- (NSString *)pathRMD160;
@end
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern const struct MGMHashDescription RMD160Desc;

char *RMD160String(const char *string, int length);
char *RMD160File(const char *path);

#define RMD160Length 20
#define RMD160BufferSize 64

struct RMD160Context {
	uint64_t length;
	unsigned char buf[RMD160BufferSize];
	uint32_t curlen, state[5];
};

void RMD160Init(struct RMD160Context *context);
void RMD160Update(struct RMD160Context *context, const unsigned char *buf, unsigned len);
void RMD160Final(unsigned char digest[RMD160Length], struct RMD160Context *context);
void RMD160Transform(struct RMD160Context *context, unsigned char *buf);
int RMD160Test();

#ifdef __cplusplus
}
#endif

#endif