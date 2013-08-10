//
//  MGMRMD128.h
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 5/31/11.
//  No Copyright Claimed. Public Domain.
//

#ifndef _MD_RMD128
#define _MD_RMD128

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>


extern NSString * const MDNRMD128;

@interface NSString (MGMRMD128)
- (NSString *)RMD128;
- (NSString *)pathRMD128;
@end
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern const struct MGMHashDescription RMD128Desc;

char *RMD128String(const char *string, int length);
char *RMD128File(const char *path);

#define RMD128Length 16
#define RMD128BufferSize 64

struct RMD128Context {
	uint64_t length;
	unsigned char buf[RMD128BufferSize];
	uint32_t curlen, state[4];
};

void RMD128Init(struct RMD128Context *context);
void RMD128Update(struct RMD128Context *context, const unsigned char *buf, unsigned len);
void RMD128Final(unsigned char digest[RMD128Length], struct RMD128Context *context);
void RMD128Transform(struct RMD128Context *context, unsigned char *buf);
int RMD128Test();

#ifdef __cplusplus
}
#endif

#endif