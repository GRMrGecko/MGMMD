//
//  MGMRMD320.h
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 5/31/11.
//  No Copyright Claimed. Public Domain.
//

#ifndef _MD_RMD320
#define _MD_RMD320

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>


extern NSString * const MDNRMD320;

@interface NSString (MGMRMD320)
- (NSString *)RMD320;
- (NSString *)pathRMD320;
@end
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern const struct MGMHashDescription RMD320Desc;

char *RMD320String(const char *string, int length);
char *RMD320File(const char *path);

#define RMD320Length 40
#define RMD320BufferSize 64

struct RMD320Context {
	uint64_t length;
	unsigned char buf[RMD320BufferSize];
	uint32_t curlen, state[10];
};

void RMD320Init(struct RMD320Context *context);
void RMD320Update(struct RMD320Context *context, const unsigned char *buf, unsigned len);
void RMD320Final(unsigned char digest[RMD320Length], struct RMD320Context *context);
void RMD320Transform(struct RMD320Context *context, unsigned char *buf);
int RMD320Test();

#ifdef __cplusplus
}
#endif

#endif