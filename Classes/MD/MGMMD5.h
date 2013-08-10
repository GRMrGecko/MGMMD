//
//  MGMMD5.h
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 1/6/10.
//  No Copyright Claimed. Public Domain.
//

#ifndef _MD_MD5
#define _MD_MD5

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>


extern NSString * const MDNMD5;

@interface NSString (MGMMD5)
- (NSString *)MD5;
- (NSString *)pathMD5;
@end
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern const struct MGMHashDescription MD5Desc;

char *MD5String(const char *string, int length);
char *MD5File(const char *path);

#define MD5Length 16
#define MD5BufferSize 64

struct MD5Context {
	uint32_t length;
	uint32_t state[4], curlen;
	unsigned char buf[MD5BufferSize];
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, const unsigned char *buf, unsigned len);
void MD5Final(unsigned char digest[MD5Length], struct MD5Context *context);
void MD5Transform(struct MD5Context *context, unsigned char *buf);
int MD5Test();

#ifdef __cplusplus
}
#endif

#endif