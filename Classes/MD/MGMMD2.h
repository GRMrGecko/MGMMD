//
//  MGMMD2.h
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 5/27/11.
//  No Copyright Claimed. Public Domain.
//

#ifndef _MD_MD2
#define _MD_MD2

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>


extern NSString * const MDNMD2;

@interface NSString (MGMMD2)
- (NSString *)MD2;
- (NSString *)pathMD2;
@end
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern const struct MGMHashDescription MD2Desc;

char *MD2String(const char *string, int length);
char *MD2File(const char *path);

#define MD2Length 16

struct MD2Context {
	unsigned char checksum[MD2Length], X[48], buf[MD2Length];
	unsigned long curlen;
};

void MD2Init(struct MD2Context *context);
void MD2Update(struct MD2Context *context, const unsigned char *buf, unsigned len);
void MD2Final(unsigned char digest[MD2Length], struct MD2Context *context);
void MD2UpdateCheckSum(struct MD2Context *context);
void MD2Transform(struct MD2Context *context);
int MD2Test();

#ifdef __cplusplus
}
#endif

#endif