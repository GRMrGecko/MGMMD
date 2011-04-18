//
//  MGMSHA512.h
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 2/24/10.
//  No Copyright Claimed. Public Domain.
//

#ifndef _MD_BASE64
#define _MD_BASE64

#ifdef __NEXT_RUNTIME__
#import <Foundation/Foundation.h>

extern NSString * const cryptBase64;

@interface NSString (MGMBase64)
- (NSString *)encodeBase64;
- (NSString *)decodeBase64;
- (NSString *)pathEncodeBase64;
- (NSString *)pathDecodeBase64;
@end
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define base64BufferSize 6

typedef enum {
	step_a, step_b, step_c, step_d
} base64Step;
	
struct base64EncodeState {
	base64Step step;
	char result;
	int stepcount;
};

void base64InitEncodeState(struct base64EncodeState *state_in);
char base64EncodeValue(char value_in);
int base64EncodeBlock(const char *plaintext_in, int length_in, char *code_out, struct base64EncodeState *state_in);
int base64EncodeBlockEnd(char *code_out, struct base64EncodeState *state_in);

struct base64DecodeState {
	base64Step step;
	char plainchar;
};

void base64InitDecodeState(struct base64DecodeState *state_in);
int base64DecodeValue(char value_in);
int base64DecodeBlock(const char *code_in, const int length_in, char *plaintext_out, struct base64DecodeState *state_in);

#ifdef __cplusplus
}
#endif

#endif