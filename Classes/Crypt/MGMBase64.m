//
//  MGMSHA512.m
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 2/24/10.
//  No Copyright Claimed. Public Domain.
//  C Algorithm from libb64 <http://sourceforge.net/projects/libb64>
//

#ifdef __NEXT_RUNTIME__
#import "MGMBase64.h"
#import "MGMTypes.h"

NSString * const cryptBase64 = @"base64";

@implementation NSString (MGMBase64)
- (NSString *)encodeBase64 {
	NSData *cryptData = [self dataUsingEncoding:NSUTF8StringEncoding];
	struct base64EncodeState cryptContext;
	char *cryptBuffer = malloc(base64BufferSize);
	unsigned long length = [cryptData length];
	NSRange bufferRange = NSMakeRange(0, base64BufferSize/2);
	NSMutableString *result = [NSMutableString string];
	NSCharacterSet *lines = [NSCharacterSet newlineCharacterSet];
	
	base64InitEncodeState(&cryptContext);
	while (length>0) {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		if (length<bufferRange.length)
			bufferRange.length = length;
		char *data = malloc(bufferRange.length);
		[cryptData getBytes:data range:bufferRange];
		int len = base64EncodeBlock(data, bufferRange.length, cryptBuffer, &cryptContext);
		NSString *dataString = [[[[NSString alloc] initWithBytes:cryptBuffer length:len encoding:NSUTF8StringEncoding] autorelease] stringByTrimmingCharactersInSet:lines];
		[result appendString:dataString];
		free(data);
		length -= bufferRange.length;
		bufferRange.location += bufferRange.length;
		[pool drain];
	}
	int len = base64EncodeBlockEnd(cryptBuffer, &cryptContext);
	NSString *dataString = [[[[NSString alloc] initWithBytes:cryptBuffer length:len encoding:NSUTF8StringEncoding] autorelease] stringByTrimmingCharactersInSet:lines];
	[result appendString:dataString];
	free(cryptBuffer);
	return result;
}
- (NSString *)decodeBase64 {
	NSData *cryptData = [self dataUsingEncoding:NSUTF8StringEncoding];
	struct base64DecodeState cryptContext;
	char *cryptBuffer = malloc(base64BufferSize);
	unsigned long length = [cryptData length];
	NSRange bufferRange = NSMakeRange(0, base64BufferSize/2);
	NSMutableString *result = [NSMutableString string];
	
	base64InitDecodeState(&cryptContext);
	while (length>0) {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		if (length<bufferRange.length)
			bufferRange.length = length;
		char *data = malloc(bufferRange.length);
		[cryptData getBytes:data range:bufferRange];
		int len = base64DecodeBlock(data, bufferRange.length, cryptBuffer, &cryptContext);
		NSString *dataString = [[[NSString alloc] initWithBytes:cryptBuffer length:len encoding:NSUTF8StringEncoding] autorelease];
		[result appendString:dataString];
		free(data);
		length -= bufferRange.length;
		bufferRange.location += bufferRange.length;
		[pool drain];
	}
	free(cryptBuffer);
	return result;
}
- (NSString *)pathEncodeBase64 {
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:self];
	struct base64EncodeState cryptContext;
	char *cryptBuffer = malloc(base64BufferSize);
	NSMutableString *result = [NSMutableString string];
	NSCharacterSet *lines = [NSCharacterSet newlineCharacterSet];
	
	base64InitEncodeState(&cryptContext);
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *cryptData = [file readDataOfLength:base64BufferSize/2];
		length = [cryptData length];
		int len = base64EncodeBlock([cryptData bytes], [cryptData length], cryptBuffer, &cryptContext);
		NSString *dataString = [[[[NSString alloc] initWithBytes:cryptBuffer length:len encoding:NSUTF8StringEncoding] autorelease] stringByTrimmingCharactersInSet:lines];
		[result appendString:dataString];
		[pool release];
	} while (length>0);
	int len = base64EncodeBlockEnd(cryptBuffer, &cryptContext);
	NSString *dataString = [[[[NSString alloc] initWithBytes:cryptBuffer length:len encoding:NSUTF8StringEncoding] autorelease] stringByTrimmingCharactersInSet:lines];
	[result appendString:dataString];
	free(cryptBuffer);
	return result;
}
- (NSString *)pathDecodeBase64 {
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:self];
	struct base64DecodeState cryptContext;
	char *cryptBuffer = malloc(base64BufferSize);
	NSMutableString *result = [NSMutableString string];
	
	base64InitDecodeState(&cryptContext);
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *cryptData = [file readDataOfLength:base64BufferSize/2];
		length = [cryptData length];
		int len = base64DecodeBlock([cryptData bytes], [cryptData length], cryptBuffer, &cryptContext);
		NSString *dataString = [[[NSString alloc] initWithBytes:cryptBuffer length:len encoding:NSUTF8StringEncoding] autorelease];
		[result appendString:dataString];
		[pool release];
	} while (length>0);
	free(cryptBuffer);
	return result;
}
@end
#else
#include <stdio.h>
#include <string.h>
#include "MGMMD5.h"
#include "MGMTypes.h"
#endif

const int base64CharsPerLine = 72;

void base64InitEncodeState(struct base64EncodeState *state_in) {
	state_in->step = step_a;
	state_in->result = 0;
	state_in->stepcount = 0;
}

char base64EncodeValue(char value_in) {
	static const char *base64Encoding = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	if (value_in > 63) return '=';
	return base64Encoding[(int)value_in];
}

int base64EncodeBlock(const char *plaintext_in, int length_in, char *code_out, struct base64EncodeState *state_in) {
	const char *plainchar = plaintext_in;
	const char *const plaintextend = plaintext_in + length_in;
	char *codechar = code_out;
	char result;
	char fragment;
	
	result = state_in->result;
	
	switch (state_in->step) {
		while (1) {
		case step_a:
			if (plainchar==plaintextend) {
				state_in->result = result;
				state_in->step = step_a;
				return codechar - code_out;
			}
			fragment = *plainchar++;
			result = (fragment & 0x0fc) >> 2;
			*codechar++ = base64EncodeValue(result);
			result = (fragment & 0x003) << 4;
		case step_b:
			if (plainchar==plaintextend) {
				state_in->result = result;
				state_in->step = step_b;
				return codechar - code_out;
			}
			fragment = *plainchar++;
			result |= (fragment & 0x0f0) >> 4;
			*codechar++ = base64EncodeValue(result);
			result = (fragment & 0x00f) << 2;
		case step_c:
			if (plainchar==plaintextend) {
				state_in->result = result;
				state_in->step = step_c;
				return codechar - code_out;
			}
			fragment = *plainchar++;
			result |= (fragment & 0x0c0) >> 6;
			*codechar++ = base64EncodeValue(result);
			result  = (fragment & 0x03f) >> 0;
			*codechar++ = base64EncodeValue(result);
			
			++(state_in->stepcount);
			if (state_in->stepcount == base64CharsPerLine/4) {
				*codechar++ = '\n';
				state_in->stepcount = 0;
			}
		default:
			break;
		}
	}
	return codechar - code_out;
}

int base64EncodeBlockEnd(char *code_out, struct base64EncodeState *state_in) {
	char *codechar = code_out;
	
	switch (state_in->step) {
		case step_b:
			*codechar++ = base64EncodeValue(state_in->result);
			*codechar++ = '=';
			*codechar++ = '=';
			break;
		case step_c:
			*codechar++ = base64EncodeValue(state_in->result);
			*codechar++ = '=';
			break;
		case step_a:
			break;
		default:
			break;
	}
	*codechar++ = '\n';
	
	return codechar - code_out;
}

void base64InitDecodeState(struct base64DecodeState *state_in) {
	state_in->step = step_a;
	state_in->plainchar = 0;
}

int base64DecodeValue(char value_in) {
	static const char decoding[] = {62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51};
	static const char decoding_size = sizeof(decoding);
	value_in -= 43;
	if (value_in < 0 || value_in > decoding_size) return -1;
	return decoding[(int)value_in];
}

int base64DecodeBlock(const char *code_in, const int length_in, char *plaintext_out, struct base64DecodeState *state_in) {
	const char *codechar = code_in;
	char *plainchar = plaintext_out;
	char fragment;
	
	*plainchar = state_in->plainchar;
	
	switch (state_in->step) {
			while (1) {
			case step_a:
				do {
					if (codechar == code_in+length_in) {
						state_in->step = step_a;
						state_in->plainchar = *plainchar;
						return plainchar - plaintext_out;
					}
					fragment = (char)base64DecodeValue(*codechar++);
				} while (fragment < 0);
				*plainchar = (fragment & 0x03f) << 2;
			case step_b:
				do {
					if (codechar == code_in+length_in) {
						state_in->step = step_b;
						state_in->plainchar = *plainchar;
						return plainchar - plaintext_out;
					}
					fragment = (char)base64DecodeValue(*codechar++);
				} while (fragment < 0);
				*plainchar++ |= (fragment & 0x030) >> 4;
				*plainchar = (fragment & 0x00f) << 4;
			case step_c:
				do {
					if (codechar == code_in+length_in) {
						state_in->step = step_c;
						state_in->plainchar = *plainchar;
						return plainchar - plaintext_out;
					}
					fragment = (char)base64DecodeValue(*codechar++);
				} while (fragment < 0);
				*plainchar++ |= (fragment & 0x03c) >> 2;
				*plainchar = (fragment & 0x003) << 6;
			case step_d:
				do {
					if (codechar == code_in+length_in) {
						state_in->step = step_d;
						state_in->plainchar = *plainchar;
						return plainchar - plaintext_out;
					}
					fragment = (char)base64DecodeValue(*codechar++);
				} while (fragment < 0);
				*plainchar++ |= (fragment & 0x03f);
			}
	}
	return plainchar - plaintext_out;
}