//
//  MGMMD.m
//  MGMMD
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 8/23/10.
//  No Copyright Claimed. Public Domain.
//

#import "MGMMD.h"

@implementation MGMMD
+ (NSString *)stringHash:(NSString *)theString usingAlgorithm:(NSString *)theAlgorithm {
	MGMMD *md = [self mdWithAlgorithm:theAlgorithm];
	[md updateWithString:theString];
	return [md finalHash];
}
+ (NSString *)fileHash:(NSString *)theFile usingAlgorithm:(NSString *)theAlgorithm {
	MGMMD *md = [self mdWithAlgorithm:theAlgorithm];
	[md updateWithFile:theFile];
	return [md finalHash];
}
+ (NSString *)dataHash:(NSData *)theData usingAlgorithm:(NSString *)theAlgorithm {
	MGMMD *md = [self mdWithAlgorithm:theAlgorithm];
	[md updateWithData:theData];
	return [md finalHash];
}

+ (NSArray *)supportedAlgorithms {
	NSMutableArray *algorithms = [NSMutableArray array];
#ifdef _MD_MD2
	[algorithms addObject:MDNMD2];
#endif
#ifdef _MD_MD5
	[algorithms addObject:MDNMD5];
#endif
#ifdef _MD_SHA1
	[algorithms addObject:MDNSHA1];
#endif
#ifdef _MD_SHA224
	[algorithms addObject:MDNSHA224];
#endif
#ifdef _MD_SHA256
	[algorithms addObject:MDNSHA256];
#endif
#ifdef _MD_SHA384
	[algorithms addObject:MDNSHA384];
#endif
#ifdef _MD_SHA512
	[algorithms addObject:MDNSHA512];
#endif
	return algorithms;
}

+ (id)mdWithAlgorithm:(NSString *)theAlgorithm {
	return [[self alloc] initWithAlgorithm:theAlgorithm];
}
- (id)initWithAlgorithm:(NSString *)theAlgorithm {
	if (self = [super init]) {
		theAlgorithm = [theAlgorithm lowercaseString];
		algorithm = MDNULL;
		context = NULL;
#ifdef _MD_MD2
		if ([theAlgorithm isEqual:MDNMD2]) {
			algorithm = MDMD2;
			description = MD2Desc;
		}
#endif
#ifdef _MD_MD5
		if ([theAlgorithm isEqual:MDNMD5]) {
			algorithm = MDMD5;
			description = MD5Desc;
		}
#endif
#ifdef _MD_SHA1
		if ([theAlgorithm isEqual:MDNSHA1]) {
			algorithm = MDSHA1;
			description = SHA1Desc;
		}
#endif
#ifdef _MD_SHA224
		if ([theAlgorithm isEqual:MDNSHA224]) {
			algorithm = MDSHA224;
			description = SHA224Desc;
		}
#endif
#ifdef _MD_SHA256
		if ([theAlgorithm isEqual:MDNSHA256]) {
			algorithm = MDSHA256;
			description = SHA256Desc;
		}
#endif
#ifdef _MD_SHA384
		if ([theAlgorithm isEqual:MDNSHA384]) {
			algorithm = MDSHA384;
			description = SHA384Desc;
		}
#endif
#ifdef _MD_SHA512
		if ([theAlgorithm isEqual:MDNSHA512]) {
			algorithm = MDSHA512;
			description = SHA512Desc;
		}
#endif
		if (algorithm==MDNULL) {
			NSLog(@"The alorithm \"%@\" is not supported.", theAlgorithm);
			[self release];
			self = nil;
		} else {
			context = malloc(description.contextSize);
			description.init(context);
		}
	}
	return self;
}
- (void)dealloc {
	if (context!=NULL)
		free(context);
	if (finalData!=nil)
		[finalData release];
	[super dealloc];
}

- (BOOL)updateWithString:(NSString *)theString {
	return [self updateWithData:[theString dataUsingEncoding:NSUTF8StringEncoding]];
}
- (BOOL)updateWithFile:(NSString *)theFile {
	if (finalData!=nil) return NO;
	NSFileHandle *file = [NSFileHandle fileHandleForReadingAtPath:theFile];
	if (file==nil)
		return NO;
	int length;
	do {
		NSAutoreleasePool *pool = [NSAutoreleasePool new];
		NSData *MDData = [file readDataOfLength:MDFileReadLength];
		length = [MDData length];
		[self updateWithData:MDData];
		[pool release];
	} while (length>0);
	return YES;
}
- (BOOL)updateWithData:(NSData *)theData {
	return [self updateWithBytes:[theData bytes] length:[theData length]];
}
- (BOOL)updateWithBytes:(const char *)theBytes length:(int)theLength {
	if (finalData!=nil) return NO;
	description.update(context, (const unsigned char *)theBytes, theLength);
	return YES;
}

- (NSData *)finalData {
	if (finalData==nil) {
		unsigned char MDDigest[description.length];
		description.final(MDDigest, context);
		finalData = [[NSData dataWithBytes:MDDigest length:description.length] retain];
	}
	return finalData;
}
- (const char *)finalBytes {
	return [[self finalData] bytes];
}
- (const char *)finalStringHash {
	const size_t length = [[self finalData] length];
	const char *bytes = [[self finalData] bytes];
	char *stringBuffer = (char *)malloc(length * 2 + 1);
	char *hexBuffer = stringBuffer;
	
	for (int i=0; i<length; i++) {
		*hexBuffer++ = hexdigits[(*bytes >> 4) & 0xF];
		*hexBuffer++ = hexdigits[*bytes & 0xF];
		bytes++;
	}
	*hexBuffer = '\0';
	return [[NSData dataWithBytesNoCopy:stringBuffer length:description.length*2] bytes];
}
- (NSString *)finalHash {
	return [NSString stringWithUTF8String:[self finalStringHash]];
}
@end