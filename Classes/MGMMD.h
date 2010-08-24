//
//  MGMMD.h
//  MGMMD
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 8/23/10.
//  No Copyright Claimed. Public Domain.
//

#import <Foundation/Foundation.h>
#import "MGMMD5.h"
#import "MGMSHA1.h"
#import "MGMSHA224.h"
#import "MGMSHA256.h"
#import "MGMSHA384.h"
#import "MGMSHA512.h"

typedef enum {
	MDNULL = -1,
	MDMD5 = 0,
	MDSHA1 = 1,
	MDSHA224 = 2,
	MDSHA256 = 3,
	MDSHA384 = 4,
	MDSHA512 = 5,
} MGMMDType;

@interface MGMMD : NSObject {
	MGMMDType algorithm;
	int algorithmLength;
	void *context;
	NSData *finalData;
}
+ (NSString *)stringHash:(NSString *)theString usingAlgorithm:(NSString *)theAlgorithm;
+ (NSString *)fileHash:(NSString *)theFile usingAlgorithm:(NSString *)theAlgorithm;
+ (NSString *)dataHash:(NSData *)theData usingAlgorithm:(NSString *)theAlgorithm;

+ (NSArray *)supportedAlgorithms;

+ (id)mdWithAlgorithm:(NSString *)theAlgorithm;
- (id)initWithAlgorithm:(NSString *)theAlgorithm;

- (BOOL)updateWithString:(NSString *)theString;
- (BOOL)updateWithFile:(NSString *)theFile;
- (BOOL)updateWithData:(NSData *)theData;
- (BOOL)updateWithBytes:(const char *)theBytes length:(int)theLength;

- (NSData *)finalData;
- (const char *)finalBytes;
- (const char *)finalStringHash;
- (NSString *)finalHash;
@end