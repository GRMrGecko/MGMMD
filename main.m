//
//  main.m
//
//  Created by Mr. Gecko <GRMrGecko@gmail.com> on 2/23/10.
//  No Copyright Claimed. Public Domain.
//

#import <Foundation/Foundation.h>
#import "MGMMD5.h"
#import "MGMSHA1.h"
#import "MGMSHA224.h"
#import "MGMSHA256.h"
#import "MGMSHA384.h"
#import "MGMSHA512.h"
#import "MGMMD.h"
#import "MGMBase64.h"

int main (int argc, const char * argv[]) {
    NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	
	NSString *correct = @"It is correct.";
	NSString *incorrect = @"Something is wrong, it is incorrect.";
	
	NSString *MDString = @"Test String";
	NSString *hash;
	NSLog(@"Obj-C MD of %@", MDString);
	hash = [MDString MD5];
	NSLog(@"MD5: %@ %@", hash, ([hash isEqual:@"bd08ba3c982eaad768602536fb8e1184"] ? correct : incorrect));
	hash = [MDString SHA1];
	NSLog(@"SHA1: %@ %@", hash, ([hash isEqual:@"a5103f9c0b7d5ff69ddc38607c74e53d4ac120f2"] ? correct : incorrect));
	hash = [MDString SHA224];
	NSLog(@"SHA224: %@ %@", hash, ([hash isEqual:@"a4342acc574edb5032b8b0f0fc0edeb5e4d977ca8c87a60214c62c69"] ? correct : incorrect));
	hash = [MDString SHA256];
	NSLog(@"SHA256: %@ %@", hash, ([hash isEqual:@"30c6ff7a44f7035af933babaea771bf177fc38f06482ad06434cbcc04de7ac14"] ? correct : incorrect));
	hash = [MDString SHA384];
	NSLog(@"SHA384: %@ %@", hash, ([hash isEqual:@"d76a1b44f76d7cfe3f1cc244078de956a23a0b34adea1321ce67b188929719750979db66f793abdf4f87481ceb1cf931"] ? correct : incorrect));
	hash = [MDString SHA512];
	NSLog(@"SHA512: %@ %@", hash, ([hash isEqual:@"924bae629fbad5096a0a68929d5314d5b10b00108c5f9387c98d4c6cfe527a3cb6bba4303ed769c1feb38699800012b50c41e638bf0b47854f78344a3ac442a8"] ? correct : incorrect));
	
	NSString *MDFile = [[NSBundle mainBundle] executablePath];
	//Change this to the path of the test file.
	MDFile = [[[[MDFile stringByDeletingLastPathComponent] stringByDeletingLastPathComponent] stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"MDTest.bin"];
	NSLog(@"Obj-C File MD of %@", MDFile);
	hash = [MDFile pathMD5];
	NSLog(@"MD5: %@ %@", hash, ([hash isEqual:@"db393181e59d5b50c72bc582c505ab6f"] ? correct : incorrect));
	hash = [MDFile pathSHA1];
	NSLog(@"SHA1: %@ %@", hash, ([hash isEqual:@"deeed48d8e6b2c2cec878d12f241729a4158029a"] ? correct : incorrect));
	hash = [MDFile pathSHA224];
	NSLog(@"SHA224: %@ %@", hash, ([hash isEqual:@"4005eb91d5ce3a9555d359a401557ae1977546cfb246975d230674e1"] ? correct : incorrect));
	hash = [MDFile pathSHA256];
	NSLog(@"SHA256: %@ %@", hash, ([hash isEqual:@"db1c95c8679dc505dd71dccd1c5f9df86fe9dcb5d63f1689835fa6f24e062828"] ? correct : incorrect));
	hash = [MDFile pathSHA384];
	NSLog(@"SHA384: %@ %@", hash, ([hash isEqual:@"a6a1008686fcbfd55198038966fdbe6c0cc3faab7e9efc6c6394cee86601ff33ca1d54d2824bb577361aaa6aac4f8599"] ? correct : incorrect));
	hash = [MDFile pathSHA512];
	NSLog(@"SHA512: %@ %@", hash, ([hash isEqual:@"6801c0d3e7fdf43218e5f0986ee3e8dc33928a57470cffbde7ebdc23b454fb06024d5b0cba2646eaf58d8f53bb32eaff0d6a0ad7d97e8b4f607a181bd1bf7936"] ? correct : incorrect));
	
	const char *MDChar = "0123456789abcdefghijklmnopqrstuvwxyz";
	char *hashChar;
	NSLog(@"C MD of %s", MDChar);
	hashChar = MD5String(MDChar, strlen(MDChar));
	NSLog(@"MD5: %s %@", hashChar, (strcmp(hashChar, "e9b1713db620f1e3a14b6812de523f4b") ? incorrect : correct));
	free(hashChar);
	hashChar = SHA1String(MDChar, strlen(MDChar));
	NSLog(@"SHA1: %s %@", hashChar, (strcmp(hashChar, "a26704c04fc5f10db5aab58468035531cc542485") ? incorrect : correct));
	free(hashChar);
	hashChar = SHA224String(MDChar, strlen(MDChar));
	NSLog(@"SHA224: %s %@", hashChar, (strcmp(hashChar, "e6e4a6be069cc9bead8b6050856d2b26da6b3f7efa0951e5fb3a54dd") ? incorrect : correct));
	free(hashChar);
	hashChar = SHA256String(MDChar, strlen(MDChar));
	NSLog(@"SHA256: %s %@", hashChar, (strcmp(hashChar, "74e7e5bb9d22d6db26bf76946d40fff3ea9f0346b884fd0694920fccfad15e33") ? incorrect : correct));
	free(hashChar);
	hashChar = SHA384String(MDChar, strlen(MDChar));
	NSLog(@"SHA384: %s %@", hashChar, (strcmp(hashChar, "ce6d4ea5442bc6c830bea1942d4860db9f7b96f0e9d2c3073ffe47a0e1166d95612d840ff15e5efdd23c1f273096da32") ? incorrect : correct));
	free(hashChar);
	hashChar = SHA512String(MDChar, strlen(MDChar));
	NSLog(@"SHA512: %s %@", hashChar, (strcmp(hashChar, "95cadc34aa46b9fdef432f62fe5bad8d9f475bfbecf797d5802bb5f2937a85d93ce4857a6262b03834c01c610d74cd1215f9a466dc6ad3dd15078e3309a03a6d") ? incorrect : correct));
	free(hashChar);
	
	const char *MDCharFile = [MDFile UTF8String];
	NSLog(@"C File MD of %s", MDCharFile);
	hashChar = MD5File(MDCharFile);
	if (hashChar!=NULL) {
		NSLog(@"MD5: %s %@", hashChar, (strcmp(hashChar, "db393181e59d5b50c72bc582c505ab6f") ? incorrect : correct));
		free(hashChar);
	}
	hashChar = SHA1File(MDCharFile);
	if (hashChar!=NULL) {
		NSLog(@"SHA1: %s %@", hashChar, (strcmp(hashChar, "deeed48d8e6b2c2cec878d12f241729a4158029a") ? incorrect : correct));
		free(hashChar);
	}
	hashChar = SHA224File(MDCharFile);
	if (hashChar!=NULL) {
		NSLog(@"SHA224: %s %@", hashChar, (strcmp(hashChar, "4005eb91d5ce3a9555d359a401557ae1977546cfb246975d230674e1") ? incorrect : correct));
		free(hashChar);
	}
	hashChar = SHA256File(MDCharFile);
	if (hashChar!=NULL) {
		NSLog(@"SHA256: %s %@", hashChar, (strcmp(hashChar, "db1c95c8679dc505dd71dccd1c5f9df86fe9dcb5d63f1689835fa6f24e062828") ? incorrect : correct));
		free(hashChar);
	}
	hashChar = SHA384File(MDCharFile);
	if (hashChar!=NULL) {
		NSLog(@"SHA384: %s %@", hashChar, (strcmp(hashChar, "a6a1008686fcbfd55198038966fdbe6c0cc3faab7e9efc6c6394cee86601ff33ca1d54d2824bb577361aaa6aac4f8599") ? incorrect : correct));
		free(hashChar);
	}
	hashChar = SHA512File(MDCharFile);
	if (hashChar!=NULL) {
		NSLog(@"SHA512: %s %@", hashChar, (strcmp(hashChar, "6801c0d3e7fdf43218e5f0986ee3e8dc33928a57470cffbde7ebdc23b454fb06024d5b0cba2646eaf58d8f53bb32eaff0d6a0ad7d97e8b4f607a181bd1bf7936") ? incorrect : correct));
		free(hashChar);
	}
	
	MGMMD *md;
	NSLog(@"File MGMMD of %@", MDFile);
	md = [MGMMD mdWithAlgorithm:@"MD5"];
	[md updateWithFile:MDFile];
	NSLog(@"MD5: %@ %@", [md finalHash], ([[md finalHash] isEqual:@"db393181e59d5b50c72bc582c505ab6f"] ? correct : incorrect));
	md = [MGMMD mdWithAlgorithm:@"SHA1"];
	[md updateWithFile:MDFile];
	NSLog(@"SHA1: %@ %@", [md finalHash], ([[md finalHash] isEqual:@"deeed48d8e6b2c2cec878d12f241729a4158029a"] ? correct : incorrect));
	md = [MGMMD mdWithAlgorithm:@"SHA224"];
	[md updateWithFile:MDFile];
	NSLog(@"SHA224: %@ %@", [md finalHash], ([[md finalHash] isEqual:@"4005eb91d5ce3a9555d359a401557ae1977546cfb246975d230674e1"] ? correct : incorrect));
	md = [MGMMD mdWithAlgorithm:@"SHA256"];
	[md updateWithFile:MDFile];
	NSLog(@"SHA256: %@ %@", [md finalHash], ([[md finalHash] isEqual:@"db1c95c8679dc505dd71dccd1c5f9df86fe9dcb5d63f1689835fa6f24e062828"] ? correct : incorrect));
	md = [MGMMD mdWithAlgorithm:@"SHA384"];
	[md updateWithFile:MDFile];
	NSLog(@"SHA384: %@ %@", [md finalHash], ([[md finalHash] isEqual:@"a6a1008686fcbfd55198038966fdbe6c0cc3faab7e9efc6c6394cee86601ff33ca1d54d2824bb577361aaa6aac4f8599"] ? correct : incorrect));
	md = [MGMMD mdWithAlgorithm:@"SHA512"];
	[md updateWithFile:MDFile];
	NSLog(@"SHA512: %@ %@", [md finalHash], ([[md finalHash] isEqual:@"6801c0d3e7fdf43218e5f0986ee3e8dc33928a57470cffbde7ebdc23b454fb06024d5b0cba2646eaf58d8f53bb32eaff0d6a0ad7d97e8b4f607a181bd1bf7936"] ? correct : incorrect));
	
	MDString = @"asdjl32j4lkjDS;:J;iaslkhjouh3hjsad89y45ioausf89sahuxzyLHuiyf8yHuyhiuash";
	NSLog(@"MGMMD of %@", MDString);
	md = [MGMMD mdWithAlgorithm:@"MD5"];
	[md updateWithString:MDString];
	NSLog(@"MD5: %@ %@", [md finalHash], ([[md finalHash] isEqual:@"c204f2099b3c64057437889e40d6f1ba"] ? correct : incorrect));
	md = [MGMMD mdWithAlgorithm:@"SHA1"];
	[md updateWithString:MDString];
	NSLog(@"SHA1: %@ %@", [md finalHash], ([[md finalHash] isEqual:@"038e54bbf286cd1628145253a7afcdb63742db24"] ? correct : incorrect));
	md = [MGMMD mdWithAlgorithm:@"SHA224"];
	[md updateWithString:MDString];
	NSLog(@"SHA224: %@ %@", [md finalHash], ([[md finalHash] isEqual:@"aa0bf85004330e18856482c1aec134f51d91ac2a1c87cb2f11dc1283"] ? correct : incorrect));
	md = [MGMMD mdWithAlgorithm:@"SHA256"];
	[md updateWithString:MDString];
	NSLog(@"SHA256: %@ %@", [md finalHash], ([[md finalHash] isEqual:@"4b25724a05afaab26147179fdcfa7f7a81db0464d78072614a57e738b5bf1b0f"] ? correct : incorrect));
	md = [MGMMD mdWithAlgorithm:@"SHA384"];
	[md updateWithString:MDString];
	NSLog(@"SHA384: %@ %@", [md finalHash], ([[md finalHash] isEqual:@"665fc58df2e22ceafc373b0b951bd100a9e1f60fb68b4758ad88e32e5e5cbc02771c1a7cde672e7c5c6756860ce88a50"] ? correct : incorrect));
	md = [MGMMD mdWithAlgorithm:@"SHA512"];
	[md updateWithString:MDString];
	NSLog(@"SHA512: %@ %@", [md finalHash], ([[md finalHash] isEqual:@"1c58a65cf90dbeb31f8e4f196ce278936d70507cffea9682a9cbf79da9b046aebca9ed08c6f94d8e9f80cc4df0d5ddc65072cdb8a9b65d9e89b0fbf9bb0700ef"] ? correct : incorrect));
	
	NSString *cryptString = @"Test String";
	NSString *crypt = [cryptString encodeBase64];
	NSLog(@"Base64 Encrypt: %@ %@", crypt, ([crypt isEqual:@"VGVzdCBTdHJpbmc="] ? correct : incorrect));
	crypt = [crypt decodeBase64];
	NSLog(@"Base64 Decrypt: %@ %@", crypt, ([crypt isEqual:cryptString] ? correct : incorrect));
	
    [pool drain];
    return 0;
}
