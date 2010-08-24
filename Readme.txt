I (Mr. Gecko) went around the internet and found public domain implementations of some hash algorithms and decided to clean them up, make them look alike, and work alike so it's easy to use just by replacing the name with what algorithm you want. (NAMEInit, NAMEUpdate, Ect…)
Because I'm a cocoa developer, I also added some cocoa apis such as MGMMD for accessing the algorithms via objective-c, and NSString/NSData add-on methods.

Hashing Algorithms Support so far.
MD5
SHA1
SHA224
SHA256
SHA384
SHA512

MGMMD Methods.
+ (NSString *)stringHash:(NSString *)theString usingAlgorithm:(NSString *)theAlgorithm; - Hash a string with the given algorithm.
+ (NSString *)fileHash:(NSString *)theFile usingAlgorithm:(NSString *)theAlgorithm; - Hash a file with the given algorithm.
+ (NSString *)dataHash:(NSData *)theData usingAlgorithm:(NSString *)theAlgorithm; - Hash a NSData with the given algorithm.

+ (NSArray *)supportedAlgorithms; - Tells you the supported algorithms.

+ (id)mdWithAlgorithm:(NSString *)theAlgorithm; - Creates an instance of MGMMD with the algorithm given.
- (id)initWithAlgorithm:(NSString *)theAlgorithm;  - Initializes an instance of MGMMD with the algorithm given.

- (BOOL)updateWithString:(NSString *)theString; - Updates the context with a string.
- (BOOL)updateWithFile:(NSString *)theFile; - Updates the context with a file.
- (BOOL)updateWithData:(NSData *)theData; - Updates the context with a NSData.
- (BOOL)updateWithBytes:(const char *)theBytes length:(int)theLength; - Updates the context with a c string.

- (NSData *)finalData; - Returns the final digest as NSData.
- (const char *)finalBytes; - Returns the final digest as a c string.
- (const char *)finalStringHash; - Returns the final hash as a c string.
- (NSString *)finalHash; - Returns the final hash as a string.

Note: Once you call final*, it'll no longer be able to be updated. There is a MDNNAME (Replace NAME with algorithm) string that you are able to use to specify the algorithm.

C Functions. (Replace NAME with the name of the hash you want.)
char *NAMEString(const char *string, int length); - Returns the hash of a c string as a c string. (Note: You have to free this.)
char *NAMEFile(const char *path); - Returns the hash of a file as a cstring.

Raw access c functions.
void NAMEInit(struct NAMEContext *context); - Initializes a context with the start data of the algorithm.
void NAMEUpdate(struct NAMEContext *context, const unsigned char *buf, unsigned len); - Updates the context with a given c string.
void NAMEFinal(unsigned char digest[NAMELength], struct NAMEContext *context); - Gets the final digest of the algorithm. (Note: The digest array length must be the length of the algorithm's digest. The length is specified in the defines as NAMELength.)


Adding more algorithms.
If you want to help me out and add more algorithms, please do, but keep these guide lines in mind.
1. DO NOT STEAL CODE FROM AN OPEN SOURCE (That is not Public Domain) OR CLOSED SOURCE PROJECT UNLESS YOU OWN THAT PROJECT AND HAVE THE RIGHT TO MAKE THE CODE PUBLIC DOMAIN.
2. ONLY PUBLIC DOMAIN CODE WILL BE ALLOWED AS WE DO NOT WANT COMPANIES/PEOPLE/ALIENS SAYING THAT WE STOLE THEIR CODE.
3. You must mention who created the c algorithm as they'll appreciate it.
4. You must follow my API rules or email me so I can make it follow the rules.
5. Email the .m and .h files and I'll add it to the project and mention you in the file with the information your want or no information if you don't want to be mentioned.

Licenses.
There is no licenses whatsoever, you may copy, redistribute, modify, sell, or hand it off to aliens. You are here by granted full power of the hash algorithms.

Warranties.
Obviously there is no warranties just like every other software out there. I am just forced to say this just incase there are people out there who don't know this.

Compiling for C and C++.
I have not tested this, but if you change the extension of the algorithm's .m file to .c or .cpp, you should be able to just compile with your projects and access the function part of the files. I added a if for the compiler to check if it's objective-c or c/c++ so it should just work out of the box.

Compiling Framework for Mac.
Open MGMMD.xcodeproj in Xcode and change the configuration to release, target to MGMMD Framework, and compile. 

Compiling Static Library for iPhone/iPod/iPad.
Open MGMMD.xcodeproj in Xcode and change the configuration to release, target to MGMMD Touch, and compile.