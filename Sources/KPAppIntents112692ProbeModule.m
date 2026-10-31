#import "KPAppIntents112692ProbeModule.h"

#import <Intents/Intents.h>
#import <errno.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

@interface KPAppIntents112692ProbeModule ()
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;
@end

@implementation KPAppIntents112692ProbeModule

static NSString *KPAppIntentsBPFControl(void) {
    int descriptor = open("/dev/bpf0", O_RDONLY | O_NONBLOCK);
    int error = descriptor < 0 ? errno : 0;
    if (descriptor >= 0) close(descriptor);
    return [NSString stringWithFormat:@"fd=%d errno=%d (%s)", descriptor, error, strerror(error)];
}

static void KPAppIntentsCollectScopes(id object, NSMutableArray<NSString *> *entries,
                                      NSUInteger *nonNullCount, NSString *path, NSUInteger depth) {
    if (depth > 64 || !object) return;
    if ([object isKindOfClass:NSDictionary.class]) {
        NSDictionary *dictionary = object;
        for (id key in dictionary) {
            id value = dictionary[key];
            NSString *childPath = [path stringByAppendingFormat:@"/%@", key];
            if ([key isKindOfClass:NSString.class] &&
                [key rangeOfString:@"securityscope" options:NSCaseInsensitiveSearch].location != NSNotFound) {
                if (value == NSNull.null) {
                    [entries addObject:[NSString stringWithFormat:@"%@=<null>", childPath]];
                } else {
                    (*nonNullCount)++;
                    [entries addObject:[NSString stringWithFormat:@"%@=<%@>", childPath, [value class]]];
                }
            }
            KPAppIntentsCollectScopes(value, entries, nonNullCount, childPath, depth + 1);
        }
    } else if ([object isKindOfClass:NSArray.class] || [object isKindOfClass:NSSet.class]) {
        NSUInteger index = 0;
        for (id value in object) {
            NSString *childPath = [path stringByAppendingFormat:@"/%lu", (unsigned long)index++];
            KPAppIntentsCollectScopes(value, entries, nonNullCount, childPath, depth + 1);
        }
    }
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _identifier = @"appintents112692.probe";
        _title = @"App Intents 112692 INFile";
        _subtitle = @"Safe temp-file archive/security-scope oracle with /dev/bpf control";
        _icon = @"doc.badge.gearshape";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== CVE-2026-112692 INFile security-scope parser probe ===\n"];
    [report appendString:@"Target: iOS 27.0.1. Only one temporary file in Documents; no sensitive or system file is read.\n"];
    [report appendFormat:@"BPF control before: %s\n", KPAppIntentsBPFControl().UTF8String];

    NSString *documents = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *path = [documents stringByAppendingPathComponent:@"appintents112692-benign.bin"];
    NSData *original = [@"APPINTENTS112692-BENIGN-TEMP-FILE-NOT-SENSITIVE" dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error = nil;
    if (![NSFileManager.defaultManager createDirectoryAtPath:documents
                                 withIntermediateDirectories:YES
                                                  attributes:nil
                                                       error:&error] ||
        ![original writeToFile:path options:NSDataWritingAtomic error:&error]) {
        [report appendFormat:@"Temporary file setup failed: %@\n", error.localizedDescription];
        return report;
    }

    @try {
        NSURL *url = [NSURL fileURLWithPath:path];
        INFile *file = [INFile fileWithFileURL:url filename:url.lastPathComponent typeIdentifier:nil];
        if (!file) {
            [report appendString:@"INFile construction failed; parser verdict is inconclusive.\n"];
            return report;
        }
        NSData *archive = [NSKeyedArchiver archivedDataWithRootObject:file
                                               requiringSecureCoding:YES
                                                               error:&error];
        if (!archive) {
            [report appendFormat:@"INFile archive failed: %@\n", error.localizedDescription];
            return report;
        }
        [report appendFormat:@"Archive bytes: %lu\n", (unsigned long)archive.length];

        id propertyList = [NSPropertyListSerialization propertyListWithData:archive
                                                                    options:NSPropertyListImmutable
                                                                     format:NULL
                                                                      error:&error];
        NSMutableArray<NSString *> *scopeEntries = [NSMutableArray array];
        NSUInteger nonNullScopes = 0;
        if (propertyList) {
            KPAppIntentsCollectScopes(propertyList, scopeEntries, &nonNullScopes, @"$", 0);
        }
        [report appendFormat:@"Archive scope entries: %@; non-null scope count=%lu\n",
         scopeEntries.count ? [scopeEntries componentsJoinedByString:@", "] : @"none",
         (unsigned long)nonNullScopes];

        error = nil;
        INFile *decoded = [NSKeyedUnarchiver unarchivedObjectOfClass:INFile.class
                                                            fromData:archive
                                                               error:&error];
        NSURL *decodedURL = decoded.fileURL;
        NSData *decodedData = decoded.data;
        BOOL dataMatches = [decodedData isEqualToData:original];
        [report appendFormat:@"Decoded object=%@ fileURL=%@ data_length=%lu data_matches=%s error=%@\n",
         decoded ? @"present" : @"nil", decodedURL ?: @"nil",
         (unsigned long)decodedData.length, dataMatches ? "yes" : "no",
         error.localizedDescription ?: @"none"];

        if (nonNullScopes != 0) {
            [report appendString:@"PARSER ORACLE INCONCLUSIVE: archive contains a non-null security scope; missing-scope acceptance was not tested.\n"];
        } else if (decoded && decodedURL && dataMatches) {
            [report appendString:@"PARSER ORACLE POSITIVE: archive without a non-null security scope retained fileURL and returned the benign file bytes. This confirms parser-level capability acceptance, not an end-to-end sensitive-file exploit.\n"];
        } else {
            [report appendString:@"PARSER ORACLE NEGATIVE: missing-scope file URL was not usable for reading the benign file. This does not identify another App Intents path.\n"];
        }
    } @catch (NSException *exception) {
        [report appendFormat:@"Objective-C exception; verdict is inconclusive: %@\n", exception];
    } @finally {
        [NSFileManager.defaultManager removeItemAtPath:path error:nil];
    }

    [report appendFormat:@"BPF control after: %s\n", KPAppIntentsBPFControl().UTF8String];
    [report appendString:@"Primitive assessment: INFile archive/security-scope handling only. No arbitrary service invocation, kernel address, or kernel R/W is used. BPF success would require a separate capability check; parser acceptance alone does not grant it.\n"];
    return report;
}

@end
