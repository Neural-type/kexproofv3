#import "KPDOVIRPUProbeModule.h"

#import "KPDOVIRPUVariants.h"
#import "KPLog.h"

#import <CommonCrypto/CommonDigest.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <signal.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

#ifndef KP_DOVIRPU_ENABLE_ARMED
#define KP_DOVIRPU_ENABLE_ARMED 0
#endif

#define KP_RPU_SIGNAL_COUNT 6

static uint32_t KPDOVIRPUCallVersion(CFDataRef data, BOOL *available) {
    static void *handle;
    static uint32_t (*function)(CFDataRef);
    if (!function) {
        handle = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia", RTLD_LAZY);
        if (handle) function = (uint32_t (*)(CFDataRef))dlsym(handle, "CMGetDMVersionLevelFromRPU");
    }
    if (!function) {
        if (available) *available = NO;
        return 0;
    }
    if (available) *available = YES;
    return function(data);
}

static const int KPDOVIRPUSignals[KP_RPU_SIGNAL_COUNT] = {SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE, SIGTRAP};
static volatile sig_atomic_t gRPUActive;
static int gRPUJournalFD = -1;
static const char *gRPUIdentifier;
static size_t gRPUIdentifierLength;

@interface KPDOVIRPUProbeModule ()
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;
@end

@implementation KPDOVIRPUProbeModule

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        _identifier = armed ? @"dovirpu112688.array-overflow" : @"dovirpu112688.info";
        _title = armed ? @"DOVI RPU ARMED" : @"DOVI RPU Info";
        _subtitle = armed
            ? @"A10/B2/C6 · one-over to eight-over · resume after crash"
            : @"Baseline RPU parse · no overrun blocks";
        _icon = armed ? @"exclamationmark.triangle" : @"doc.text.magnifyingglass";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

static NSError *KPDOVIRPUError(NSString *description) {
    return [NSError errorWithDomain:@"KPDOVIRPU" code:1 userInfo:@{NSLocalizedDescriptionKey: description}];
}

static NSString *KPDOVIRPUSHA256(NSData *data) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger index = 0; index < sizeof(digest); index++) {
        [result appendFormat:@"%02x", digest[index]];
    }
    return result;
}

static NSDictionary *KPDOVIRPUInspect(const KPDOVIRPUVariant *variant, NSError **error) {
    NSURL *URL = [NSBundle.mainBundle URLForResource:[NSString stringWithUTF8String:variant->resource]
                                     withExtension:@"bin"];
    if (!URL) {
        if (error) *error = KPDOVIRPUError([NSString stringWithFormat:@"Missing %s.bin", variant->resource]);
        return nil;
    }
    NSData *data = [NSData dataWithContentsOfURL:URL options:0 error:error];
    if (!data) return nil;
    if (data.length < 7 || ((const uint8_t *)data.bytes)[0] != 0x19) {
        if (error) *error = KPDOVIRPUError(@"RPU type/header mismatch");
        return nil;
    }
    NSString *sha = KPDOVIRPUSHA256(data);
    BOOL matched = [sha isEqualToString:[NSString stringWithUTF8String:variant->sha256]];
    if (!matched && error) *error = KPDOVIRPUError(@"SHA-256 does not match the deterministic RPU resource");
    return @{@"data": data, @"size": @(data.length), @"sha256": sha, @"matched": @(matched)};
}

static BOOL KPDOVIRPUWriteFD(int fd, const void *bytes, size_t length) {
    const uint8_t *position = bytes;
    while (length) {
        ssize_t written = write(fd, position, length);
        if (written < 0) {
            if (errno == EINTR) continue;
            return NO;
        }
        if (!written) return NO;
        position += written;
        length -= (size_t)written;
    }
    return YES;
}

static BOOL KPDOVIRPUJournalLine(int fd, NSString *line, BOOL synchronize) {
    NSString *terminated = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    NSData *data = [terminated dataUsingEncoding:NSUTF8StringEncoding];
    if (!KPDOVIRPUWriteFD(fd, data.bytes, data.length)) return NO;
    return !synchronize || fsync(fd) == 0;
}

static NSString *KPDOVIRPUJournalPath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproofv3-dovi-rpu-armed-journal.log"];
}

static int KPDOVIRPUOpenJournal(NSError **error) {
    NSString *documents = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    if (![[NSFileManager defaultManager] createDirectoryAtPath:documents
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:error]) {
        return -1;
    }
    int fd = open(KPDOVIRPUJournalPath().fileSystemRepresentation,
                  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0 && error) {
        *error = KPDOVIRPUError([NSString stringWithFormat:@"open %@: %s", KPDOVIRPUJournalPath(), strerror(errno)]);
    }
    return fd;
}

static NSString *KPDOVIRPUJournalTail(void) {
    NSString *body = [NSString stringWithContentsOfFile:KPDOVIRPUJournalPath() encoding:NSUTF8StringEncoding error:nil];
    if (!body.length) return @"<empty>";
    NSArray<NSString *> *lines = [body componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet];
    NSMutableArray<NSString *> *events = [NSMutableArray array];
    for (NSString *line in lines) {
        if ([line hasPrefix:@"BEGIN "] || [line hasPrefix:@"END "] || [line hasPrefix:@"CRASH "]) {
            [events addObject:line];
        }
    }
    NSUInteger start = events.count > 12 ? events.count - 12 : 0;
    return [[events subarrayWithRange:NSMakeRange(start, events.count - start)] componentsJoinedByString:@"\n"];
}

static BOOL KPDOVIRPUCompleted(const KPDOVIRPUVariant *variant) {
    NSString *body = [NSString stringWithContentsOfFile:KPDOVIRPUJournalPath() encoding:NSUTF8StringEncoding error:nil];
    if (!body.length) return NO;
    NSString *identifier = [NSString stringWithUTF8String:variant->identifier];
    NSString *end = [NSString stringWithFormat:@"END id=%@ ", identifier];
    NSString *crash = [NSString stringWithFormat:@"CRASH id=%@ ", identifier];
    return [body containsString:end] || [body containsString:crash];
}

static NSUInteger KPDOVIRPUNextVariant(void) {
    for (NSUInteger index = 1; index < KPDOVIRPUVariantCount; index++) {
        if (!KPDOVIRPUCompleted(&KPDOVIRPUVariants[index])) return index;
    }
    return NSNotFound;
}

static size_t KPDOVIRPUCStringLength(const char *string) {
    size_t length = 0;
    while (string[length]) length++;
    return length;
}

static size_t KPDOVIRPUUnsignedString(char *output, uint64_t value, unsigned base) {
    char reversed[32];
    size_t count = 0;
    do {
        unsigned digit = (unsigned)(value % base);
        reversed[count++] = (char)(digit < 10 ? '0' + digit : 'a' + digit - 10);
        value /= base;
    } while (value && count < sizeof(reversed));
    for (size_t index = 0; index < count; index++) output[index] = reversed[count - index - 1];
    return count;
}

static const char *KPDOVIRPUSignalName(int signalNumber) {
    switch (signalNumber) {
        case SIGSEGV: return "SIGSEGV";
        case SIGBUS: return "SIGBUS";
        case SIGABRT: return "SIGABRT";
        case SIGILL: return "SIGILL";
        case SIGFPE: return "SIGFPE";
        case SIGTRAP: return "SIGTRAP";
        default: return "UNKNOWN";
    }
}

static void KPDOVIRPUCrashHandler(int signalNumber, siginfo_t *info, void *context) {
    (void)context;
    if (gRPUActive && gRPUJournalFD >= 0) {
        const char *identifier = gRPUIdentifier ? gRPUIdentifier : "unknown";
        size_t identifierLength = gRPUIdentifier ? gRPUIdentifierLength : 7;
        const char *signalName = KPDOVIRPUSignalName(signalNumber);
        char number[32];
        size_t length;
        KPDOVIRPUWriteFD(gRPUJournalFD, "CRASH id=", 9);
        KPDOVIRPUWriteFD(gRPUJournalFD, identifier, identifierLength);
        KPDOVIRPUWriteFD(gRPUJournalFD, " signal=", 8);
        KPDOVIRPUWriteFD(gRPUJournalFD, signalName, KPDOVIRPUCStringLength(signalName));
        KPDOVIRPUWriteFD(gRPUJournalFD, " sig=", 5);
        length = KPDOVIRPUUnsignedString(number, (uint64_t)signalNumber, 10);
        KPDOVIRPUWriteFD(gRPUJournalFD, number, length);
        KPDOVIRPUWriteFD(gRPUJournalFD, " code=", 6);
        length = KPDOVIRPUUnsignedString(number, info ? (uint64_t)info->si_code : 0, 10);
        KPDOVIRPUWriteFD(gRPUJournalFD, number, length);
        KPDOVIRPUWriteFD(gRPUJournalFD, " address=0x", 11);
        length = KPDOVIRPUUnsignedString(number, (uint64_t)(uintptr_t)(info ? info->si_addr : NULL), 16);
        KPDOVIRPUWriteFD(gRPUJournalFD, number, length);
        KPDOVIRPUWriteFD(gRPUJournalFD, "\n", 1);
    }
    _exit(128 + signalNumber);
}

static NSUInteger KPDOVIRPUArmSignals(int journalFD, const KPDOVIRPUVariant *variant,
                                      struct sigaction oldActions[KP_RPU_SIGNAL_COUNT]) {
    gRPUJournalFD = journalFD;
    gRPUIdentifier = variant->identifier;
    gRPUIdentifierLength = strlen(variant->identifier);
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = KPDOVIRPUCrashHandler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_SIGINFO;
    NSUInteger installed = 0;
    for (; installed < KP_RPU_SIGNAL_COUNT; installed++) {
        if (sigaction(KPDOVIRPUSignals[installed], &action, &oldActions[installed]) != 0) {
            for (NSUInteger rollback = 0; rollback < installed; rollback++) {
                sigaction(KPDOVIRPUSignals[rollback], &oldActions[rollback], NULL);
            }
            gRPUJournalFD = -1;
            gRPUIdentifier = NULL;
            gRPUIdentifierLength = 0;
            return 0;
        }
    }
    gRPUActive = 1;
    return installed;
}

static void KPDOVIRPURestoreSignals(struct sigaction oldActions[KP_RPU_SIGNAL_COUNT], NSUInteger installed) {
    gRPUActive = 0;
    for (NSUInteger index = 0; index < installed; index++) {
        sigaction(KPDOVIRPUSignals[index], &oldActions[index], NULL);
    }
    gRPUJournalFD = -1;
    gRPUIdentifier = NULL;
    gRPUIdentifierLength = 0;
}

static void KPDOVIRPUAppendVariant(NSMutableString *report, const KPDOVIRPUVariant *variant, NSDictionary *info) {
    [report appendFormat:@"[%s] resource=%s.bin size=%@ sha256=%@ structure=%@ blockID=%u capacity=%u over=%u blocks=%u\n",
     variant->identifier, variant->resource, info[@"size"] ?: @0,
     info[@"sha256"] ?: @"unavailable", [info[@"matched"] boolValue] ? @"MATCH" : @"MISMATCH",
     variant->blockID, variant->capacity, variant->over, variant->capacity + variant->over];
}

static NSString *KPDOVIRPUBeginLine(const KPDOVIRPUVariant *variant, NSDictionary *info) {
    return [NSString stringWithFormat:
            @"BEGIN id=%s resource=%s.bin route=CMGetDMVersionLevelFromRPU blockID=%u capacity=%u over=%u blocks=%u block_length_ue=0 block_bits=9 sha256=%@ os=%@",
            variant->identifier, variant->resource, variant->blockID,
            variant->capacity, variant->over, variant->capacity + variant->over,
            info[@"sha256"], NSProcessInfo.processInfo.operatingSystemVersionString];
}

- (NSString *)runSafe {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV3 DOVI RPU baseline ===\n"];
    [report appendFormat:@"App version: %@\nDevice OS: %@\n",
     [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"3.5.0",
     NSProcessInfo.processInfo.operatingSystemVersionString];
    [report appendString:@"Safe row parses only the baseline with no overrun blocks. Armed A10/B2/C6 variants are not parsed here.\n"];
    NSError *error = nil;
    const KPDOVIRPUVariant *baseline = &KPDOVIRPUVariants[0];
    NSDictionary *info = KPDOVIRPUInspect(baseline, &error);
    if (!info) {
        [report appendFormat:@"BASELINE STRUCTURE ERROR: %@\n", error.localizedDescription];
        return report;
    }
    KPDOVIRPUAppendVariant(report, baseline, info);
    if (![info[@"matched"] boolValue]) {
        [report appendString:@"BASELINE PARSE SKIPPED: resource mismatch.\n"];
        return report;
    }
    BOOL available = NO;
    uint32_t version = KPDOVIRPUCallVersion((__bridge CFDataRef)info[@"data"], &available);
    [report appendFormat:@"BASELINE id=rpu-baseline result=RETURNED version=%u blocks=0 symbol_available=%@\n",
     version, available ? @"YES" : @"NO"];
    [report appendFormat:@"Armed variant count=%zu; array A uses blockID=10 (capacity 4), B=2 (capacity 8), C=6 (capacity 5).\n",
     KPDOVIRPUVariantCount - 1];
    [report appendFormat:@"Previous journal events (last 12):\n%@\n", KPDOVIRPUJournalTail()];
    return report;
}

#if KP_DOVIRPU_ENABLE_ARMED
- (NSString *)runArmed {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV3 DOVI RPU extension block overrun ===\n"];
    [report appendFormat:@"App version: %@\nDevice OS: %@\n",
     [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"3.5.0",
     NSProcessInfo.processInfo.operatingSystemVersionString];
    NSUInteger index = KPDOVIRPUNextVariant();
    if (index == NSNotFound) {
        [report appendString:@"SWEEP_COMPLETE: all A10/B2/C6 one-over through eight-over variants have an END or CRASH record.\n"];
        [report appendFormat:@"Journal: %@\nPrevious journal events (last 12):\n%@\n",
         KPDOVIRPUJournalPath(), KPDOVIRPUJournalTail()];
        return report;
    }
    const KPDOVIRPUVariant *variant = &KPDOVIRPUVariants[index];
    [report appendFormat:@"Next variant: %s; completed variants are skipped after END or CRASH.\n", variant->identifier];
    [report appendFormat:@"Journal: %@\nPrevious journal events (last 12):\n%@\n",
     KPDOVIRPUJournalPath(), KPDOVIRPUJournalTail()];
    NSError *error = nil;
    NSDictionary *info = KPDOVIRPUInspect(variant, &error);
    if (!info) {
        [report appendFormat:@"ARMED STRUCTURE ERROR: %@; no parser call was attempted.\n", error.localizedDescription];
        return report;
    }
    KPDOVIRPUAppendVariant(report, variant, info);
    if (![info[@"matched"] boolValue]) {
        [report appendString:@"ARMED PARSE SKIPPED: resource mismatch.\n"];
        return report;
    }
    int journalFD = KPDOVIRPUOpenJournal(&error);
    if (journalFD < 0) {
        [report appendFormat:@"JOURNAL SETUP FAILED: %@; no parser call was attempted.\n", error.localizedDescription];
        return report;
    }
    NSString *begin = KPDOVIRPUBeginLine(variant, info);
    if (!KPDOVIRPUJournalLine(journalFD, begin, YES)) {
        [report appendString:@"JOURNAL BEGIN FAILED; no parser call was attempted.\n"];
        close(journalFD);
        return report;
    }
    [KPLog.shared appendFormat:@"DOVIRPU %@\nJournal: %@", begin, KPDOVIRPUJournalPath()];
    [report appendFormat:@"\n%@\n", begin];
    struct sigaction oldActions[KP_RPU_SIGNAL_COUNT];
    NSUInteger installed = KPDOVIRPUArmSignals(journalFD, variant, oldActions);
    if (installed != KP_RPU_SIGNAL_COUNT) {
        NSString *end = [NSString stringWithFormat:@"END id=%s result=SIGNAL_SETUP_FAILED errno=%d", variant->identifier, errno];
        KPDOVIRPUJournalLine(journalFD, end, YES);
        [report appendFormat:@"%@; no parser call was attempted.\n", end];
        close(journalFD);
        return report;
    }
    BOOL available = NO;
    uint32_t version = KPDOVIRPUCallVersion((__bridge CFDataRef)info[@"data"], &available);
    KPDOVIRPURestoreSignals(oldActions, installed);
    NSString *end = [NSString stringWithFormat:
                     @"END id=%s result=RETURNED version=%u symbol_available=%@ fault_address=none triage=not-a-primitive",
                     variant->identifier, version, available ? @"YES" : @"NO"];
    if (!KPDOVIRPUJournalLine(journalFD, end, YES)) {
        [KPLog.shared append:@"DOVIRPU journal END failed"];
    }
    [KPLog.shared append:end];
    [report appendFormat:@"%@\n", end];
    close(journalFD);
    [report appendString:@"If parsing terminates the process, reopen this row: persisted CRASH contains block ID, count, signal, code and fault address.\n"];
    return report;
}
#endif

- (NSString *)runReport {
    if (!self.isArmed) return [self runSafe];
#if KP_DOVIRPU_ENABLE_ARMED
    return [self runArmed];
#else
    return @"Armed execution was NOT COMPILED. KP_DOVIRPU_ENABLE_ARMED=1 is required; no overrun RPU was parsed by this row.\n";
#endif
}

@end
