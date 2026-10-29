#import "KPCGType5StackProbeModule.h"

#import "KPCGType5StackVariants.h"
#import "KPLog.h"

#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <errno.h>
#import <fcntl.h>
#import <signal.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

#ifndef KP_CGTYPE5STACK_ENABLE_ARMED
#define KP_CGTYPE5STACK_ENABLE_ARMED 0
#endif

#define KP_STACK_RENDER_SIZE 256
#define KP_STACK_SIGNAL_COUNT 6
#define KP_STACK_MAIN_INDEX 33

static const int KPCGType5StackSignals[KP_STACK_SIGNAL_COUNT] = {SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE, SIGTRAP};
static volatile sig_atomic_t gStackActive;
static int gStackJournalFD = -1;
static const char *gStackIdentifier;
static size_t gStackIdentifierLength;

@interface KPCGType5StackProbeModule ()
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;
- (NSString *)runStackVariant:(const KPCGType5StackVariant *)variant report:(NSMutableString *)report;
@end

@implementation KPCGType5StackProbeModule

- (instancetype)initWithArmed:(BOOL)armed {
    return [self initWithArmed:armed sweep:NO];
}

- (instancetype)initWithArmed:(BOOL)armed sweep:(BOOL)sweep {
    self = [super init];
    if (self) {
        _armed = armed;
        _sweep = sweep;
        if (!armed) {
            _identifier = @"cgtype5.stack.info";
            _title = @"CG Type 5 Stack Info";
            _subtitle = @"Safe R4/C1 render · R136 checked only by SHA";
        } else if (sweep) {
            _identifier = @"cgtype5.stack.sweep";
            _title = @"CG Type 5 Stack Sweep";
            _subtitle = @"R4..256 step 4 · resume after crash · explicit tap";
        } else {
            _identifier = @"cgtype5.stack.r136";
            _title = @"CG Type 5 STACK R136";
            _subtitle = @"T=2 stack mesh · 1048 OOB bytes · crash may terminate app";
        }
        _icon = armed ? @"exclamationmark.triangle" : @"doc.text.magnifyingglass";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

static NSError *KPCGType5StackError(NSString *description) {
    return [NSError errorWithDomain:@"KPCGType5Stack" code:1 userInfo:@{NSLocalizedDescriptionKey: description}];
}

static NSString *KPCGType5StackSHA256(NSData *data) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger index = 0; index < sizeof(digest); index++) {
        [result appendFormat:@"%02x", digest[index]];
    }
    return result;
}

static NSDictionary *KPCGType5StackInspect(const KPCGType5StackVariant *variant, NSError **error) {
    NSURL *URL = [NSBundle.mainBundle URLForResource:[NSString stringWithUTF8String:variant->resource]
                                     withExtension:@"pdf"];
    if (!URL) {
        if (error) *error = KPCGType5StackError([NSString stringWithFormat:@"Missing %s.pdf", variant->resource]);
        return nil;
    }
    NSData *data = [NSData dataWithContentsOfURL:URL options:0 error:error];
    if (!data) return nil;
    if (data.length < 8 || memcmp(data.bytes, "%PDF-", 5) != 0) {
        if (error) *error = KPCGType5StackError(@"Missing PDF header");
        return nil;
    }
    NSString *sha = KPCGType5StackSHA256(data);
    BOOL matched = [sha isEqualToString:[NSString stringWithUTF8String:variant->sha256]];
    if (!matched && error) *error = KPCGType5StackError(@"SHA-256 does not match the deterministic stack resource");
    return @{@"url": URL, @"size": @(data.length), @"sha256": sha, @"matched": @(matched)};
}

static NSDictionary *KPCGType5StackRenderPDF(NSURL *URL) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"route"] = @"CGPDFDocument-CGBitmapContext-CGContextDrawPDFPage";
    CGPDFDocumentRef document = NULL;
    CGColorSpaceRef colorSpace = NULL;
    CGContextRef context = NULL;
    CGImageRef image = NULL;
    @try {
        document = CGPDFDocumentCreateWithURL((__bridge CFURLRef)URL);
        if (!document) {
            result[@"status"] = @"PDF_OPEN_FAILED";
            return result;
        }
        size_t pages = CGPDFDocumentGetNumberOfPages(document);
        result[@"pages"] = @(pages);
        CGPDFPageRef page = CGPDFDocumentGetPage(document, 1);
        if (!page) {
            result[@"status"] = @"PDF_PAGE_FAILED";
            return result;
        }
        colorSpace = CGColorSpaceCreateDeviceRGB();
        if (!colorSpace) {
            result[@"status"] = @"COLORSPACE_FAILED";
            return result;
        }
        context = CGBitmapContextCreate(NULL, KP_STACK_RENDER_SIZE, KP_STACK_RENDER_SIZE, 8,
                                        KP_STACK_RENDER_SIZE * 4, colorSpace,
                                        kCGImageAlphaPremultipliedLast);
        if (!context) {
            result[@"status"] = @"CONTEXT_CREATE_FAILED";
            return result;
        }
        CGContextSetRGBFillColor(context, 1, 1, 1, 1);
        CGContextFillRect(context, CGRectMake(0, 0, KP_STACK_RENDER_SIZE, KP_STACK_RENDER_SIZE));
        CGContextSetShouldSmoothFonts(context, false);
        CGContextDrawPDFPage(context, page);
        CGContextFlush(context);
        image = CGBitmapContextCreateImage(context);
        if (!image) {
            result[@"status"] = @"DRAW_RETURNED_NO_IMAGE";
            return result;
        }
        result[@"status"] = @"RENDERED_SURVIVED";
        result[@"image"] = [NSString stringWithFormat:@"%zux%zu", CGImageGetWidth(image), CGImageGetHeight(image)];
        return result;
    } @catch (NSException *exception) {
        result[@"status"] = @"EXCEPTION";
        result[@"detail"] = exception.reason ?: exception.name;
        return result;
    } @finally {
        if (image) CGImageRelease(image);
        if (context) CGContextRelease(context);
        if (colorSpace) CGColorSpaceRelease(colorSpace);
        if (document) CGPDFDocumentRelease(document);
    }
}

static BOOL KPCGType5StackWriteFD(int fd, const void *bytes, size_t length) {
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

static BOOL KPCGType5StackJournalLine(int fd, NSString *line, BOOL synchronize) {
    NSString *terminated = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    NSData *data = [terminated dataUsingEncoding:NSUTF8StringEncoding];
    if (!KPCGType5StackWriteFD(fd, data.bytes, data.length)) return NO;
    return !synchronize || fsync(fd) == 0;
}

static NSString *KPCGType5StackJournalPath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproofv3-cgtype5-stack-armed-journal.log"];
}

static int KPCGType5StackOpenJournal(NSError **error) {
    NSString *documents = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    if (![[NSFileManager defaultManager] createDirectoryAtPath:documents
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:error]) {
        return -1;
    }
    int fd = open(KPCGType5StackJournalPath().fileSystemRepresentation,
                  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0 && error) {
        *error = KPCGType5StackError([NSString stringWithFormat:@"open %@: %s", KPCGType5StackJournalPath(), strerror(errno)]);
    }
    return fd;
}

static NSString *KPCGType5StackJournalTail(void) {
    NSString *body = [NSString stringWithContentsOfFile:KPCGType5StackJournalPath() encoding:NSUTF8StringEncoding error:nil];
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

static BOOL KPCGType5StackCompleted(const KPCGType5StackVariant *variant) {
    NSString *body = [NSString stringWithContentsOfFile:KPCGType5StackJournalPath() encoding:NSUTF8StringEncoding error:nil];
    if (!body.length) return NO;
    NSString *identifier = [NSString stringWithUTF8String:variant->identifier];
    NSString *end = [NSString stringWithFormat:@"END id=%@ ", identifier];
    NSString *crash = [NSString stringWithFormat:@"CRASH id=%@ ", identifier];
    return [body containsString:end] || [body containsString:crash];
}

static NSUInteger KPCGType5StackNextVariant(void) {
    for (NSUInteger index = 1; index < KPCGType5StackVariantCount; index++) {
        if (!KPCGType5StackCompleted(&KPCGType5StackVariants[index]) ) return index;
    }
    return NSNotFound;
}

static size_t KPCGType5StackCStringLength(const char *string) {
    size_t length = 0;
    while (string[length]) length++;
    return length;
}

static size_t KPCGType5StackUnsignedString(char *output, uint64_t value, unsigned base) {
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

static const char *KPCGType5StackSignalName(int signalNumber) {
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

static void KPCGType5StackCrashHandler(int signalNumber, siginfo_t *info, void *context) {
    (void)context;
    if (gStackActive && gStackJournalFD >= 0) {
        const char *identifier = gStackIdentifier ? gStackIdentifier : "unknown";
        size_t identifierLength = gStackIdentifier ? gStackIdentifierLength : 7;
        const char *signalName = KPCGType5StackSignalName(signalNumber);
        char number[32];
        size_t length;
        KPCGType5StackWriteFD(gStackJournalFD, "CRASH id=", 9);
        KPCGType5StackWriteFD(gStackJournalFD, identifier, identifierLength);
        KPCGType5StackWriteFD(gStackJournalFD, " signal=", 8);
        KPCGType5StackWriteFD(gStackJournalFD, signalName, KPCGType5StackCStringLength(signalName));
        KPCGType5StackWriteFD(gStackJournalFD, " sig=", 5);
        length = KPCGType5StackUnsignedString(number, (uint64_t)signalNumber, 10);
        KPCGType5StackWriteFD(gStackJournalFD, number, length);
        KPCGType5StackWriteFD(gStackJournalFD, " code=", 6);
        length = KPCGType5StackUnsignedString(number, info ? (uint64_t)info->si_code : 0, 10);
        KPCGType5StackWriteFD(gStackJournalFD, number, length);
        KPCGType5StackWriteFD(gStackJournalFD, " address=0x", 11);
        length = KPCGType5StackUnsignedString(number, (uint64_t)(uintptr_t)(info ? info->si_addr : NULL), 16);
        KPCGType5StackWriteFD(gStackJournalFD, number, length);
        KPCGType5StackWriteFD(gStackJournalFD, "\n", 1);
    }
    _exit(128 + signalNumber);
}

static NSUInteger KPCGType5StackArmSignals(int journalFD, const KPCGType5StackVariant *variant,
                                           struct sigaction oldActions[KP_STACK_SIGNAL_COUNT]) {
    gStackJournalFD = journalFD;
    gStackIdentifier = variant->identifier;
    gStackIdentifierLength = strlen(variant->identifier);
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = KPCGType5StackCrashHandler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_SIGINFO;
    NSUInteger installed = 0;
    for (; installed < KP_STACK_SIGNAL_COUNT; installed++) {
        if (sigaction(KPCGType5StackSignals[installed], &action, &oldActions[installed]) != 0) {
            for (NSUInteger rollback = 0; rollback < installed; rollback++) {
                sigaction(KPCGType5StackSignals[rollback], &oldActions[rollback], NULL);
            }
            gStackJournalFD = -1;
            gStackIdentifier = NULL;
            gStackIdentifierLength = 0;
            return 0;
        }
    }
    gStackActive = 1;
    return installed;
}

static void KPCGType5StackRestoreSignals(struct sigaction oldActions[KP_STACK_SIGNAL_COUNT], NSUInteger installed) {
    gStackActive = 0;
    for (NSUInteger index = 0; index < installed; index++) {
        sigaction(KPCGType5StackSignals[index], &oldActions[index], NULL);
    }
    gStackJournalFD = -1;
    gStackIdentifier = NULL;
    gStackIdentifierLength = 0;
}

static void KPCGType5StackAppendParams(NSMutableString *report, const KPCGType5StackVariant *variant, NSDictionary *info) {
    [report appendFormat:@"[%s] resource=%s.pdf size=%@ sha256=%@ structure=%@\n",
     variant->identifier, variant->resource, info[@"size"] ?: @0,
     info[@"sha256"] ?: @"unavailable", [info[@"matched"] boolValue] ? @"MATCH" : @"MISMATCH"];
    uint32_t oob = variant->rangeDimension > 5 ? 8 * (variant->rangeDimension - 5) : 0;
    [report appendFormat:@"  C=%u R=%u VPR=%u rows=%u triangles=%u allocation_model=0x%x first_OOB_model=B+0x%x OOB_bytes=%u outputs=1.0\n",
     variant->colorSpaceComponents, variant->rangeDimension, variant->verticesPerRow,
     variant->rows, variant->triangles, variant->allocationSize, variant->allocationSize, oob];
}

static NSString *KPCGType5StackBeginLine(const KPCGType5StackVariant *variant, NSDictionary *info) {
    uint32_t oob = variant->rangeDimension > 5 ? 8 * (variant->rangeDimension - 5) : 0;
    return [NSString stringWithFormat:
            @"BEGIN id=%s resource=%s.pdf route=CGPDFDocument-CGBitmapContext-CGContextDrawPDFPage C=%u R=%u VPR=%u rows=%u triangles=%u allocation_model=0x%x first_OOB_model=B+0x%x OOB_bytes=%u outputs=1.0 expected_public_fault=0x3ff000000000001c sha256=%@ os=%@",
            variant->identifier, variant->resource, variant->colorSpaceComponents,
            variant->rangeDimension, variant->verticesPerRow, variant->rows,
            variant->triangles, variant->allocationSize, variant->allocationSize, oob,
            info[@"sha256"], NSProcessInfo.processInfo.operatingSystemVersionString];
}

- (NSString *)runSafe {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV3 CoreGraphics Type 5 stack baseline ===\n"];
    [report appendFormat:@"App version: %@\nDevice OS: %@\n",
     [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"3.5.0",
     NSProcessInfo.processInfo.operatingSystemVersionString];
    [report appendString:@"Only R4/C1 is rendered here. R136 is checked by SHA-256 but is never rendered by the safe row.\n"];
    NSError *error = nil;
    const KPCGType5StackVariant *baseline = &KPCGType5StackVariants[0];
    NSDictionary *info = KPCGType5StackInspect(baseline, &error);
    if (!info) {
        [report appendFormat:@"BASELINE STRUCTURE ERROR: %@\n", error.localizedDescription];
        return report;
    }
    KPCGType5StackAppendParams(report, baseline, info);
    const KPCGType5StackVariant *mainVariant = &KPCGType5StackVariants[KP_STACK_MAIN_INDEX];
    NSDictionary *mainInfo = KPCGType5StackInspect(mainVariant, &error);
    if (mainInfo) {
        KPCGType5StackAppendParams(report, mainVariant, mainInfo);
    } else {
        [report appendFormat:@"R136 STRUCTURE ERROR: %@\n", error.localizedDescription];
    }
    if (![info[@"matched"] boolValue] || ![mainInfo[@"matched"] boolValue]) {
        [report appendString:@"SAFE RENDER SKIPPED: resource mismatch.\n"];
        return report;
    }
    NSDictionary *rendered = KPCGType5StackRenderPDF(info[@"url"]);
    [report appendFormat:@"BASELINE id=type5-stack-r004 result=%@ pages=%@ image=%@ detail=%@\n",
     rendered[@"status"], rendered[@"pages"] ?: @0, rendered[@"image"] ?: @"none", rendered[@"detail"] ?: @"none"];
    int journalFD = KPCGType5StackOpenJournal(&error);
    if (journalFD >= 0) {
        NSString *end = [NSString stringWithFormat:@"END id=type5-stack-r004 result=%@ pages=%@ image=%@",
                         rendered[@"status"], rendered[@"pages"] ?: @0, rendered[@"image"] ?: @"none"];
        KPCGType5StackJournalLine(journalFD, end, YES);
        close(journalFD);
    }
    [report appendFormat:@"Previous journal events (last 12):\n%@\n", KPCGType5StackJournalTail()];
    return report;
}

#if KP_CGTYPE5STACK_ENABLE_ARMED
- (NSString *)runStackVariant:(const KPCGType5StackVariant *)variant report:(NSMutableString *)report {
    NSError *error = nil;
    NSDictionary *info = KPCGType5StackInspect(variant, &error);
    if (!info) {
        [report appendFormat:@"ARMED STRUCTURE ERROR: %@; no render was attempted.\n", error.localizedDescription];
        return @"STRUCTURE_ERROR";
    }
    KPCGType5StackAppendParams(report, variant, info);
    if (![info[@"matched"] boolValue]) {
        [report appendString:@"ARMED RENDER SKIPPED: resource mismatch.\n"];
        return @"STRUCTURE_MISMATCH";
    }
    int journalFD = KPCGType5StackOpenJournal(&error);
    if (journalFD < 0) {
        [report appendFormat:@"JOURNAL SETUP FAILED: %@; no armed render was attempted.\n", error.localizedDescription];
        return @"JOURNAL_ERROR";
    }
    NSString *begin = KPCGType5StackBeginLine(variant, info);
    if (!KPCGType5StackJournalLine(journalFD, begin, YES)) {
        [report appendString:@"JOURNAL BEGIN FAILED; no armed render was attempted.\n"];
        close(journalFD);
        return @"JOURNAL_ERROR";
    }
    [KPLog.shared appendFormat:@"CGTYPE5STACK %@\nJournal: %@", begin, KPCGType5StackJournalPath()];
    [report appendFormat:@"\n%@\n", begin];
    struct sigaction oldActions[KP_STACK_SIGNAL_COUNT];
    NSUInteger installed = KPCGType5StackArmSignals(journalFD, variant, oldActions);
    if (installed != KP_STACK_SIGNAL_COUNT) {
        NSString *end = [NSString stringWithFormat:@"END id=%s result=SIGNAL_SETUP_FAILED errno=%d", variant->identifier, errno];
        KPCGType5StackJournalLine(journalFD, end, YES);
        [report appendFormat:@"%@; no armed render was attempted.\n", end];
        close(journalFD);
        return @"SIGNAL_SETUP_ERROR";
    }
    NSDictionary *rendered = KPCGType5StackRenderPDF(info[@"url"]);
    KPCGType5StackRestoreSignals(oldActions, installed);
    NSString *end = [NSString stringWithFormat:
                     @"END id=%s route=%@ result=%@ pages=%@ image=%@ fault_address=none detail=%@ triage=not-a-primitive",
                     variant->identifier, rendered[@"route"] ?: @"unknown", rendered[@"status"],
                     rendered[@"pages"] ?: @0, rendered[@"image"] ?: @"none", rendered[@"detail"] ?: @"none"];
    if (!KPCGType5StackJournalLine(journalFD, end, YES)) {
        [KPLog.shared append:@"CGTYPE5STACK journal END failed"];
    }
    [KPLog.shared append:end];
    [report appendFormat:@"%@\n", end];
    close(journalFD);
    return end;
}

- (NSString *)runMain {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV3 CoreGraphics Type 5 STACK R136 ARMED probe ===\n"];
    [report appendFormat:@"App version: %@\nDevice OS: %@\n",
     [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"3.5.0",
     NSProcessInfo.processInfo.operatingSystemVersionString];
    [report appendString:@"T=2, allocation 432 bytes, R=136/C=1, every output double is 1.0. Pre-trigger journal is fsynced before rendering. CRASH alone is not a primitive claim.\n"];
    [report appendFormat:@"Journal: %@\nPrevious journal events (last 12):\n%@\n",
     KPCGType5StackJournalPath(), KPCGType5StackJournalTail()];
    [self runStackVariant:&KPCGType5StackVariants[KP_STACK_MAIN_INDEX] report:report];
    [report appendString:@"If the process terminated, reopen this row: the persisted CRASH line carries the variant, signal, code and fault address.\n"];
    return report;
}

- (NSString *)runSweep {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV3 CoreGraphics Type 5 stack length sweep ===\n"];
    [report appendFormat:@"App version: %@\nDevice OS: %@\n",
     [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"3.5.0",
     NSProcessInfo.processInfo.operatingSystemVersionString];
    NSUInteger index = KPCGType5StackNextVariant();
    if (index == NSNotFound) {
        [report appendString:@"SWEEP_COMPLETE: all R=4..256 step-4 variants have an END or CRASH record.\n"];
        [report appendFormat:@"Journal: %@\nPrevious journal events (last 12):\n%@\n",
         KPCGType5StackJournalPath(), KPCGType5StackJournalTail()];
        return report;
    }
    const KPCGType5StackVariant *variant = &KPCGType5StackVariants[index];
    [report appendFormat:@"Next variant: %s; completed variants are skipped after END or CRASH.\n", variant->identifier];
    [self runStackVariant:variant report:report];
    [report appendString:@"Tap again or relaunch for the next R. A fatal signal leaves BEGIN/CRASH and no END for the interrupted variant.\n"];
    return report;
}
#endif

- (NSString *)runReport {
    if (!self.isArmed) return [self runSafe];
#if KP_CGTYPE5STACK_ENABLE_ARMED
    return self.isSweep ? [self runSweep] : [self runMain];
#else
    return @"Armed execution was NOT COMPILED. KP_CGTYPE5STACK_ENABLE_ARMED=1 is required; no stack PDF was rendered by this row.\n";
#endif
}

@end
