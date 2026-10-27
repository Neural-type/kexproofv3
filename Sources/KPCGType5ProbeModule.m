#import "KPCGType5ProbeModule.h"

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

#ifndef KP_CGTYPE527_ENABLE_ARMED
#define KP_CGTYPE527_ENABLE_ARMED 0
#endif

#define KP_CGTYPE5_RENDER_SIZE 256
#define KP_CGTYPE5_SIGNAL_COUNT 6

typedef struct {
    const char *identifier;
    const char *resource;
    const char *sha256;
    uint32_t rangeDimension;
    uint32_t colorSpaceComponents;
    uint32_t verticesPerRow;
    uint32_t rows;
    uint32_t triangles;
    uint32_t allocationSize;
} KPCGType5Variant;

static const KPCGType5Variant KPCGType5Benign = {
    .identifier = "type5-benign",
    .resource = "cgtype5-benign",
    .sha256 = "ee8847551ed6f5072e9ba9fd4abb817ff0c8db84d54939832def4d99d7d1f687",
    .rangeDimension = 1,
    .colorSpaceComponents = 1,
    .verticesPerRow = 2,
    .rows = 130,
    .triangles = 258,
    .allocationSize = 0xd9b0
};

static const KPCGType5Variant KPCGType5Armed = {
    .identifier = "type5-r6-heap",
    .resource = "cgtype5-r6-heap",
    .sha256 = "c9733413f61e825694498bfe946817b95c28c213dfd19ba6ed8ec44715f7c998",
    .rangeDimension = 6,
    .colorSpaceComponents = 1,
    .verticesPerRow = 2,
    .rows = 130,
    .triangles = 258,
    .allocationSize = 0xd9b0
};

static const int KPCGType5Signals[KP_CGTYPE5_SIGNAL_COUNT] = {SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE, SIGTRAP};
static volatile sig_atomic_t gType5Active;
static int gType5JournalFD = -1;
static const char *gType5Identifier;
static size_t gType5IdentifierLength;

@interface KPCGType5ProbeModule ()
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;
@end

@implementation KPCGType5ProbeModule

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        _identifier = armed ? @"cgtype527.render.armed" : @"cgtype527.render.safe";
        _title = armed ? @"CG Type 5 R6 ARMED" : @"CG Type 5 Safe Render";
        _subtitle = armed
            ? @"Explicit tap · R6/C1 · 258 triangles · crash may terminate app"
            : @"Valid Type 5 · R1/C1 · same 258-triangle render path";
        _icon = armed ? @"exclamationmark.triangle" : @"doc.text.magnifyingglass";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

static NSError *KPCGType5Error(NSString *description) {
    return [NSError errorWithDomain:@"KPCGType5Probe" code:1 userInfo:@{NSLocalizedDescriptionKey: description}];
}

static NSString *KPCGType5SHA256(NSData *data) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger index = 0; index < sizeof(digest); index++) {
        [result appendFormat:@"%02x", digest[index]];
    }
    return result;
}

static NSDictionary *KPCGType5Inspect(const KPCGType5Variant *variant, NSError **error) {
    NSURL *URL = [NSBundle.mainBundle URLForResource:[NSString stringWithUTF8String:variant->resource]
                                     withExtension:@"pdf"];
    if (!URL) {
        if (error) *error = KPCGType5Error([NSString stringWithFormat:@"Missing %s.pdf", variant->resource]);
        return nil;
    }
    NSData *data = [NSData dataWithContentsOfURL:URL options:0 error:error];
    if (!data) return nil;
    if (data.length < 8 || memcmp(data.bytes, "%PDF-", 5) != 0) {
        if (error) *error = KPCGType5Error(@"Missing PDF header");
        return nil;
    }
    NSString *sha = KPCGType5SHA256(data);
    BOOL matched = [sha isEqualToString:[NSString stringWithUTF8String:variant->sha256]];
    if (!matched && error) *error = KPCGType5Error(@"SHA-256 does not match the deterministic Type 5 resource");
    return @{
        @"url": URL,
        @"size": @(data.length),
        @"sha256": sha,
        @"matched": @(matched)
    };
}

static NSDictionary *KPCGType5RenderPDF(NSURL *URL) {
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
        context = CGBitmapContextCreate(NULL, KP_CGTYPE5_RENDER_SIZE, KP_CGTYPE5_RENDER_SIZE, 8,
                                        KP_CGTYPE5_RENDER_SIZE * 4, colorSpace,
                                        kCGImageAlphaPremultipliedLast);
        if (!context) {
            result[@"status"] = @"CONTEXT_CREATE_FAILED";
            return result;
        }
        CGContextSetRGBFillColor(context, 1, 1, 1, 1);
        CGContextFillRect(context, CGRectMake(0, 0, KP_CGTYPE5_RENDER_SIZE, KP_CGTYPE5_RENDER_SIZE));
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

static BOOL KPCGType5WriteFD(int fd, const void *bytes, size_t length) {
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

static BOOL KPCGType5JournalLine(int fd, NSString *line, BOOL synchronize) {
    NSString *terminated = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    NSData *data = [terminated dataUsingEncoding:NSUTF8StringEncoding];
    if (!KPCGType5WriteFD(fd, data.bytes, data.length)) return NO;
    return !synchronize || fsync(fd) == 0;
}

static NSString *KPCGType5DocumentsPath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
}

static NSString *KPCGType5JournalPath(void) {
    return [KPCGType5DocumentsPath() stringByAppendingPathComponent:@"kexproofv3-cgtype5-armed-journal.log"];
}

static int KPCGType5OpenJournal(NSError **error) {
    NSString *documents = KPCGType5DocumentsPath();
    if (![[NSFileManager defaultManager] createDirectoryAtPath:documents
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:error]) {
        return -1;
    }
    int fd = open(KPCGType5JournalPath().fileSystemRepresentation,
                  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0 && error) {
        *error = KPCGType5Error([NSString stringWithFormat:@"open %@: %s", KPCGType5JournalPath(), strerror(errno)]);
    }
    return fd;
}

static NSString *KPCGType5JournalTail(void) {
    NSString *body = [NSString stringWithContentsOfFile:KPCGType5JournalPath() encoding:NSUTF8StringEncoding error:nil];
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

static size_t KPCGType5CStringLength(const char *string) {
    size_t length = 0;
    while (string[length]) length++;
    return length;
}

static size_t KPCGType5UnsignedString(char *output, uint64_t value, unsigned base) {
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

static const char *KPCGType5SignalName(int signalNumber) {
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

static void KPCGType5CrashHandler(int signalNumber, siginfo_t *info, void *context) {
    (void)context;
    if (gType5Active && gType5JournalFD >= 0) {
        const char *identifier = gType5Identifier ? gType5Identifier : "unknown";
        size_t identifierLength = gType5Identifier ? gType5IdentifierLength : 7;
        const char *signalName = KPCGType5SignalName(signalNumber);
        char number[32];
        size_t length;
        KPCGType5WriteFD(gType5JournalFD, "CRASH id=", 9);
        KPCGType5WriteFD(gType5JournalFD, identifier, identifierLength);
        KPCGType5WriteFD(gType5JournalFD, " signal=", 8);
        KPCGType5WriteFD(gType5JournalFD, signalName, KPCGType5CStringLength(signalName));
        KPCGType5WriteFD(gType5JournalFD, " sig=", 5);
        length = KPCGType5UnsignedString(number, (uint64_t)signalNumber, 10);
        KPCGType5WriteFD(gType5JournalFD, number, length);
        KPCGType5WriteFD(gType5JournalFD, " code=", 6);
        length = KPCGType5UnsignedString(number, info ? (uint64_t)info->si_code : 0, 10);
        KPCGType5WriteFD(gType5JournalFD, number, length);
        KPCGType5WriteFD(gType5JournalFD, " address=0x", 11);
        length = KPCGType5UnsignedString(number, (uint64_t)(uintptr_t)(info ? info->si_addr : NULL), 16);
        KPCGType5WriteFD(gType5JournalFD, number, length);
        KPCGType5WriteFD(gType5JournalFD, "\n", 1);
    }
    _exit(128 + signalNumber);
}

static NSUInteger KPCGType5ArmSignals(int journalFD, const KPCGType5Variant *variant,
                                      struct sigaction oldActions[KP_CGTYPE5_SIGNAL_COUNT]) {
    gType5JournalFD = journalFD;
    gType5Identifier = variant->identifier;
    gType5IdentifierLength = strlen(variant->identifier);
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = KPCGType5CrashHandler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_SIGINFO;
    NSUInteger installed = 0;
    for (; installed < KP_CGTYPE5_SIGNAL_COUNT; installed++) {
        if (sigaction(KPCGType5Signals[installed], &action, &oldActions[installed]) != 0) {
            for (NSUInteger rollback = 0; rollback < installed; rollback++) {
                sigaction(KPCGType5Signals[rollback], &oldActions[rollback], NULL);
            }
            gType5JournalFD = -1;
            gType5Identifier = NULL;
            gType5IdentifierLength = 0;
            return 0;
        }
    }
    gType5Active = 1;
    return installed;
}

static void KPCGType5RestoreSignals(struct sigaction oldActions[KP_CGTYPE5_SIGNAL_COUNT], NSUInteger installed) {
    gType5Active = 0;
    for (NSUInteger index = 0; index < installed; index++) {
        sigaction(KPCGType5Signals[index], &oldActions[index], NULL);
    }
    gType5JournalFD = -1;
    gType5Identifier = NULL;
    gType5IdentifierLength = 0;
}

static void KPCGType5AppendParams(NSMutableString *report, const KPCGType5Variant *variant, NSDictionary *info) {
    [report appendFormat:@"[%s] resource=%s.pdf size=%@ sha256=%@ structure=%@\n",
     variant->identifier, variant->resource, info[@"size"] ?: @0,
     info[@"sha256"] ?: @"unavailable", [info[@"matched"] boolValue] ? @"MATCH" : @"MISMATCH"];
    [report appendFormat:@"  C=%u R=%u VPR=%u rows=%u triangles=%u allocation_model=0x%x first_OOB_model=B+0x%x sixth_double=1.0\n",
     variant->colorSpaceComponents, variant->rangeDimension, variant->verticesPerRow,
     variant->rows, variant->triangles, variant->allocationSize, variant->allocationSize];
}

- (NSString *)runSafe {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV3 CoreGraphics Type 5 safe render ===\n"];
    [report appendFormat:@"App version: %@\nDevice OS: %@\n",
     [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"3.4.0",
     NSProcessInfo.processInfo.operatingSystemVersionString];
    [report appendString:@"Safe row renders only the valid R1/C1 resource. The R6 resource is checked by SHA-256 but is never rendered here.\n"];
    NSError *error = nil;
    NSDictionary *info = KPCGType5Inspect(&KPCGType5Benign, &error);
    if (!info) {
        [report appendFormat:@"BENIGN STRUCTURE ERROR: %@\n", error.localizedDescription];
        return report;
    }
    KPCGType5AppendParams(report, &KPCGType5Benign, info);
    NSError *armedError = nil;
    NSDictionary *armedInfo = KPCGType5Inspect(&KPCGType5Armed, &armedError);
    if (armedInfo) {
        KPCGType5AppendParams(report, &KPCGType5Armed, armedInfo);
    } else {
        [report appendFormat:@"[type5-r6-heap] STRUCTURE ERROR: %@\n", armedError.localizedDescription];
    }
    if (![info[@"matched"] boolValue]) {
        [report appendString:@"BENIGN RENDER SKIPPED: resource mismatch.\n"];
        return report;
    }
    NSDictionary *rendered = KPCGType5RenderPDF(info[@"url"]);
    [report appendFormat:@"BENIGN id=type5-benign result=%@ pages=%@ image=%@ detail=%@\n",
     rendered[@"status"], rendered[@"pages"] ?: @0, rendered[@"image"] ?: @"none", rendered[@"detail"] ?: @"none"];
    [report appendString:@"The valid result verifies this CoreGraphics Type 5 render route only; it is not an OOB oracle.\n"];
    return report;
}

#if KP_CGTYPE527_ENABLE_ARMED
- (NSString *)runArmed {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV3 CoreGraphics Type 5 R6 ARMED probe ===\n"];
    [report appendFormat:@"App version: %@\nDevice OS: %@\n",
     [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"3.4.0",
     NSProcessInfo.processInfo.operatingSystemVersionString];
    [report appendString:@"One bounded render. CRASH is triage evidence, not a proven primitive; reclaim and pointer targets remain unproven. RENDERED_SURVIVED does not disprove OOB corruption.\n"];
    [report appendString:@"No canary is claimed: B is an internal CoreGraphics allocation and this module uses no private allocator hooks.\n"];
    [report appendFormat:@"Journal: %@\nPrevious journal events (last 12):\n%@\n",
     KPCGType5JournalPath(), KPCGType5JournalTail()];

    NSError *error = nil;
    NSDictionary *info = KPCGType5Inspect(&KPCGType5Armed, &error);
    if (!info) {
        [report appendFormat:@"ARMED STRUCTURE ERROR: %@; no render was attempted.\n", error.localizedDescription];
        return report;
    }
    KPCGType5AppendParams(report, &KPCGType5Armed, info);
    if (![info[@"matched"] boolValue]) {
        [report appendString:@"ARMED RENDER SKIPPED: resource mismatch.\n"];
        return report;
    }
    int journalFD = KPCGType5OpenJournal(&error);
    if (journalFD < 0) {
        [report appendFormat:@"JOURNAL SETUP FAILED: %@; no armed render was attempted.\n", error.localizedDescription];
        return report;
    }
    NSString *begin = [NSString stringWithFormat:
                       @"BEGIN id=type5-r6-heap resource=cgtype5-r6-heap.pdf route=CGPDFDocument-CGBitmapContext-CGContextDrawPDFPage C=1 R=6 VPR=2 rows=130 triangles=258 allocation_model=0xd9b0 first_OOB_model=B+0xd9b0 sixth_double=1.0 canary=unavailable-no-private-B sha256=%@ os=%@",
                       info[@"sha256"], NSProcessInfo.processInfo.operatingSystemVersionString];
    if (!KPCGType5JournalLine(journalFD, begin, YES)) {
        [report appendString:@"JOURNAL BEGIN FAILED; no armed render was attempted.\n"];
        close(journalFD);
        return report;
    }
    [KPLog.shared appendFormat:@"CGTYPE5 %@\nJournal: %@", begin, KPCGType5JournalPath()];
    [report appendFormat:@"\n%@\n", begin];

    struct sigaction oldActions[KP_CGTYPE5_SIGNAL_COUNT];
    NSUInteger installed = KPCGType5ArmSignals(journalFD, &KPCGType5Armed, oldActions);
    if (installed != KP_CGTYPE5_SIGNAL_COUNT) {
        NSString *end = [NSString stringWithFormat:@"END id=type5-r6-heap result=SIGNAL_SETUP_FAILED errno=%d", errno];
        KPCGType5JournalLine(journalFD, end, YES);
        [report appendFormat:@"%@; no armed render was attempted.\n", end];
        close(journalFD);
        return report;
    }
    NSDictionary *rendered = KPCGType5RenderPDF(info[@"url"]);
    KPCGType5RestoreSignals(oldActions, installed);
    NSString *end = [NSString stringWithFormat:
                     @"END id=type5-r6-heap route=%@ result=%@ pages=%@ image=%@ fault_address=none canary=not-claimed detail=%@ triage=not-a-primitive",
                     rendered[@"route"] ?: @"unknown", rendered[@"status"], rendered[@"pages"] ?: @0,
                     rendered[@"image"] ?: @"none", rendered[@"detail"] ?: @"none"];
    if (!KPCGType5JournalLine(journalFD, end, YES)) {
        [KPLog.shared append:@"CGTYPE5 journal END failed"];
    }
    [KPLog.shared append:end];
    [report appendFormat:@"%@\n", end];
    close(journalFD);
    [report appendString:@"If the process terminated, reopen this row: the persisted CRASH line carries the variant, signal, code and fault address. No END line is expected after a fatal signal.\n"];
    return report;
}
#endif

- (NSString *)runReport {
    if (!self.isArmed) return [self runSafe];
#if KP_CGTYPE527_ENABLE_ARMED
    return [self runArmed];
#else
    return @"Armed execution was NOT COMPILED. KP_CGTYPE527_ENABLE_ARMED=1 is required; no PDF was rendered by this row.\n";
#endif
}

@end
