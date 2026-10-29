#import "KPHEIC112621ProbeModule.h"

#import "KPLog.h"

#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#import <errno.h>
#import <fcntl.h>
#import <signal.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

#ifndef KP_HEIC112621_ENABLE_ARMED
#define KP_HEIC112621_ENABLE_ARMED 0
#endif

#define KP_HEIC_WIDTH 256
#define KP_HEIC_SIGNAL_COUNT 6

static const int KPHEICSignals[KP_HEIC_SIGNAL_COUNT] = {SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE, SIGTRAP};
static volatile sig_atomic_t gHEICActive;
static int gHEICJournalFD = -1;
static const char *gHEICIdentifier;
static size_t gHEICIdentifierLength;

@interface KPHEIC112621ProbeModule ()
@end

@implementation KPHEIC112621ProbeModule

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        _identifier = armed ? @"heic112621.height-mismatch" : @"heic112621.equal-height-control";
        _title = armed ? @"HEIC 112621 Height Mismatch" : @"HEIC Equal-Height Control";
        _subtitle = armed
            ? @"Explicit tap · 256x16 + 256x48 BGRA collection · encode and decode"
            : @"256x16 + 256x16 BGRA collection · baseline encode and decode";
        _icon = armed ? @"exclamationmark.triangle" : @"photo.on.rectangle";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

static NSError *KPHEICError(NSString *description) {
    return [NSError errorWithDomain:@"KPHEIC112621Probe" code:1 userInfo:@{NSLocalizedDescriptionKey: description}];
}

static NSString *KPHEICSHA256(NSData *data) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger index = 0; index < sizeof(digest); index++) {
        [result appendFormat:@"%02x", digest[index]];
    }
    return result;
}

static BOOL KPHEICWriteFD(int fd, const void *bytes, size_t length) {
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

static BOOL KPHEICJournalLine(int fd, NSString *line, BOOL synchronize) {
    NSString *terminated = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    NSData *data = [terminated dataUsingEncoding:NSUTF8StringEncoding];
    if (!KPHEICWriteFD(fd, data.bytes, data.length)) return NO;
    return !synchronize || fsync(fd) == 0;
}

static NSString *KPHEICDocumentsPath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
}

static NSString *KPHEICJournalPath(BOOL armed) {
    NSString *name = armed ? @"kexproofv3-heic112621-armed-journal.log" : @"kexproofv3-heic112621-control-journal.log";
    return [KPHEICDocumentsPath() stringByAppendingPathComponent:name];
}

static int KPHEICOpenJournal(BOOL armed, NSError **error) {
    NSString *documents = KPHEICDocumentsPath();
    if (![[NSFileManager defaultManager] createDirectoryAtPath:documents
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:error]) {
        return -1;
    }
    int fd = open(KPHEICJournalPath(armed).fileSystemRepresentation,
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 && error) {
        *error = KPHEICError([NSString stringWithFormat:@"open %@: %s", KPHEICJournalPath(armed), strerror(errno)]);
    }
    return fd;
}

static size_t KPHEICCStringLength(const char *string) {
    size_t length = 0;
    while (string[length]) length++;
    return length;
}

static size_t KPHEICUnsignedString(char *output, uint64_t value, unsigned base) {
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

static const char *KPHEICSignalName(int signalNumber) {
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

static void KPHEICCrashHandler(int signalNumber, siginfo_t *info, void *context) {
    (void)context;
    if (gHEICActive && gHEICJournalFD >= 0) {
        const char *identifier = gHEICIdentifier ? gHEICIdentifier : "unknown";
        size_t identifierLength = gHEICIdentifier ? gHEICIdentifierLength : 7;
        const char *signalName = KPHEICSignalName(signalNumber);
        char number[32];
        size_t length;
        KPHEICWriteFD(gHEICJournalFD, "CRASH id=", 9);
        KPHEICWriteFD(gHEICJournalFD, identifier, identifierLength);
        KPHEICWriteFD(gHEICJournalFD, " signal=", 8);
        KPHEICWriteFD(gHEICJournalFD, signalName, KPHEICCStringLength(signalName));
        KPHEICWriteFD(gHEICJournalFD, " sig=", 5);
        length = KPHEICUnsignedString(number, (uint64_t)signalNumber, 10);
        KPHEICWriteFD(gHEICJournalFD, number, length);
        KPHEICWriteFD(gHEICJournalFD, " code=", 6);
        length = KPHEICUnsignedString(number, info ? (uint64_t)info->si_code : 0, 10);
        KPHEICWriteFD(gHEICJournalFD, number, length);
        KPHEICWriteFD(gHEICJournalFD, " address=0x", 11);
        length = KPHEICUnsignedString(number, (uint64_t)(uintptr_t)(info ? info->si_addr : NULL), 16);
        KPHEICWriteFD(gHEICJournalFD, number, length);
        KPHEICWriteFD(gHEICJournalFD, "\n", 1);
    }
    _exit(128 + signalNumber);
}

static NSUInteger KPHEICArmSignals(int journalFD, const char *identifier,
                                   struct sigaction oldActions[KP_HEIC_SIGNAL_COUNT]) {
    gHEICJournalFD = journalFD;
    gHEICIdentifier = identifier;
    gHEICIdentifierLength = strlen(identifier);
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = KPHEICCrashHandler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_SIGINFO;
    NSUInteger installed = 0;
    for (; installed < KP_HEIC_SIGNAL_COUNT; installed++) {
        if (sigaction(KPHEICSignals[installed], &action, &oldActions[installed]) != 0) {
            for (NSUInteger rollback = 0; rollback < installed; rollback++) {
                sigaction(KPHEICSignals[rollback], &oldActions[rollback], NULL);
            }
            gHEICJournalFD = -1;
            gHEICIdentifier = NULL;
            gHEICIdentifierLength = 0;
            return 0;
        }
    }
    gHEICActive = 1;
    return installed;
}

static void KPHEICRestoreSignals(struct sigaction oldActions[KP_HEIC_SIGNAL_COUNT], NSUInteger installed) {
    gHEICActive = 0;
    for (NSUInteger index = 0; index < installed; index++) {
        sigaction(KPHEICSignals[index], &oldActions[index], NULL);
    }
    gHEICJournalFD = -1;
    gHEICIdentifier = NULL;
    gHEICIdentifierLength = 0;
}

static CGImageRef KPHEICMakeFrame(size_t height, uint32_t bgra) {
    const size_t rowBytes = KP_HEIC_WIDTH * 4;
    uint8_t *pixels = malloc(rowBytes * height);
    if (!pixels) return NULL;
    for (size_t index = 0; index < KP_HEIC_WIDTH * height; index++) {
        memcpy(pixels + index * 4, &bgra, 4);
    }
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(
        pixels, KP_HEIC_WIDTH, height, 8, rowBytes, colorSpace,
        kCGImageAlphaNoneSkipFirst | kCGBitmapByteOrder32Little);
    CGImageRef image = context ? CGBitmapContextCreateImage(context) : NULL;
    if (context) CGContextRelease(context);
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    free(pixels);
    return image;
}

static BOOL KPHEICRenderImage(CGImageRef image, int journalFD, const char *route, size_t index) {
    if (!image) {
        KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"DECODE_FAILED route=%s index=%zu", route, index], YES);
        return NO;
    }
    size_t width = CGImageGetWidth(image);
    size_t height = CGImageGetHeight(image);
    KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"DECODED route=%s index=%zu width=%zu height=%zu", route, index, width, height], YES);
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(NULL, width, height, 8, width * 4, colorSpace,
                                                 kCGImageAlphaPremultipliedLast);
    if (!context) {
        if (colorSpace) CGColorSpaceRelease(colorSpace);
        KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"CONTEXT_FAILED route=%s index=%zu", route, index], YES);
        return NO;
    }
    KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"BEFORE_RENDER route=%s index=%zu", route, index], YES);
    CGContextDrawImage(context, CGRectMake(0, 0, width, height), image);
    CGContextFlush(context);
    KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"AFTER_RENDER route=%s index=%zu", route, index], YES);
    CGContextRelease(context);
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    return YES;
}

static BOOL KPHEICDecodeCollection(NSURL *URL, int journalFD) {
    CGImageSourceRef source = CGImageSourceCreateWithURL((__bridge CFURLRef)URL, NULL);
    if (!source) {
        KPHEICJournalLine(journalFD, @"SOURCE_OPEN_FAILED", YES);
        return NO;
    }
    size_t count = CGImageSourceGetCount(source);
    KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"SOURCE_OPENED count=%zu", count], YES);
    BOOL ok = YES;
    for (size_t index = 0; index < count; index++) {
        KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"BEFORE_DECODE_IMAGE index=%zu", index], YES);
        CGImageRef image = CGImageSourceCreateImageAtIndex(source, index, NULL);
        ok = KPHEICRenderImage(image, journalFD, "image", index) && ok;
        if (image) CGImageRelease(image);
        KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"BEFORE_DECODE_THUMBNAIL index=%zu", index], YES);
        NSDictionary *options = @{
            (NSString *)kCGImageSourceCreateThumbnailWithTransform: @YES,
            (NSString *)kCGImageSourceThumbnailMaxPixelSize: @(KP_HEIC_WIDTH),
            (NSString *)kCGImageSourceCreateThumbnailFromImageAlways: @YES
        };
        CGImageRef thumbnail = CGImageSourceCreateThumbnailAtIndex(source, index, (__bridge CFDictionaryRef)options);
        ok = KPHEICRenderImage(thumbnail, journalFD, "thumbnail", index) && ok;
        if (thumbnail) CGImageRelease(thumbnail);
    }
    CFRelease(source);
    return ok;
}

- (NSString *)runWithArmed:(BOOL)armed {
    NSMutableString *report = [NSMutableString string];
    const char *identifier = armed ? "heic112621.height-mismatch" : "heic112621.equal-height-control";
    size_t heights[] = {16, armed ? 48 : 16};
    uint32_t colors[] = {0xFF202020u, 0xFFADBEEFu};
    NSString *path = [KPHEICDocumentsPath() stringByAppendingPathComponent:
                      armed ? @"heic112621-armed.heic" : @"heic112621-control.heic"];
    NSError *error = nil;
    NSFileManager *manager = [NSFileManager defaultManager];
    if ([manager fileExistsAtPath:path]) {
        [manager removeItemAtPath:path error:nil];
    }
    int journalFD = KPHEICOpenJournal(armed, &error);
    if (journalFD < 0) {
        [report appendFormat:@"JOURNAL SETUP FAILED: %@; no encode was attempted.\n", error.localizedDescription];
        return report;
    }
    [report appendFormat:@"=== KexProofV3 HEIC 112621 %@ ===\nDevice OS: %@\nJournal: %@\nHEIC path: %@\n",
     armed ? @"ARMED" : @"CONTROL", NSProcessInfo.processInfo.operatingSystemVersionString,
     KPHEICJournalPath(armed), path];
    KPHEICJournalLine(journalFD, [NSString stringWithFormat:
                                  @"BEGIN id=%s width=%u heights=%zu,%zu markers=0x%08x,0x%08x os=%@",
                                  identifier, KP_HEIC_WIDTH, heights[0], heights[1], colors[0], colors[1],
                                  NSProcessInfo.processInfo.operatingSystemVersionString], YES);

    struct sigaction oldActions[KP_HEIC_SIGNAL_COUNT];
    NSUInteger installed = KPHEICArmSignals(journalFD, identifier, oldActions);
    if (installed != KP_HEIC_SIGNAL_COUNT) {
        KPHEICJournalLine(journalFD, @"END result=SIGNAL_SETUP_FAILED", YES);
        close(journalFD);
        [report appendString:@"SIGNAL SETUP FAILED; no encode was attempted.\n"];
        return report;
    }

    NSURL *URL = [NSURL fileURLWithPath:path];
    CGImageDestinationRef destination = CGImageDestinationCreateWithURL(
        (__bridge CFURLRef)URL, CFSTR("public.heic"), 2, NULL);
    if (!destination) {
        KPHEICJournalLine(journalFD, @"END result=DESTINATION_CREATE_FAILED", YES);
        KPHEICRestoreSignals(oldActions, installed);
        close(journalFD);
        [report appendString:@"DESTINATION CREATE FAILED.\n"];
        return report;
    }
    KPHEICJournalLine(journalFD, @"DESTINATION_CREATED type=public.heic count=2", YES);

    BOOL ok = YES;
    NSDictionary *options = @{(NSString *)kCGImageDestinationLossyCompressionQuality: @1.0};
    for (size_t index = 0; index < 2; index++) {
        KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"BEFORE_ADD_IMAGE index=%zu height=%zu", index, heights[index]], YES);
        CGImageRef frame = KPHEICMakeFrame(heights[index], colors[index]);
        if (!frame) {
            KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"FRAME_CREATE_FAILED index=%zu", index], YES);
            ok = NO;
            break;
        }
        CGImageDestinationAddImage(destination, frame, (__bridge CFDictionaryRef)options);
        CGImageRelease(frame);
        KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"AFTER_ADD_IMAGE index=%zu", index], YES);
    }
    if (ok) {
        KPHEICJournalLine(journalFD, @"BEFORE_FINALIZE", YES);
        ok = CGImageDestinationFinalize(destination);
        KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"AFTER_FINALIZE ok=%d", ok], YES);
    } else {
        KPHEICJournalLine(journalFD, @"FINALIZE_SKIPPED frame creation failed", YES);
    }
    CFRelease(destination);

    NSData *data = nil;
    NSString *sha = nil;
    if (ok) {
        data = [NSData dataWithContentsOfURL:URL options:0 error:&error];
        if (!data) {
            ok = NO;
            KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"READ_BACK_FAILED %@", error.localizedDescription], YES);
        } else {
            sha = KPHEICSHA256(data);
            KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"HEIC_READY bytes=%llu sha256=%@",
                                          (unsigned long long)data.length, sha], YES);
        }
    }
    if (ok) ok = KPHEICDecodeCollection(URL, journalFD);
    KPHEICRestoreSignals(oldActions, installed);
    KPHEICJournalLine(journalFD, [NSString stringWithFormat:@"END id=%s result=%@ sha256=%@",
                                  identifier, ok ? @"SURVIVED" : @"FAILED", sha ?: @"unavailable"], YES);
    close(journalFD);
    [report appendFormat:@"result=%@ bytes=%llu sha256=%@\n", ok ? @"SURVIVED" : @"FAILED",
     (unsigned long long)data.length, sha ?: @"unavailable"];
    [report appendString:@"SURVIVED is not evidence that OOB is absent. A fatal result must be read from the persisted pre-call journal.\n"];
    return report;
}

- (NSString *)runReport {
#if KP_HEIC112621_ENABLE_ARMED
    return [self runWithArmed:self.isArmed];
#else
    if (self.isArmed) {
        return @"Armed execution was NOT COMPILED. KP_HEIC112621_ENABLE_ARMED=1 is required; no HEIC was encoded.\n";
    }
    return [self runWithArmed:NO];
#endif
}

@end
