#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <errno.h>
#import <fcntl.h>
#import <signal.h>
#import <stdint.h>
#import <string.h>
#import <unistd.h>

static const int gSignals[] = {SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE, SIGTRAP};
static volatile sig_atomic_t gActive;
static int gJournalFD = -1;

static BOOL writeFD(int fd, const void *bytes, size_t length) {
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

static BOOL journal(NSString *line) {
    NSData *data = [[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    return writeFD(gJournalFD, data.bytes, data.length) && fsync(gJournalFD) == 0;
}

static void crashHandler(int signalNumber, siginfo_t *info, void *context) {
    (void)context;
    if (gActive && gJournalFD >= 0) {
        char buffer[160];
        int length = snprintf(buffer, sizeof(buffer), "CRASH signal=%d code=%d address=%p\n",
                              signalNumber, info ? info->si_code : 0, info ? info->si_addr : NULL);
        if (length > 0) writeFD(gJournalFD, buffer, (size_t)length);
    }
    _exit(128 + signalNumber);
}

static BOOL armSignals(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = crashHandler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_SIGINFO;
    for (size_t index = 0; index < sizeof(gSignals) / sizeof(gSignals[0]); index++) {
        if (sigaction(gSignals[index], &action, NULL) != 0) return NO;
    }
    gActive = 1;
    return YES;
}

static CGImageRef makeFrame(size_t height, uint32_t bgra) {
    const size_t width = 256;
    const size_t rowBytes = width * 4;
    uint8_t *pixels = malloc(rowBytes * height);
    if (!pixels) return NULL;
    for (size_t index = 0; index < width * height; index++) {
        memcpy(pixels + index * 4, &bgra, 4);
    }
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(pixels, width, height, 8, rowBytes, colorSpace,
                                                 kCGImageAlphaNoneSkipFirst | kCGBitmapByteOrder32Little);
    CGImageRef image = context ? CGBitmapContextCreateImage(context) : NULL;
    if (context) CGContextRelease(context);
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    free(pixels);
    return image;
}

static BOOL renderImage(CGImageRef image, const char *route, size_t index) {
    if (!image) {
        journal([NSString stringWithFormat:@"DECODE_FAILED route=%s index=%zu", route, index]);
        return NO;
    }
    size_t width = CGImageGetWidth(image);
    size_t height = CGImageGetHeight(image);
    journal([NSString stringWithFormat:@"DECODED route=%s index=%zu width=%zu height=%zu", route, index, width, height]);
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(NULL, width, height, 8, width * 4, colorSpace,
                                                 kCGImageAlphaPremultipliedLast);
    if (!context) {
        if (colorSpace) CGColorSpaceRelease(colorSpace);
        journal([NSString stringWithFormat:@"CONTEXT_FAILED route=%s index=%zu", route, index]);
        return NO;
    }
    journal([NSString stringWithFormat:@"BEFORE_RENDER route=%s index=%zu", route, index]);
    CGContextDrawImage(context, CGRectMake(0, 0, width, height), image);
    CGContextFlush(context);
    journal([NSString stringWithFormat:@"AFTER_RENDER route=%s index=%zu", route, index]);
    CGContextRelease(context);
    CGColorSpaceRelease(colorSpace);
    return YES;
}

static BOOL decodeCollection(NSURL *URL) {
    CGImageSourceRef source = CGImageSourceCreateWithURL((__bridge CFURLRef)URL, NULL);
    if (!source) {
        journal(@"SOURCE_OPEN_FAILED");
        return NO;
    }
    size_t count = CGImageSourceGetCount(source);
    journal([NSString stringWithFormat:@"SOURCE_OPENED count=%zu", count]);
    BOOL ok = YES;
    for (size_t index = 0; index < count; index++) {
        journal([NSString stringWithFormat:@"BEFORE_DECODE_IMAGE index=%zu", index]);
        CGImageRef image = CGImageSourceCreateImageAtIndex(source, index, NULL);
        ok = renderImage(image, "image", index) && ok;
        if (image) CGImageRelease(image);
        journal([NSString stringWithFormat:@"BEFORE_DECODE_THUMBNAIL index=%zu", index]);
        NSDictionary *options = @{
            (NSString *)kCGImageSourceCreateThumbnailWithTransform: @YES,
            (NSString *)kCGImageSourceThumbnailMaxPixelSize: @256,
            (NSString *)kCGImageSourceCreateThumbnailFromImageAlways: @YES
        };
        CGImageRef thumbnail = CGImageSourceCreateThumbnailAtIndex(source, index, (__bridge CFDictionaryRef)options);
        ok = renderImage(thumbnail, "thumbnail", index) && ok;
        if (thumbnail) CGImageRelease(thumbnail);
    }
    CFRelease(source);
    return ok;
}

static NSString *sha256(NSData *data) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:sizeof(digest) * 2];
    for (size_t index = 0; index < sizeof(digest); index++) [result appendFormat:@"%02x", digest[index]];
    return result;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 3 || (strcmp(argv[2], "armed") && strcmp(argv[2], "control"))) {
            fprintf(stderr, "usage: %s OUTPUT_DIRECTORY armed|control\n", argv[0]);
            return 2;
        }
        BOOL armed = strcmp(argv[2], "armed") == 0;
        NSString *directory = @(argv[1]);
        NSString *identifier = armed ? @"armed" : @"control";
        NSString *HEICPath = [directory stringByAppendingPathComponent:
                              [NSString stringWithFormat:@"heic112621-%@.heic", identifier]];
        NSString *journalPath = [directory stringByAppendingPathComponent:
                                 [NSString stringWithFormat:@"heic112621-%@-journal.log", identifier]];
        [[NSFileManager defaultManager] removeItemAtPath:HEICPath error:nil];
        [[NSFileManager defaultManager] removeItemAtPath:journalPath error:nil];
        gJournalFD = open(journalPath.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (gJournalFD < 0) {
            fprintf(stderr, "open %s: %s\n", journalPath.fileSystemRepresentation, strerror(errno));
            return 3;
        }
        size_t heights[] = {16, armed ? 48 : 16};
        uint32_t colors[] = {0xFF202020u, 0xFFADBEEFu};
        journal([NSString stringWithFormat:@"BEGIN mode=%@ width=256 heights=%zu,%zu markers=0x%08x,0x%08x os=%@",
                  identifier, heights[0], heights[1], colors[0], colors[1],
                  NSProcessInfo.processInfo.operatingSystemVersionString]);
        if (!armSignals()) {
            journal(@"END result=SIGNAL_SETUP_FAILED");
            close(gJournalFD);
            return 4;
        }
        NSURL *URL = [NSURL fileURLWithPath:HEICPath];
        CGImageDestinationRef destination = CGImageDestinationCreateWithURL(
            (__bridge CFURLRef)URL, CFSTR("public.heic"), 2, NULL);
        if (!destination) {
            journal(@"END result=DESTINATION_CREATE_FAILED");
            close(gJournalFD);
            return 5;
        }
        journal(@"DESTINATION_CREATED type=public.heic count=2");
        BOOL ok = YES;
        NSDictionary *options = @{(NSString *)kCGImageDestinationLossyCompressionQuality: @1.0};
        for (size_t index = 0; index < 2; index++) {
            journal([NSString stringWithFormat:@"BEFORE_ADD_IMAGE index=%zu height=%zu", index, heights[index]]);
            CGImageRef frame = makeFrame(heights[index], colors[index]);
            if (!frame) {
                journal([NSString stringWithFormat:@"FRAME_CREATE_FAILED index=%zu", index]);
                ok = NO;
                break;
            }
            CGImageDestinationAddImage(destination, frame, (__bridge CFDictionaryRef)options);
            CGImageRelease(frame);
            journal([NSString stringWithFormat:@"AFTER_ADD_IMAGE index=%zu", index]);
        }
        if (ok) {
            journal(@"BEFORE_FINALIZE");
            ok = CGImageDestinationFinalize(destination);
            journal([NSString stringWithFormat:@"AFTER_FINALIZE ok=%d", ok]);
        }
        CFRelease(destination);
        NSData *data = nil;
        if (ok) {
            data = [NSData dataWithContentsOfURL:URL];
            if (!data) {
                ok = NO;
                journal(@"READ_BACK_FAILED");
            } else {
                journal([NSString stringWithFormat:@"HEIC_READY bytes=%llu sha256=%@",
                          (unsigned long long)data.length, sha256(data)]);
            }
        }
        if (ok) ok = decodeCollection(URL);
        journal([NSString stringWithFormat:@"END mode=%@ result=%@", identifier, ok ? @"SURVIVED" : @"FAILED"]);
        close(gJournalFD);
        printf("mode=%s result=%s heic=%s journal=%s\n", armed ? "armed" : "control",
               ok ? "SURVIVED" : "FAILED", HEICPath.fileSystemRepresentation, journalPath.fileSystemRepresentation);
        return ok ? 0 : 1;
    }
}
