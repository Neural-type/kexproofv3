#import "KPAVE112705ProbeModule.h"

#import "KPLog.h"

#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <VideoToolbox/VideoToolbox.h>
#import <errno.h>
#import <fcntl.h>
#import <string.h>
#import <unistd.h>

#ifndef KP_AVE112705_ENABLE_ARMED
#define KP_AVE112705_ENABLE_ARMED 0
#endif

@interface KPAVE112705ProbeModule ()
@end

@implementation KPAVE112705ProbeModule

- (instancetype)initWithTemporalLayers:(NSUInteger)temporalLayers {
    self = [super init];
    if (self) {
        _temporalLayers = temporalLayers;
        _armed = temporalLayers >= 16462;
        _identifier = [NSString stringWithFormat:@"ave112705.ntl-%lu", (unsigned long)temporalLayers];
        if (temporalLayers == 16463) {
            _title = @"AVE 112705 NTL 16463";
            _subtitle = @"Explicit tap · HEVC 1280x720 · first encode may panic AppleAVE2";
            _icon = @"exclamationmark.triangle";
        } else if (temporalLayers == 16462) {
            _title = @"AVE NTL Threshold 16462";
            _subtitle = @"Explicit tap · HEVC 1280x720 · boundary-first encode";
            _icon = @"video";
        } else {
            _title = [NSString stringWithFormat:@"AVE NTL Baseline %lu", (unsigned long)temporalLayers];
            _subtitle = @"HEVC 1280x720 · safe first-encode baseline";
            _icon = @"video";
        }
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

static BOOL KPAVEWriteFD(int fd, const void *bytes, size_t length) {
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

static BOOL KPAVEJournalLine(int fd, NSString *line) {
    NSData *data = [[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    return KPAVEWriteFD(fd, data.bytes, data.length) && fsync(fd) == 0;
}

static NSString *KPAVEJournalPath(NSUInteger temporalLayers) {
    return [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"] stringByAppendingPathComponent:
            [NSString stringWithFormat:@"kexproofv3-ave112705-ntl-%lu-journal.log", (unsigned long)temporalLayers]];
}

static void KPAVELogSetStatus(int journalFD, NSString *key, OSStatus status) {
    KPAVEJournalLine(journalFD, [NSString stringWithFormat:@"AFTER_SET key=%@ status=%d", key, status]);
}

static NSString *KPAVEStop(int journalFD, VTCompressionSessionRef session, CVPixelBufferRef pixel,
                           OSStatus status, NSString *stage, NSMutableString *report) {
    if (pixel) CVPixelBufferRelease(pixel);
    if (session) {
        VTCompressionSessionInvalidate(session);
        CFRelease(session);
    }
    KPAVEJournalLine(journalFD, [NSString stringWithFormat:@"END result=FAILED stage=%@ status=%d", stage, status]);
    close(journalFD);
    [report appendFormat:@"result=FAILED stage=%@ status=%d\n", stage, status];
    return report;
}

- (NSString *)runProbe {
    NSMutableString *report = [NSMutableString string];
    NSUInteger temporalLayers = self.temporalLayers;
    NSString *journalPath = KPAVEJournalPath(temporalLayers);
    NSString *documents = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSError *error = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:documents withIntermediateDirectories:YES attributes:nil error:&error];
    int journalFD = open(journalPath.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (journalFD < 0) {
        return [NSString stringWithFormat:@"JOURNAL SETUP FAILED: %s; no session was created.\n", strerror(errno)];
    }
    [report appendFormat:@"=== KexProofV3 AVE 112705 NTL %lu ===\nDevice OS: %@\nJournal: %@\n",
     (unsigned long)temporalLayers, NSProcessInfo.processInfo.operatingSystemVersionString, journalPath];
    KPAVEJournalLine(journalFD, [NSString stringWithFormat:
                                  @"BEGIN id=ave112705 ntl=%lu width=1280 height=720 codec=hvc1 encoderUsage=1 rcMode=20 realTime=false os=%@",
                                  (unsigned long)temporalLayers, NSProcessInfo.processInfo.operatingSystemVersionString]);

    VTCompressionSessionRef session = NULL;
    CVPixelBufferRef pixel = NULL;
    KPAVEJournalLine(journalFD, @"BEFORE_CREATE codec=hvc1 width=1280 height=720");
    OSStatus status = VTCompressionSessionCreate(kCFAllocatorDefault, 1280, 720, kCMVideoCodecType_HEVC,
                                                 NULL, NULL, NULL, NULL, NULL, &session);
    KPAVEJournalLine(journalFD, [NSString stringWithFormat:@"AFTER_CREATE status=%d session=%p", status, session]);
    if (status != 0 || !session) return KPAVEStop(journalFD, session, pixel, status, @"CREATE", report);

    KPAVEJournalLine(journalFD, @"BEFORE_SET key=EncoderUsage value=1");
    status = VTSessionSetProperty(session, CFSTR("EncoderUsage"), (__bridge CFTypeRef)@(1));
    KPAVELogSetStatus(journalFD, @"EncoderUsage", status);
    if (status != 0) return KPAVEStop(journalFD, session, pixel, status, @"SET_EncoderUsage", report);

    KPAVEJournalLine(journalFD, @"BEFORE_SET key=RCMode value=20");
    status = VTSessionSetProperty(session, CFSTR("RCMode"), (__bridge CFTypeRef)@(20));
    KPAVELogSetStatus(journalFD, @"RCMode", status);
    if (status != 0) return KPAVEStop(journalFD, session, pixel, status, @"SET_RCMode", report);

    KPAVEJournalLine(journalFD, @"BEFORE_SET key=RealTime value=false");
    status = VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
    KPAVELogSetStatus(journalFD, @"RealTime", status);
    if (status != 0) return KPAVEStop(journalFD, session, pixel, status, @"SET_RealTime", report);

    KPAVEJournalLine(journalFD, [NSString stringWithFormat:@"BEFORE_SET key=NumberOfTemporalLayers value=%lu",
                                  (unsigned long)temporalLayers]);
    status = VTSessionSetProperty(session, CFSTR("NumberOfTemporalLayers"), (__bridge CFTypeRef)@(temporalLayers));
    KPAVELogSetStatus(journalFD, @"NumberOfTemporalLayers", status);
    CFTypeRef readback = NULL;
    OSStatus readbackStatus = VTSessionCopyProperty(session, CFSTR("NumberOfTemporalLayers"), kCFAllocatorDefault, &readback);
    if (readback) {
        KPAVEJournalLine(journalFD, [NSString stringWithFormat:@"READBACK key=NumberOfTemporalLayers status=%d value=%@", readbackStatus, readback]);
        CFRelease(readback);
    } else {
        KPAVEJournalLine(journalFD, [NSString stringWithFormat:@"READBACK key=NumberOfTemporalLayers status=%d value=NULL", readbackStatus]);
    }
    if (status != 0) return KPAVEStop(journalFD, session, pixel, status, @"SET_NumberOfTemporalLayers", report);

    NSDictionary *attributes = @{(NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{}};
    KPAVEJournalLine(journalFD, @"BEFORE_PIXEL_CREATE format=420YpCbCr8BiPlanarVideoRange width=1280 height=720");
    status = CVPixelBufferCreate(kCFAllocatorDefault, 1280, 720, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
                                 (__bridge CFDictionaryRef)attributes, &pixel);
    KPAVEJournalLine(journalFD, [NSString stringWithFormat:@"AFTER_PIXEL_CREATE status=%d pixel=%p", status, pixel]);
    if (status != 0 || !pixel) return KPAVEStop(journalFD, session, pixel, status, @"PIXEL_CREATE", report);

    status = CVPixelBufferLockBaseAddress(pixel, 0);
    KPAVEJournalLine(journalFD, [NSString stringWithFormat:@"AFTER_PIXEL_LOCK status=%d", status]);
    if (status != 0) return KPAVEStop(journalFD, session, pixel, status, @"PIXEL_LOCK", report);
    size_t planeCount = CVPixelBufferGetPlaneCount(pixel);
    for (size_t plane = 0; plane < planeCount; plane++) {
        size_t height = CVPixelBufferGetHeightOfPlane(pixel, plane);
        size_t rowBytes = CVPixelBufferGetBytesPerRowOfPlane(pixel, plane);
        void *base = CVPixelBufferGetBaseAddressOfPlane(pixel, plane);
        if (!base) {
            CVPixelBufferUnlockBaseAddress(pixel, 0);
            return KPAVEStop(journalFD, session, pixel, -1, @"PIXEL_BASE", report);
        }
        memset(base, plane == 0 ? 0x40 : 0x80, height * rowBytes);
        KPAVEJournalLine(journalFD, [NSString stringWithFormat:@"FILLED_PLANE index=%zu height=%zu rowBytes=%zu fill=0x%02x",
                                      plane, height, rowBytes, plane == 0 ? 0x40 : 0x80]);
    }
    status = CVPixelBufferUnlockBaseAddress(pixel, 0);
    KPAVEJournalLine(journalFD, [NSString stringWithFormat:@"AFTER_PIXEL_UNLOCK status=%d", status]);
    if (status != 0) return KPAVEStop(journalFD, session, pixel, status, @"PIXEL_UNLOCK", report);

    KPAVEJournalLine(journalFD, [NSString stringWithFormat:@"BEFORE_ENCODE index=0 ntl=%lu pts=0/30", (unsigned long)temporalLayers]);
    status = VTCompressionSessionEncodeFrameWithOutputHandler(
        session, pixel, CMTimeMake(0, 30), kCMTimeInvalid, NULL, NULL,
        ^(OSStatus callbackStatus, VTEncodeInfoFlags infoFlags, CMSampleBufferRef sampleBuffer) {
            (void)callbackStatus;
            (void)infoFlags;
            (void)sampleBuffer;
        });
    KPAVEJournalLine(journalFD, [NSString stringWithFormat:@"AFTER_ENCODE index=0 status=%d", status]);
    if (status != 0) return KPAVEStop(journalFD, session, pixel, status, @"ENCODE", report);

    KPAVEJournalLine(journalFD, @"BEFORE_COMPLETE_FRAMES");
    status = VTCompressionSessionCompleteFrames(session, kCMTimeInvalid);
    KPAVEJournalLine(journalFD, [NSString stringWithFormat:@"AFTER_COMPLETE_FRAMES status=%d", status]);
    if (status != 0) return KPAVEStop(journalFD, session, pixel, status, @"COMPLETE_FRAMES", report);

    VTCompressionSessionInvalidate(session);
    CFRelease(session);
    CVPixelBufferRelease(pixel);
    KPAVEJournalLine(journalFD, [NSString stringWithFormat:@"END result=SURVIVED ntl=%lu encodeStatus=0", (unsigned long)temporalLayers]);
    close(journalFD);
    [report appendString:@"result=SURVIVED encodeStatus=0\n"];
    return report;
}

- (NSString *)runReport {
#if KP_AVE112705_ENABLE_ARMED
    return [self runProbe];
#else
    if (self.isArmed) {
        return @"Armed execution was NOT COMPILED. KP_AVE112705_ENABLE_ARMED=1 is required; no session was created.\n";
    }
    return [self runProbe];
#endif
}

@end
