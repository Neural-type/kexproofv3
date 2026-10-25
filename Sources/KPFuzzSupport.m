#import "KPFuzzSupport.h"

#import <UIKit/UIKit.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

static const uint64_t KPFuzzBoundaries[] = {
    0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff,
    0x8000, 0xffff, 0x10000, 0x7fffffff,
    0x80000000ULL, 0xffffffffULL, 0x40000000ULL
};

static const size_t KPFuzzVariableLengths[] = {
    0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 65,
    127, 128, 255, 256, 511, 512, 1024, 2048, 4096
};

static uint32_t KPFuzzGet32(const uint8_t *bytes, size_t offset) {
    uint32_t value = 0;
    memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

static uint64_t KPFuzzGet64(const uint8_t *bytes, size_t offset) {
    uint64_t value = 0;
    memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

static void KPFuzzPut32(uint8_t *bytes, size_t offset, uint32_t value) {
    memcpy(bytes + offset, &value, sizeof(value));
}

static void KPFuzzPut64(uint8_t *bytes, size_t offset, uint64_t value) {
    memcpy(bytes + offset, &value, sizeof(value));
}

static uint64_t KPFuzzSplitMix64(uint64_t value) {
    value += 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}

static uint64_t KPFuzzNext(uint64_t *state) {
    uint64_t value = *state;
    value ^= value >> 12;
    value ^= value << 25;
    value ^= value >> 27;
    *state = value;
    return value * 0x2545f4914f6cdd1dULL;
}

uint64_t KPFuzzCallSeed(uint64_t runSeed, NSUInteger planIndex, uint32_t iteration) {
    uint64_t mixed = runSeed ^ ((uint64_t)planIndex << 32) ^ ((uint64_t)iteration << 1);
    return KPFuzzSplitMix64(mixed + 0x6b705f75657a0000ULL);
}

static uint64_t KPFuzzHashBytes(const void *bytes, size_t length, uint64_t hash) {
    const uint8_t *data = bytes;
    for (size_t index = 0; index < length; index++) {
        hash ^= data[index];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

uint64_t KPFuzzCallHash(const KPFuzzCall *call) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    hash = KPFuzzHashBytes(call->scalarInput, call->scalarInputCount * sizeof(uint64_t), hash);
    return KPFuzzHashBytes(call->structInput, call->structInputCount, hash);
}

static NSString *KPFuzzHex(const void *bytes, size_t length) {
    if (!bytes || !length) return @"-";
    const uint8_t *data = bytes;
    NSMutableString *result = [NSMutableString stringWithCapacity:length * 2 + 1];
    for (size_t index = 0; index < length; index++) {
        [result appendFormat:@"%02x", data[index]];
    }
    return result;
}

static BOOL KPFuzzWriteAll(int descriptor, NSString *text) {
    if (descriptor < 0) return NO;
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    size_t offset = 0;
    while (offset < data.length) {
        ssize_t written = write(descriptor, data.bytes + offset, data.length - offset);
        if (written <= 0) return NO;
        offset += (size_t)written;
    }
    return YES;
}

BOOL KPFuzzReproStart(KPFuzzRepro *repro, uint64_t runSeed, NSError **error) {
    if (!repro) return NO;
    memset((void *)repro, 0, sizeof(*repro));
    repro->descriptor = -1;
    NSString *documents = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    if (![[NSFileManager defaultManager] createDirectoryAtPath:documents
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:error]) {
        return NO;
    }
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    formatter.dateFormat = @"yyyyMMdd-HHmmss-SSS";
    NSString *name = [NSString stringWithFormat:@"kexproofv3-fuzzer-%@-%016llx.log",
                      [formatter stringFromDate:[NSDate date]], runSeed];
    repro->path = [documents stringByAppendingPathComponent:name];
    repro->descriptor = open(repro->path.fileSystemRepresentation,
                             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (repro->descriptor < 0) {
        if (error) {
            *error = [NSError errorWithDomain:NSPOSIXErrorDomain
                                         code:errno
                                     userInfo:@{NSLocalizedDescriptionKey: @(strerror(errno))}];
        }
        return NO;
    }
    NSString *header = [NSString stringWithFormat:
                        @"=== KexProofV3 IOKit fuzzer ===\nversion=%@ target=iOS 27.0.1\nrunSeed=0x%016llx\n%@\n",
                        KPFuzzBuildVersion, runSeed, KPFuzzPlanSummary()];
    if (!KPFuzzWriteAll(repro->descriptor, header) || fsync(repro->descriptor) != 0) {
        KPFuzzReproFinish(repro);
        if (error) {
            *error = [NSError errorWithDomain:NSPOSIXErrorDomain
                                         code:errno
                                     userInfo:@{NSLocalizedDescriptionKey: @(strerror(errno))}];
        }
        return NO;
    }
    return YES;
}

void KPFuzzReproFinish(KPFuzzRepro *repro) {
    if (!repro) return;
    if (repro->descriptor >= 0) {
        fsync(repro->descriptor);
        close(repro->descriptor);
        repro->descriptor = -1;
    }
}

static kern_return_t KPFuzzOpenSimple(const char *serviceName, uint32_t type, io_connect_t *connection) {
    if (!connection) return kIOReturnBadArgument;
    *connection = IO_OBJECT_NULL;
    io_service_t service = IOServiceGetMatchingService(MACH_PORT_NULL,
                                                        IOServiceMatching(serviceName));
    if (service == IO_OBJECT_NULL) return kIOReturnNoDevice;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), type, connection);
    IOObjectRelease(service);
    if (kr == KERN_SUCCESS && *connection == IO_OBJECT_NULL) return kIOReturnNoDevice;
    return kr;
}

static kern_return_t KPFuzzOpenAGX(io_connect_t *connection) {
    static const char *names[] = {"IOGPU", "IOGPUDevice", "AGXDevice"};
    static const uint32_t firstTypes[] = {1, 0, 0};
    *connection = IO_OBJECT_NULL;
    kern_return_t lastError = kIOReturnNoDevice;
    for (uint32_t nameIndex = 0; nameIndex < 3; nameIndex++) {
        for (uint32_t typeIndex = 0; typeIndex < 2; typeIndex++) {
            uint32_t type = (firstTypes[nameIndex] + typeIndex) & 1;
            io_connect_t candidate = IO_OBJECT_NULL;
            kern_return_t kr = KPFuzzOpenSimple(names[nameIndex], type, &candidate);
            if (kr == KERN_SUCCESS && candidate != IO_OBJECT_NULL) {
                *connection = candidate;
                return KERN_SUCCESS;
            }
            if (candidate != IO_OBJECT_NULL) IOServiceClose(candidate);
            lastError = kr;
        }
    }
    return lastError;
}

static kern_return_t KPFuzzOpenFamily(KPFuzzFamily family, io_service_t fastPathService, io_connect_t *connection) {
    *connection = IO_OBJECT_NULL;
    if (family == KPFuzzFamilyIOGPU) return KPFuzzOpenAGX(connection);
    if (family == KPFuzzFamilyFastPath) {
        if (fastPathService == IO_OBJECT_NULL) return kIOReturnNoDevice;
        kern_return_t kr = IOServiceOpen(fastPathService, mach_task_self(), 2, connection);
        if (kr == KERN_SUCCESS && *connection == IO_OBJECT_NULL) return kIOReturnNoDevice;
        return kr;
    }
    return KPFuzzOpenSimple(KPFuzzFamilyService(family).UTF8String,
                            KPFuzzFamilyOpenType(family), connection);
}

typedef struct {
    uint64_t address;
    uint32_t width;
    uint32_t height;
    uint32_t pixelFormat;
    uint32_t bytesPerElement;
    uint32_t bytesPerRow;
    uint32_t allocSize;
} KPFuzzFastCreateArgs;

_Static_assert(sizeof(KPFuzzFastCreateArgs) == 0x20, "fast-create ABI");

static kern_return_t KPFuzzCreateSurface(io_connect_t connection,
                                         uint32_t width,
                                         uint32_t height,
                                         uint32_t *surfaceID) {
    KPFuzzFastCreateArgs args;
    memset(&args, 0, sizeof(args));
    args.width = width;
    args.height = height;
    args.pixelFormat = 0x42475241;
    args.bytesPerElement = 4;
    args.bytesPerRow = width * 4;
    args.allocSize = width * height * 4;
    uint8_t output[0xc68] = {0};
    size_t outputSize = sizeof(output);
    *surfaceID = 0;
    kern_return_t kr = IOConnectCallMethod(connection, 6,
                                           NULL, 0,
                                           &args, sizeof(args),
                                           NULL, NULL,
                                           output, &outputSize);
    if (kr == KERN_SUCCESS && outputSize >= 0x1c) {
        memcpy(surfaceID, output + 0x18, sizeof(*surfaceID));
        if (*surfaceID == 0) return kIOReturnError;
    } else if (kr == KERN_SUCCESS) {
        return kIOReturnUnderrun;
    }
    return kr;
}

static void KPFuzzReleaseSurface(io_connect_t connection, uint32_t surfaceID) {
    if (connection == IO_OBJECT_NULL || !surfaceID) return;
    uint64_t input = surfaceID;
    IOConnectCallMethod(connection, 1, &input, 1, NULL, 0,
                        NULL, NULL, NULL, NULL);
}

static kern_return_t KPFuzzAGXCreateQueue(KPFuzzSession *session) {
    uint8_t input[0x410] = {0};
    uint8_t output[0x10] = {0};
    size_t outputSize = sizeof(output);
    kern_return_t kr = IOConnectCallMethod(session->connection, 6,
                                           NULL, 0,
                                           input, sizeof(input),
                                           NULL, NULL,
                                           output, &outputSize);
    if (kr == KERN_SUCCESS) {
        session->queueID = KPFuzzGet32(output, 0);
        if (outputSize != sizeof(output) || !session->queueID) return kIOReturnError;
    }
    return kr;
}

static kern_return_t KPFuzzAGXCreateNotification(KPFuzzSession *session) {
    uint64_t scalars[] = {256, 32};
    uint8_t output[0x10] = {0};
    size_t outputSize = sizeof(output);
    kern_return_t kr = IOConnectCallMethod(session->connection, 14,
                                           scalars, 2,
                                           NULL, 0,
                                           NULL, NULL,
                                           output, &outputSize);
    if (kr == KERN_SUCCESS) {
        session->notificationID = KPFuzzGet32(output, 8);
        if (outputSize != sizeof(output) || !session->notificationID) return kIOReturnError;
    }
    return kr;
}

static kern_return_t KPFuzzAGXCreateShmem(KPFuzzSession *session, KPFuzzShmem *shmem) {
    memset(shmem, 0, sizeof(*shmem));
    uint64_t scalars[] = {0x4000, 0};
    uint8_t output[0x10] = {0};
    size_t outputSize = sizeof(output);
    kern_return_t kr = IOConnectCallMethod(session->connection, 12,
                                           scalars, 2,
                                           NULL, 0,
                                           NULL, NULL,
                                           output, &outputSize);
    if (kr == KERN_SUCCESS) {
        shmem->address = KPFuzzGet64(output, 0);
        shmem->size = KPFuzzGet32(output, 8);
        shmem->identifier = KPFuzzGet32(output, 12);
        if (outputSize != sizeof(output) || !shmem->identifier ||
            !shmem->address || shmem->size < 0x4000) {
            return kIOReturnError;
        }
    }
    return kr;
}

static kern_return_t KPFuzzAGXBindNotification(KPFuzzSession *session) {
    uint64_t scalars[] = {session->queueID, session->notificationID};
    return IOConnectCallMethod(session->connection, 24,
                               scalars, 2,
                               NULL, 0,
                               NULL, NULL, NULL, NULL);
}

static kern_return_t KPFuzzCreateJPEGSurfaces(KPFuzzSession *session, NSMutableString *report) {
    UIGraphicsBeginImageContext(CGSizeMake(16, 16));
    [UIColor.redColor setFill];
    UIRectFill(CGRectMake(0, 0, 16, 16));
    UIImage *image = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    NSData *jpeg = UIImageJPEGRepresentation(image, 0.9);
    if (!jpeg.length) return kIOReturnNoResources;
    size_t allocationLength = (jpeg.length + 0x3fff) & ~0x3fffUL;
    NSDictionary *sourceProperties = @{
        (id)kIOSurfaceWidth: @(allocationLength),
        (id)kIOSurfaceHeight: @1,
        (id)kIOSurfaceBytesPerElement: @1,
        (id)kIOSurfacePixelFormat: @0x20202020
    };
    NSDictionary *destProperties = @{
        (id)kIOSurfaceWidth: @64,
        (id)kIOSurfaceHeight: @64,
        (id)kIOSurfaceBytesPerElement: @4,
        (id)kIOSurfacePixelFormat: @0x42475241
    };
    IOSurfaceRef source = IOSurfaceCreate((__bridge CFDictionaryRef)sourceProperties);
    IOSurfaceRef dest = IOSurfaceCreate((__bridge CFDictionaryRef)destProperties);
    if (!source || !dest) {
        if (source) CFRelease(source);
        if (dest) CFRelease(dest);
        return kIOReturnNoResources;
    }
    IOSurfaceLock(source, 0, NULL);
    void *base = IOSurfaceGetBaseAddress(source);
    if (base) memcpy(base, jpeg.bytes, jpeg.length);
    IOSurfaceUnlock(source, 0, NULL);
    if (!base) {
        CFRelease(source);
        CFRelease(dest);
        return kIOReturnNoResources;
    }
    session->jpegSource = source;
    session->jpegDest = dest;
    session->jpegData = jpeg;
    session->jpegByteCount = (uint32_t)jpeg.length;
    session->sourceID = IOSurfaceGetID(source);
    session->destID = IOSurfaceGetID(dest);
    if (!session->sourceID || !session->destID) return kIOReturnError;
    [report appendFormat:@"  JPEG baseline: source=%u dest=%u bytes=%zu dimensions=64x64 async=0\n",
     session->sourceID, session->destID, jpeg.length];
    return KERN_SUCCESS;
}

static kern_return_t KPFuzzFastPathOpenGate(io_connect_t connection) {
    static const char xml[] =
        "<dict>"
        "<key>FastPathHasEntitlement</key><true/>"
        "<key>FastPathMotionEventEntitlement</key><true/>"
        "</dict>";
    uint64_t scalar = 0;
    return IOConnectCallMethod(connection, 0,
                               &scalar, 1,
                               (void *)xml, sizeof(xml),
                               NULL, NULL, NULL, NULL);
}

kern_return_t KPFuzzFastPathSelectService(io_service_t *selectedService, uint32_t *selectedIndex, NSMutableString *report) {
    if (!selectedService) return kIOReturnBadArgument;
    *selectedService = IO_OBJECT_NULL;
    if (selectedIndex) *selectedIndex = 0;
    CFMutableDictionaryRef matching = IOServiceMatching("IOHIDEventService");
    if (!matching) return kIOReturnBadArgument;
    io_iterator_t iterator = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iterator);
    if (kr != KERN_SUCCESS || iterator == IO_OBJECT_NULL) {
        if (iterator != IO_OBJECT_NULL) IOObjectRelease(iterator);
        return kr == KERN_SUCCESS ? kIOReturnNoDevice : kr;
    }
    kern_return_t lastError = kIOReturnNoDevice;
    uint32_t tried = 0;
    io_service_t service = IO_OBJECT_NULL;
    while (tried < 32 && (service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        tried++;
        io_connect_t candidate = IO_OBJECT_NULL;
        kern_return_t openKR = IOServiceOpen(service, mach_task_self(), 2, &candidate);
        if (openKR == KERN_SUCCESS && candidate != IO_OBJECT_NULL) {
            kern_return_t gateKR = KPFuzzFastPathOpenGate(candidate);
            [report appendFormat:@"  setup: FastPath instance=%u baseline sel0 kr=0x%08x%s\n",
             tried, (uint32_t)gateKR,
             gateKR == kIOReturnExclusiveAccess ? " (exclusive/busy; trying next)" : ""];
            if (gateKR == KERN_SUCCESS) {
                IOServiceClose(candidate);
                *selectedService = service;
                if (selectedIndex) *selectedIndex = tried;
                IOObjectRelease(iterator);
                return KERN_SUCCESS;
            }
            lastError = gateKR;
        } else {
            lastError = openKR == KERN_SUCCESS ? kIOReturnNoDevice : openKR;
            [report appendFormat:@"  setup: FastPath instance=%u IOServiceOpen kr=0x%08x\n",
             tried, (uint32_t)lastError];
        }
        if (candidate != IO_OBJECT_NULL) IOServiceClose(candidate);
        IOObjectRelease(service);
    }
    IOObjectRelease(iterator);
    [report appendFormat:@"  setup: no FastPath baseline-capable service among %u instances, last kr=0x%08x\n",
     tried, (uint32_t)lastError];
    return lastError;
}

kern_return_t KPFuzzSessionStart(const KPFuzzSelectorPlan *plan, io_service_t fastPathService, KPFuzzSession *session, NSMutableString *report) {
    memset((void *)session, 0, sizeof(*session));
    kern_return_t kr = KPFuzzOpenFamily(plan->family, fastPathService, &session->connection);
    if (kr != KERN_SUCCESS || session->connection == IO_OBJECT_NULL) {
        [report appendFormat:@"  setup: open %s type=%u failed kr=0x%08x\n",
         KPFuzzFamilyService(plan->family).UTF8String,
         KPFuzzFamilyOpenType(plan->family), (uint32_t)kr];
        return kr == KERN_SUCCESS ? kIOReturnNoDevice : kr;
    }
    switch (plan->kind) {
        case KPFuzzSelectorAGXQueue:
        case KPFuzzSelectorAGXShmem:
        case KPFuzzSelectorAGXNotification:
        case KPFuzzSelectorIOSurfaceCreate:
            session->surfaceConnection = session->connection;
            return KERN_SUCCESS;
        case KPFuzzSelectorAGXSubmit:
            kr = KPFuzzAGXCreateQueue(session);
            if (kr == KERN_SUCCESS) kr = KPFuzzAGXCreateNotification(session);
            if (kr == KERN_SUCCESS) kr = KPFuzzAGXCreateShmem(session, &session->command);
            if (kr == KERN_SUCCESS) kr = KPFuzzAGXCreateShmem(session, &session->segments);
            if (kr == KERN_SUCCESS) kr = KPFuzzAGXBindNotification(session);
            break;
        case KPFuzzSelectorIOSurfaceIncrement:
        case KPFuzzSelectorIOSurfaceDecrement:
            session->surfaceConnection = session->connection;
            kr = KPFuzzCreateSurface(session->surfaceConnection, 64, 64, &session->surfaceID);
            break;
        case KPFuzzSelectorM2Submit:
        case KPFuzzSelectorM2Credit: {
            kr = KPFuzzOpenSimple("IOSurfaceRoot", 0, &session->surfaceConnection);
            if (kr != KERN_SUCCESS) break;
            kr = KPFuzzCreateSurface(session->surfaceConnection, 32, 32, &session->sourceID);
            if (kr == KERN_SUCCESS) {
                kr = KPFuzzCreateSurface(session->surfaceConnection, 32, 32, &session->destID);
            }
            break;
        }
        case KPFuzzSelectorIOMFBScalar:
        case KPFuzzSelectorFastPathOpen:
            return KERN_SUCCESS;
        case KPFuzzSelectorFastPathCopy:
            kr = KPFuzzFastPathOpenGate(session->connection);
            break;
        case KPFuzzSelectorJPEGDecode:
        case KPFuzzSelectorJPEGEncode:
            kr = KPFuzzCreateJPEGSurfaces(session, report);
            break;
    }
    if (kr != KERN_SUCCESS) {
        [report appendFormat:@"  setup: baseline for %s sel=%u failed kr=0x%08x\n",
         KPFuzzSelectorKindName(plan->kind).UTF8String, plan->selector, (uint32_t)kr];
        KPFuzzSessionEnd(plan, session);
    }
    return kr;
}

void KPFuzzSessionEnd(const KPFuzzSelectorPlan *plan, KPFuzzSession *session) {
    switch (plan->kind) {
        case KPFuzzSelectorAGXQueue:
        case KPFuzzSelectorAGXShmem:
        case KPFuzzSelectorAGXNotification:
        case KPFuzzSelectorAGXSubmit:
        case KPFuzzSelectorIOMFBScalar:
        case KPFuzzSelectorFastPathOpen:
        case KPFuzzSelectorFastPathCopy:
            break;
        case KPFuzzSelectorIOSurfaceCreate:
        case KPFuzzSelectorIOSurfaceIncrement:
        case KPFuzzSelectorIOSurfaceDecrement:
            KPFuzzReleaseSurface(session->surfaceConnection, session->surfaceID);
            session->surfaceID = 0;
            break;
        case KPFuzzSelectorM2Submit:
        case KPFuzzSelectorM2Credit:
            KPFuzzReleaseSurface(session->surfaceConnection, session->sourceID);
            KPFuzzReleaseSurface(session->surfaceConnection, session->destID);
            session->sourceID = 0;
            session->destID = 0;
            break;
        case KPFuzzSelectorJPEGDecode:
        case KPFuzzSelectorJPEGEncode:
            if (session->jpegSource) CFRelease(session->jpegSource);
            if (session->jpegDest) CFRelease(session->jpegDest);
            session->jpegSource = NULL;
            session->jpegDest = NULL;
            session->jpegData = nil;
            break;
    }
    if (session->surfaceConnection != IO_OBJECT_NULL &&
        session->surfaceConnection != session->connection) {
        IOServiceClose(session->surfaceConnection);
    }
    if (session->connection != IO_OBJECT_NULL) IOServiceClose(session->connection);
    session->surfaceConnection = IO_OBJECT_NULL;
    session->connection = IO_OBJECT_NULL;
}

typedef struct {
    size_t offset;
    size_t length;
} KPFuzzRange;

static BOOL KPFuzzRangeAllows(size_t offset, size_t width, const KPFuzzRange *ranges, size_t rangeCount) {
    if (offset > SIZE_MAX - width) return NO;
    for (size_t index = 0; index < rangeCount; index++) {
        size_t start = ranges[index].offset;
        size_t end = start + ranges[index].length;
        if (offset < end && offset + width > start) return NO;
    }
    return YES;
}

static size_t KPFuzzMutableOffset(size_t length, size_t width, uint64_t *state,
                                  const KPFuzzRange *ranges, size_t rangeCount) {
    if (length < width || !width) return SIZE_MAX;
    for (uint32_t attempt = 0; attempt < 32; attempt++) {
        size_t offset = (size_t)(KPFuzzNext(state) % (length - width + 1));
        if (KPFuzzRangeAllows(offset, width, ranges, rangeCount)) return offset;
    }
    return SIZE_MAX;
}

static void KPFuzzMutateBuffer(KPFuzzCall *call, uint64_t *state,
                               const KPFuzzRange *ranges, size_t rangeCount,
                               BOOL variableLength, uint32_t iteration) {
    uint32_t mode = iteration & 7;
    size_t length = call->structInputCount;
    if (variableLength && mode == 5) {
        if (length) {
            size_t choice = KPFuzzVariableLengths[KPFuzzNext(state) %
                            (sizeof(KPFuzzVariableLengths) / sizeof(KPFuzzVariableLengths[0]))];
            if (choice < length) call->structInputCount = choice;
        }
        return;
    }
    if (variableLength && mode == 6) {
        size_t choices[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048};
        size_t increment = choices[KPFuzzNext(state) % (sizeof(choices) / sizeof(choices[0]))];
        size_t newLength = length > KPFuzzMaxStructSize - increment ? KPFuzzMaxStructSize : length + increment;
        for (size_t index = length; index < newLength; index++) call->structInput[index] = (uint8_t)KPFuzzNext(state);
        call->structInputCount = newLength;
        return;
    }
    if (variableLength && mode == 7) {
        size_t newLength = KPFuzzVariableLengths[KPFuzzNext(state) %
                          (sizeof(KPFuzzVariableLengths) / sizeof(KPFuzzVariableLengths[0]))];
        if (newLength > KPFuzzMaxStructSize) newLength = KPFuzzMaxStructSize;
        for (size_t index = length; index < newLength; index++) call->structInput[index] = (uint8_t)KPFuzzNext(state);
        call->structInputCount = newLength;
        return;
    }
    if (mode == 0) return;
    uint32_t changes = mode == 4 ? 1 + (uint32_t)(KPFuzzNext(state) % 4) : 1;
    for (uint32_t change = 0; change < changes; change++) {
        if (mode == 1 || mode == 4 || mode == 7) {
            size_t offset = KPFuzzMutableOffset(length, 1, state, ranges, rangeCount);
            if (offset != SIZE_MAX) call->structInput[offset] ^= (uint8_t)(1U << (KPFuzzNext(state) & 7));
        } else if (mode == 3) {
            size_t offset = KPFuzzMutableOffset(length, sizeof(uint64_t), state, ranges, rangeCount);
            if (offset != SIZE_MAX) {
                uint64_t value = KPFuzzBoundaries[KPFuzzNext(state) %
                                (sizeof(KPFuzzBoundaries) / sizeof(KPFuzzBoundaries[0]))];
                KPFuzzPut64(call->structInput, offset, value);
            }
        } else {
            size_t offset = KPFuzzMutableOffset(length, sizeof(uint32_t), state, ranges, rangeCount);
            if (offset != SIZE_MAX) {
                uint32_t value = (uint32_t)KPFuzzBoundaries[KPFuzzNext(state) %
                                (sizeof(KPFuzzBoundaries) / sizeof(KPFuzzBoundaries[0]))];
                KPFuzzPut32(call->structInput, offset, value);
            }
        }
    }
}

static void KPFuzzMutateScalars(KPFuzzCall *call, uint64_t *state, uint32_t preserveMask, uint32_t iteration) {
    for (uint32_t index = 0; index < call->scalarInputCount; index++) {
        if ((preserveMask & (1U << index)) || ((iteration + index) % 3 == 0)) continue;
        if (KPFuzzNext(state) & 1) {
            call->scalarInput[index] = KPFuzzBoundaries[KPFuzzNext(state) %
                                        (sizeof(KPFuzzBoundaries) / sizeof(KPFuzzBoundaries[0]))];
        } else {
            call->scalarInput[index] = KPFuzzNext(state);
        }
    }
}

static uint64_t KPFuzzSafeValue(uint64_t *state, const uint64_t *values, size_t count) {
    return values[KPFuzzNext(state) % count];
}

static void KPFuzzAGXFillBuffers(KPFuzzSession *session, uint32_t iteration) {
    uint8_t *command = (uint8_t *)(uintptr_t)session->command.address;
    uint8_t *segments = (uint8_t *)(uintptr_t)session->segments.address;
    memset(command, 0, 0x4000);
    memset(segments, 0, 0x4000);
    KPFuzzPut32(command, 0x00, 0x10000);
    KPFuzzPut32(command, 0x04, 0x330);
    KPFuzzPut32(command, 0xa4, 0x268);
    KPFuzzPut32(command, 0xa8, 3);
    uint8_t *cl = command + 0xc8;
    KPFuzzPut32(cl, 0x100, 15);
    KPFuzzPut32(cl, 0x104, 0);
    KPFuzzPut32(cl, 0x108, 0);
    static const uint32_t values[] = {0, 1, 2, 0x7f, 0x100};
    for (uint32_t index = 0; index < 15; index++) {
        uint64_t state = KPFuzzSplitMix64(iteration + index * 0x9e37);
        KPFuzzPut32(cl, 0x10c + 4 * index, values[state % (sizeof(values) / sizeof(values[0]))]);
    }
    KPFuzzPut64(cl, 0x148, 1);
    cl[0x1f5] = (iteration >> 3) & 3;
    KPFuzzPut32(cl, 0x254, 0xffffffff);
    KPFuzzPut32(segments, 0x08, 1);
    KPFuzzPut32(segments, 0x18, 0);
    KPFuzzPut32(segments, 0x1c, 0x330);
    KPFuzzPut32(segments, 0x20, 0);
    KPFuzzPut32(segments, 0x2c, 0);
}

static void KPFuzzApplyFieldPolicies(const KPFuzzSelectorPlan *plan,
                                     const KPFuzzSession *session,
                                     uint32_t iteration,
                                     uint64_t *state,
                                     KPFuzzCall *call) {
    static const uint64_t allocationSizes[] = {0, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x40000, 0x100000};
    static const uint64_t smallCounts[] = {0, 1, 2, 4, 8, 16, 32, 64, 128, 256};
    static const uint64_t dimensions[] = {0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 0x7f, 0x80, 0xff, 0x100};
    static const uint64_t elementSizes[] = {0, 1, 2, 4, 8, 0xff, 0x100};
    static const uint64_t subsampling[] = {0, 1, 3, 4};
    switch (plan->kind) {
        case KPFuzzSelectorAGXQueue:
        case KPFuzzSelectorM2Submit:
        case KPFuzzSelectorIOMFBScalar:
        case KPFuzzSelectorFastPathOpen:
            break;
        case KPFuzzSelectorAGXShmem:
            call->scalarInput[0] = KPFuzzSafeValue(state, allocationSizes,
                                                    sizeof(allocationSizes) / sizeof(allocationSizes[0]));
            call->scalarInput[1] = 0;
            break;
        case KPFuzzSelectorAGXNotification:
            call->scalarInput[0] = KPFuzzSafeValue(state, smallCounts,
                                                    sizeof(smallCounts) / sizeof(smallCounts[0]));
            call->scalarInput[1] = KPFuzzSafeValue(state, smallCounts,
                                                    sizeof(smallCounts) / sizeof(smallCounts[0]));
            break;
        case KPFuzzSelectorAGXSubmit:
            call->scalarInput[2] = iteration % 5 == 0 ? 1 : iteration % 3;
            call->scalarInput[3] = call->structInputCount;
            break;
        case KPFuzzSelectorIOSurfaceCreate:
            KPFuzzPut32(call->structInput, 8, (uint32_t)KPFuzzSafeValue(state, dimensions, sizeof(dimensions) / sizeof(dimensions[0])));
            KPFuzzPut32(call->structInput, 12, (uint32_t)KPFuzzSafeValue(state, dimensions, sizeof(dimensions) / sizeof(dimensions[0])));
            KPFuzzPut32(call->structInput, 20, (uint32_t)KPFuzzSafeValue(state, elementSizes, sizeof(elementSizes) / sizeof(elementSizes[0])));
            KPFuzzPut32(call->structInput, 24, (uint32_t)KPFuzzSafeValue(state, allocationSizes, sizeof(allocationSizes) / sizeof(allocationSizes[0])));
            KPFuzzPut32(call->structInput, 28, (uint32_t)KPFuzzSafeValue(state, allocationSizes, sizeof(allocationSizes) / sizeof(allocationSizes[0])));
            break;
        case KPFuzzSelectorIOSurfaceIncrement:
        case KPFuzzSelectorIOSurfaceDecrement:
            break;
        case KPFuzzSelectorM2Credit:
            KPFuzzPut32(call->structInput, 0, iteration % 4);
            break;
        case KPFuzzSelectorFastPathCopy:
            call->structOutputCapacity = KPFuzzVariableLengths[KPFuzzNext(state) %
                (sizeof(KPFuzzVariableLengths) / sizeof(KPFuzzVariableLengths[0]))];
            call->structOutputCount = call->structOutputCapacity;
            break;
        case KPFuzzSelectorJPEGDecode:
        case KPFuzzSelectorJPEGEncode: {
            uint32_t sourceSize = plan->kind == KPFuzzSelectorJPEGDecode ? session->jpegByteCount : 64 * 64 * 4;
            uint32_t destSize = plan->kind == KPFuzzSelectorJPEGDecode ? 64 * 64 * 4 : (uint32_t)IOSurfaceGetAllocSize(session->jpegSource);
            uint64_t sizes[] = {7, 8, 16, 32, 64, 128, sourceSize, destSize};
            KPFuzzPut32(call->structInput, 4, (uint32_t)KPFuzzSafeValue(state, sizes, sizeof(sizes) / sizeof(sizes[0])));
            KPFuzzPut32(call->structInput, 12, (uint32_t)KPFuzzSafeValue(state, sizes, sizeof(sizes) / sizeof(sizes[0])));
            KPFuzzPut32(call->structInput, 20, (uint32_t)KPFuzzSafeValue(state, dimensions, sizeof(dimensions) / sizeof(dimensions[0])));
            KPFuzzPut32(call->structInput, 24, (uint32_t)KPFuzzSafeValue(state, dimensions, sizeof(dimensions) / sizeof(dimensions[0])));
            KPFuzzPut32(call->structInput, 44, (uint32_t)KPFuzzSafeValue(state, subsampling, sizeof(subsampling) / sizeof(subsampling[0])));
            KPFuzzPut32(call->structInput, 76, (uint32_t)KPFuzzSafeValue(state, dimensions, sizeof(dimensions) / sizeof(dimensions[0])));
            KPFuzzPut32(call->structInput, 80, (uint32_t)KPFuzzSafeValue(state, dimensions, sizeof(dimensions) / sizeof(dimensions[0])));
            call->structInput[32] &= 7;
            break;
        }
    }
}

void KPFuzzPrepareCall(const KPFuzzSelectorPlan *plan, NSUInteger planIndex, const KPFuzzSession *session, uint32_t iteration, uint64_t runSeed, KPFuzzCall *call) {
    memset(call, 0, sizeof(*call));
    call->scalarInputCount = plan->scalarInputCount;
    call->structInputCount = plan->structInputSize;
    call->structOutputCapacity = plan->structOutputSize;
    call->structOutputCount = plan->structOutputSize;
    uint64_t state = KPFuzzCallSeed(runSeed, planIndex, iteration);
    uint32_t preserveMask = 0;
    KPFuzzRange ranges[4] = {{0, 0}};
    size_t rangeCount = 0;
    BOOL variableLength = NO;
    switch (plan->kind) {
        case KPFuzzSelectorAGXQueue:
            ranges[rangeCount++] = (KPFuzzRange){0x400, 0x10};
            variableLength = YES;
            break;
        case KPFuzzSelectorAGXShmem:
            call->scalarInput[0] = 0x4000;
            call->scalarInput[1] = 0;
            break;
        case KPFuzzSelectorAGXNotification:
            call->scalarInput[0] = 256;
            call->scalarInput[1] = 32;
            break;
        case KPFuzzSelectorAGXSubmit: {
            KPFuzzAGXFillBuffers((KPFuzzSession *)session, iteration);
            KPFuzzPut32(call->structInput, 0, session->command.identifier);
            KPFuzzPut32(call->structInput, 4, session->segments.identifier);
            KPFuzzPut32(call->structInput, 8, 0);
            call->scalarInput[0] = session->queueID;
            call->scalarInput[1] = 0;
            call->scalarInput[2] = 1;
            call->scalarInput[3] = 0x40;
            call->scalarOutputCount = 1;
            preserveMask = 1;
            ranges[rangeCount++] = (KPFuzzRange){0, 0x0c};
            variableLength = YES;
            break;
        }
        case KPFuzzSelectorIOSurfaceCreate: {
            KPFuzzFastCreateArgs *args = (KPFuzzFastCreateArgs *)call->structInput;
            args->width = 64;
            args->height = 64;
            args->pixelFormat = 0x42475241;
            args->bytesPerElement = 4;
            args->bytesPerRow = 256;
            args->allocSize = 0x4000;
            ranges[rangeCount++] = (KPFuzzRange){0, 8};
            ranges[rangeCount++] = (KPFuzzRange){16, 4};
            break;
        }
        case KPFuzzSelectorIOSurfaceIncrement:
        case KPFuzzSelectorIOSurfaceDecrement:
            call->scalarInput[0] = session->surfaceID;
            call->scalarInput[1] = iteration & 1;
            preserveMask = 1;
            break;
        case KPFuzzSelectorM2Submit:
            KPFuzzPut32(call->structInput, 0, session->sourceID);
            KPFuzzPut32(call->structInput, 4, session->destID);
            KPFuzzPut64(call->structInput, 8, 0);
            ranges[rangeCount++] = (KPFuzzRange){0, 0x10};
            break;
        case KPFuzzSelectorM2Credit:
            break;
        case KPFuzzSelectorIOMFBScalar:
            break;
        case KPFuzzSelectorFastPathOpen: {
            static const char xml[] =
                "<dict>"
                "<key>FastPathHasEntitlement</key><true/>"
                "<key>FastPathMotionEventEntitlement</key><true/>"
                "</dict>";
            memcpy(call->structInput, xml, sizeof(xml));
            call->structInputCount = sizeof(xml);
            variableLength = YES;
            break;
        }
        case KPFuzzSelectorFastPathCopy:
            call->scalarInput[0] = 0;
            call->scalarInput[1] = 1;
            call->structInputCount = 0;
            call->structOutputCapacity = KPFuzzMaxStructSize;
            call->structOutputCount = KPFuzzMaxStructSize;
            variableLength = YES;
            break;
        case KPFuzzSelectorJPEGDecode:
        case KPFuzzSelectorJPEGEncode: {
            BOOL decode = plan->kind == KPFuzzSelectorJPEGDecode;
            KPFuzzPut32(call->structInput, 0, decode ? session->sourceID : session->destID);
            KPFuzzPut32(call->structInput, 4, decode ? session->jpegByteCount : 64 * 64 * 4);
            KPFuzzPut32(call->structInput, 8, decode ? session->destID : session->sourceID);
            KPFuzzPut32(call->structInput, 12, decode ? 64 * 64 * 4 : (uint32_t)IOSurfaceGetAllocSize(session->jpegSource));
            KPFuzzPut32(call->structInput, 20, 64);
            KPFuzzPut32(call->structInput, 24, 64);
            KPFuzzPut32(call->structInput, 44, decode ? 0 : 3);
            KPFuzzPut64(call->structInput, 48, 0);
            KPFuzzPut64(call->structInput, 56, 0);
            KPFuzzPut32(call->structInput, 72, 0);
            KPFuzzPut32(call->structInput, 76, 64);
            KPFuzzPut32(call->structInput, 80, 64);
            ranges[rangeCount++] = (KPFuzzRange){0, 4};
            ranges[rangeCount++] = (KPFuzzRange){8, 4};
            ranges[rangeCount++] = (KPFuzzRange){48, 16};
            ranges[rangeCount++] = (KPFuzzRange){72, 4};
            break;
        }
    }
    if (iteration != 0) {
        KPFuzzMutateScalars(call, &state, preserveMask, iteration);
        KPFuzzMutateBuffer(call, &state, ranges, rangeCount, variableLength, iteration);
        KPFuzzApplyFieldPolicies(plan, session, iteration, &state, call);
    }
}

static BOOL KPFuzzReproBegin(const KPFuzzSelectorPlan *plan,
                             NSUInteger planIndex,
                             uint32_t iteration,
                             const KPFuzzCall *call,
                             const KPFuzzSession *session,
                             KPFuzzRepro *repro,
                             uint64_t runSeed) {
    uint64_t callSeed = KPFuzzCallSeed(runSeed, planIndex, iteration);
    uint64_t hash = KPFuzzCallHash(call);
    NSString *auxiliary = @"";
    if (plan->kind == KPFuzzSelectorAGXSubmit) {
        const void *command = (const void *)(uintptr_t)session->command.address;
        const void *segments = (const void *)(uintptr_t)session->segments.address;
        auxiliary = [NSString stringWithFormat:@" command=%@ segments=%@",
                     KPFuzzHex(command, 0x330), KPFuzzHex(segments, 0x40)];
    } else if ((plan->kind == KPFuzzSelectorJPEGDecode || plan->kind == KPFuzzSelectorJPEGEncode) &&
               iteration == 0 && session->jpegData) {
        auxiliary = [NSString stringWithFormat:@" jpegData=%@",
                     KPFuzzHex(session->jpegData.bytes, session->jpegData.length)];
    }
    NSString *line = [NSString stringWithFormat:
        @"BEGIN runSeed=0x%016llx callSeed=0x%016llx plan=%lu family=%s kind=%s selector=%u iteration=%u baseline=%u serviceIndex=%u hash=0x%016llx scalarIn=%s structIn=%s structOutCapacity=%zu%@\n",
        runSeed, callSeed, (unsigned long)planIndex,
        KPFuzzFamilyName(plan->family).UTF8String,
        KPFuzzSelectorKindName(plan->kind).UTF8String,
        plan->selector, iteration, iteration == 0, session->serviceIndex, hash,
        KPFuzzHex(call->scalarInput, call->scalarInputCount * sizeof(uint64_t)).UTF8String,
        KPFuzzHex(call->structInput, call->structInputCount).UTF8String,
        call->structOutputCapacity, auxiliary];
    return KPFuzzWriteAll(repro->descriptor, line) && fsync(repro->descriptor) == 0;
}

static void KPFuzzReproEnd(const KPFuzzCall *call, KPFuzzRepro *repro, kern_return_t kr) {
    size_t structOutputCount = MIN(call->structOutputCount, (size_t)KPFuzzMaxStructSize);
    NSString *line = [NSString stringWithFormat:
        @"END kr=0x%08x scalarOut=%s structOut=%s structOutSize=%zu\n",
        (uint32_t)kr,
        KPFuzzHex(call->scalarOutput, call->scalarOutputCount * sizeof(uint64_t)).UTF8String,
        KPFuzzHex(call->structOutput, structOutputCount).UTF8String,
        call->structOutputCount];
    KPFuzzWriteAll(repro->descriptor, line);
    fsync(repro->descriptor);
}

kern_return_t KPFuzzInvoke(const KPFuzzSelectorPlan *plan, NSUInteger planIndex, uint32_t iteration, KPFuzzCall *call, const KPFuzzSession *session, KPFuzzRepro *repro, uint64_t runSeed) {
    if (!KPFuzzReproBegin(plan, planIndex, iteration, call, session, repro, runSeed)) {
        return kIOReturnError;
    }
    call->structOutputCount = call->structOutputCapacity;
    kern_return_t kr;
    if (plan->kind == KPFuzzSelectorJPEGDecode || plan->kind == KPFuzzSelectorJPEGEncode) {
        kr = IOConnectCallStructMethod(session->connection,
                                       plan->selector,
                                       call->structInput,
                                       call->structInputCount,
                                       call->structOutput,
                                       &call->structOutputCount);
    } else {
        uint64_t *scalarOutput = call->scalarOutputCount ? call->scalarOutput : NULL;
        uint32_t *scalarOutputCount = call->scalarOutputCount ? &call->scalarOutputCount : NULL;
        void *structOutput = call->structOutputCapacity ? call->structOutput : NULL;
        size_t *structOutputCount = call->structOutputCapacity ? &call->structOutputCount : NULL;
        kr = IOConnectCallMethod(session->connection,
                                 plan->selector,
                                 call->scalarInputCount ? call->scalarInput : NULL,
                                 call->scalarInputCount,
                                 call->structInputCount ? call->structInput : NULL,
                                 call->structInputCount,
                                 scalarOutput,
                                 scalarOutputCount,
                                 structOutput,
                                 structOutputCount);
    }
    KPFuzzReproEnd(call, repro, kr);
    return kr;
}
