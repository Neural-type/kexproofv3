#import "KPFuzzModule.h"

#import "KPFuzzSupport.h"

#import <string.h>

#ifndef KP_IOKIT_FUZZER_ENABLE_ARMED
#define KP_IOKIT_FUZZER_ENABLE_ARMED 0
#endif

typedef struct {
    uint32_t planned;
    uint32_t attempted;
    uint32_t succeeded;
    uint32_t failed;
    uint32_t nack;
    uint32_t skipped;
    uint32_t setupFailed;
    uint32_t statusErrors;
    kern_return_t firstKR;
    kern_return_t lastKR;
} KPFuzzSelectorStats;

@interface KPFuzzModule ()
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;
@end

@implementation KPFuzzModule

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        if (armed) {
            _identifier = @"iokit.fuzzer.armed";
            _title = @"IOKit Fuzzer";
            _subtitle = @"ARMED structure-aware · 6 families · bounded 2000 calls";
            _icon = @"network";
        } else {
            _identifier = @"iokit.fuzzer.info";
            _title = @"IOKit Fuzzer Info";
            _subtitle = @"15 active selectors · deferred destructive/unknown layouts";
            _icon = @"info.circle";
        }
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (NSString *)planReport {
    NSMutableString *report = [NSMutableString string];
    [report appendFormat:@"=== KexProofV3 IOKit Fuzzer plan ===\n"];
    [report appendFormat:@"Version: %@; target: iPhone16,1 / A17 Pro / iOS 27.0.1\n", KPFuzzBuildVersion];
    [report appendFormat:@"%@\n", KPFuzzPlanSummary()];
    [report appendString:@"\nFixed-size ABI is exact. Variable structs are capped at 4096 bytes. Required IDs come from real objects and are preserved. Allocation sizes and enum fields use bounded policies.\n"];
    [report appendString:@"FastPath sel1, JPEG Ext/2024 and privileged/destructive methods are excluded. Cleanup close/release is allowed only for created baselines.\n"];
    [report appendString:@"Repro: Documents/kexproofv3-fuzzer-<timestamp>-<runSeed>.log; BEGIN + full input is fsynced before every call; END follows with kr.\n"];
    [report appendString:@"NACK codes 0xe00002e2/0xe00002c2 skip the selector once. Eight consecutive errors skip it, three setup failures skip a family, 250 errors abort the run.\n"];
    [report appendString:@"No kernel operation was executed by this info row. No bug verdict is made without device evidence and triage.\n"];
    return report;
}

static BOOL KPFuzzNeedsSessionPerIteration(KPFuzzSelectorKind kind) {
    switch (kind) {
        case KPFuzzSelectorAGXQueue:
        case KPFuzzSelectorAGXShmem:
        case KPFuzzSelectorAGXNotification:
        case KPFuzzSelectorIOSurfaceCreate:
        case KPFuzzSelectorFastPathOpen:
            return YES;
        default:
            return NO;
    }
}

static BOOL KPFuzzSpecialNack(kern_return_t kr) {
    return (uint32_t)kr == 0xe00002e2 || (uint32_t)kr == 0xe00002c2;
}

static void KPFuzzReleaseCreatedSurface(const KPFuzzSession *session, const KPFuzzCall *call) {
    if (session->connection == IO_OBJECT_NULL || call->structOutputCount < 0x1c) return;
    uint32_t surfaceID = 0;
    memcpy(&surfaceID, call->structOutput + 0x18, sizeof(surfaceID));
    if (!surfaceID) return;
    uint64_t input = surfaceID;
    IOConnectCallMethod(session->connection, 1, &input, 1, NULL, 0,
                        NULL, NULL, NULL, NULL);
}

static KPFuzzSelectorStats KPFuzzRunSelector(const KPFuzzSelectorPlan *plan,
                                             NSUInteger planIndex,
                                             KPFuzzRepro *repro,
                                             uint64_t runSeed,
                                             uint32_t *globalErrors,
                                             NSMutableString *report) {
    KPFuzzSelectorStats stats = {
        .planned = plan->budget,
        .firstKR = KERN_SUCCESS,
        .lastKR = KERN_SUCCESS
    };
    KPFuzzSession session;
    memset(&session, 0, sizeof(session));
    BOOL perIteration = KPFuzzNeedsSessionPerIteration(plan->kind);
    if (!perIteration) {
        kern_return_t setupKR = KPFuzzSessionStart(plan, &session, report);
        if (setupKR != KERN_SUCCESS) {
            stats.setupFailed = 1;
            (*globalErrors)++;
            stats.skipped = plan->budget;
            [report appendFormat:@"  %s sel=%u: setup skipped, kr=0x%08x\n",
             KPFuzzSelectorKindName(plan->kind).UTF8String,
             plan->selector, (uint32_t)setupKR];
            return stats;
        }
    }
    uint32_t consecutiveErrors = 0;
    for (uint32_t iteration = 0; iteration < plan->budget && *globalErrors < 250; iteration++) {
        @autoreleasepool {
            if (perIteration) {
                kern_return_t setupKR = KPFuzzSessionStart(plan, &session, report);
                if (setupKR != KERN_SUCCESS) {
                    stats.setupFailed++;
                    (*globalErrors)++;
                    if (stats.setupFailed >= 3) break;
                    continue;
                }
            }
            if (plan->kind == KPFuzzSelectorIOSurfaceDecrement) {
                uint64_t baseline[] = {session.surfaceID, 0};
                kern_return_t baselineKR = IOConnectCallMethod(session.connection, 14,
                                                               baseline, 2,
                                                               NULL, 0,
                                                               NULL, NULL, NULL, NULL);
                if (baselineKR != KERN_SUCCESS) {
                    stats.setupFailed++;
                    (*globalErrors)++;
                    if (perIteration) KPFuzzSessionEnd(plan, &session);
                    [report appendFormat:@"  %s: baseline increment failed kr=0x%08x; selector skipped\n",
                     KPFuzzSelectorKindName(plan->kind).UTF8String, (uint32_t)baselineKR];
                    break;
                }
            }
            KPFuzzCall call;
            KPFuzzPrepareCall(plan, planIndex, &session, iteration, runSeed, &call);
            stats.attempted++;
            kern_return_t kr = KPFuzzInvoke(plan, planIndex, iteration, &call, &session, repro, runSeed);
            stats.lastKR = kr;
            if (stats.attempted == 1) stats.firstKR = kr;
            if (plan->kind == KPFuzzSelectorIOSurfaceCreate && kr == KERN_SUCCESS) {
                KPFuzzReleaseCreatedSurface(&session, &call);
            }
            if (perIteration) KPFuzzSessionEnd(plan, &session);
            if (KPFuzzSpecialNack(kr)) {
                stats.nack++;
                [report appendFormat:@"  %s sel=%u: NACK kr=0x%08x once; remaining %u iterations skipped\n",
                 KPFuzzSelectorKindName(plan->kind).UTF8String,
                 plan->selector, (uint32_t)kr, plan->budget - iteration - 1];
                stats.skipped += plan->budget - iteration - 1;
                break;
            }
            if (kr == KERN_SUCCESS) {
                stats.succeeded++;
                consecutiveErrors = 0;
            } else {
                stats.failed++;
                consecutiveErrors++;
                (*globalErrors)++;
            }
            if (plan->kind == KPFuzzSelectorAGXSubmit && call.scalarOutputCount && call.scalarOutput[0]) {
                stats.statusErrors++;
                consecutiveErrors++;
                (*globalErrors)++;
            }
            if (consecutiveErrors >= 8) {
                stats.skipped += plan->budget - iteration - 1;
                [report appendFormat:@"  %s sel=%u: eight consecutive errors; remaining iterations skipped\n",
                 KPFuzzSelectorKindName(plan->kind).UTF8String, plan->selector];
                break;
            }
        }
    }
    if (!perIteration) KPFuzzSessionEnd(plan, &session);
    [report appendFormat:@"  %-34s sel=%3u planned=%4u attempted=%4u ok=%4u errors=%4u nack=%u skipped=%4u setupFailed=%u statusErrors=%u firstKR=0x%08x lastKR=0x%08x\n",
     KPFuzzSelectorKindName(plan->kind).UTF8String,
     plan->selector, stats.planned, stats.attempted, stats.succeeded,
     stats.failed, stats.nack, stats.skipped, stats.setupFailed,
     stats.statusErrors, (uint32_t)stats.firstKR, (uint32_t)stats.lastKR];
    return stats;
}

#if KP_IOKIT_FUZZER_ENABLE_ARMED
- (NSString *)runFuzz {
    uint64_t runSeed = KPFuzzDefaultRunSeed;
    NSMutableString *report = [NSMutableString string];
    [report appendFormat:@"=== KexProofV3 IOKit structure-aware fuzzer ===\n"];
    [report appendFormat:@"Version: %@; target: iPhone16,1 / A17 Pro / iOS 27.0.1\n", KPFuzzBuildVersion];
    [report appendFormat:@"runSeed=0x%016llx; budget=%lu fuzz calls excluding setup/cleanup\n",
     runSeed, (unsigned long)KPFuzzTotalBudget];
    [report appendString:@"Mode: ARMED explicit-tap only; deterministic SplitMix64-derived inputs; sync calls only; no spray, KRW, async API or race threads.\n"];
    KPFuzzRepro repro;
    NSError *reproError = nil;
    if (!KPFuzzReproStart(&repro, runSeed, &reproError)) {
        [report appendFormat:@"REPRO SETUP FAILED: %@; no fuzz calls were made.\n", reproError.localizedDescription];
        return report;
    }
    [report appendFormat:@"Repro: %s\n", repro.path.fileSystemRepresentation];
    uint32_t globalErrors = 0;
    uint32_t attempted = 0;
    uint32_t succeeded = 0;
    uint32_t failed = 0;
    uint32_t nack = 0;
    uint32_t setupFailed = 0;
    uint32_t statusErrors = 0;
    BOOL aborted = NO;
    for (KPFuzzFamily family = 0; family < KPFuzzFamilyCount && !aborted; family++) {
        uint32_t familySetupFailures = 0;
        [report appendFormat:@"\n[%s]\n", KPFuzzFamilyName(family).UTF8String];
        NSUInteger first = KPFuzzFirstPlanIndexForFamily(family);
        NSUInteger count = KPFuzzPlanCountForFamily(family);
        for (NSUInteger offset = 0; offset < count && !aborted; offset++) {
            NSUInteger planIndex = first + offset;
            const KPFuzzSelectorPlan *plan = &KPFuzzPlans[planIndex];
            if (familySetupFailures >= 3 || globalErrors >= 250) {
                [report appendFormat:@"  %s sel=%u: skipped by family/global threshold\n",
                 KPFuzzSelectorKindName(plan->kind).UTF8String, plan->selector];
                continue;
            }
            KPFuzzSelectorStats stats = KPFuzzRunSelector(plan, planIndex, &repro, runSeed, &globalErrors, report);
            attempted += stats.attempted;
            succeeded += stats.succeeded;
            failed += stats.failed;
            nack += stats.nack;
            setupFailed += stats.setupFailed;
            statusErrors += stats.statusErrors;
            familySetupFailures += stats.setupFailed;
            aborted = globalErrors >= 250;
        }
    }
    KPFuzzReproFinish(&repro);
    [report appendFormat:@"\n=== Run summary ===\nattempted=%u succeeded=%u failed=%u nack=%u setupFailed=%u statusErrors=%u globalErrors=%u aborted=%s\n",
     attempted, succeeded, failed, nack, setupFailed, statusErrors, globalErrors,
     aborted ? "YES" : "NO"];
    [report appendString:@"Coverage and kr values are signals for triage, not proof of a new bug. Panic analysis requires the persisted BEGIN input and device backtrace.\n"];
    return report;
}
#endif

- (NSString *)runReport {
    if (!self.isArmed) return [self planReport];
#if KP_IOKIT_FUZZER_ENABLE_ARMED
    return [self runFuzz];
#else
    NSMutableString *report = [self planReport];
    [report appendString:@"\nArmed execution was NOT COMPILED: KP_IOKIT_FUZZER_ENABLE_ARMED=1 is required in the unified build.\n"];
    return report;
#endif
}

@end
