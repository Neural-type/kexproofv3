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
    uint32_t rejected;
    uint32_t failed;
    uint32_t skipped;
    uint32_t setupFailed;
    uint32_t baselineFailed;
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
            _subtitle = @"ARMED wave 2 · 5 families · bounded 3050 calls";
            _icon = @"network";
        } else {
            _identifier = @"iokit.fuzzer.info";
            _title = @"IOKit Fuzzer Info";
            _subtitle = @"22 active selectors · baseline-first · dropped unreachable targets";
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
    [report appendString:@"\nFixed-size ABI is exact. Variable structs are capped at 4096 bytes. Baseline objects and IDs are real; selector-specific preserve/mutation policies apply. Allocation sizes and enum fields are bounded.\n"];
    [report appendString:@"Dropped on device evidence: FastPath sel 0,2 (32/32 exclusive) and IOMFB sel 6 (NoPower). IOGPU sel 8 (incomplete resource ABI) and sel 22 (Unsupported stub) were not added. JPEG Ext/2024 and privileged/destructive methods remain excluded.\n"];
    [report appendString:@"Repro: Documents/kexproofv3-fuzzer-<timestamp>-<runSeed>.log; BEGIN + full input is fsynced before every call; END follows with kr.\n"];
    [report appendString:@"Iteration 0 is always the unmutated baseline; a baseline failure skips only that selector. Mutated kIOReturnBadArgument, KERN_INVALID_ARGUMENT and AGX shmem zero-size kIOReturnNoMemory are expected rejections, never NACK skips.\n"];
    [report appendString:@"Wave-2 ABI was checked against tables2/methods (197 tables) and container evidence. Eight consecutive identical hard errors skip a selector, three setup failures skip a family, and 250 hard errors abort.\n"];
    [report appendString:@"No kernel operation was executed by this info row. No bug verdict is made without device evidence and triage.\n"];
    return report;
}

static BOOL KPFuzzNeedsSessionPerIteration(KPFuzzSelectorKind kind) {
    switch (kind) {
        case KPFuzzSelectorAGXQueue:
        case KPFuzzSelectorAGXShmem:
        case KPFuzzSelectorAGXNotification:
        case KPFuzzSelectorAGXCreateIOQueue:
        case KPFuzzSelectorIOSurfaceCreate:
        case KPFuzzSelectorIOSurfaceRemoveValue:
        case KPFuzzSelectorFastPathOpen:
            return YES;
        default:
            return NO;
    }
}

static BOOL KPFuzzExpectedMutationRejection(const KPFuzzSelectorPlan *plan, const KPFuzzCall *call, kern_return_t kr) {
    if (kr == kIOReturnBadArgument || kr == KERN_INVALID_ARGUMENT) return YES;
    return plan->kind == KPFuzzSelectorAGXShmem &&
           kr == kIOReturnNoMemory &&
           call->scalarInputCount > 0 &&
           call->scalarInput[0] == 0;
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

static void KPFuzzLogSelectorStats(const KPFuzzSelectorPlan *plan, const KPFuzzSelectorStats *stats, NSMutableString *report) {
    [report appendFormat:@"  %-34s sel=%3u planned=%4u attempted=%4u ok=%4u rejected=%4u hardErrors=%4u skipped=%4u setupFailed=%u baselineFailed=%u statusErrors=%u firstKR=0x%08x lastKR=0x%08x\n",
     KPFuzzSelectorKindName(plan->kind).UTF8String,
     plan->selector, stats->planned, stats->attempted, stats->succeeded,
     stats->rejected, stats->failed, stats->skipped, stats->setupFailed,
     stats->baselineFailed, stats->statusErrors,
     (uint32_t)stats->firstKR, (uint32_t)stats->lastKR];
}

static KPFuzzSelectorStats KPFuzzRunSelector(const KPFuzzSelectorPlan *plan,
                                             NSUInteger planIndex,
                                             KPFuzzRepro *repro,
                                             uint64_t runSeed,
                                             uint32_t *globalHardErrors,
                                             NSMutableString *report) {
    KPFuzzSelectorStats stats = {
        .planned = plan->budget,
        .firstKR = KERN_SUCCESS,
        .lastKR = KERN_SUCCESS
    };
    KPFuzzSession session;
    memset((void *)&session, 0, sizeof(session));
    io_service_t fastPathService = IO_OBJECT_NULL;
    uint32_t fastPathServiceIndex = 0;
    if (plan->family == KPFuzzFamilyFastPath) {
        kern_return_t selectKR = KPFuzzFastPathSelectService(&fastPathService, &fastPathServiceIndex, report);
        if (selectKR != KERN_SUCCESS) {
            stats.setupFailed = 1;
            stats.baselineFailed = 1;
            stats.skipped = plan->budget;
            (*globalHardErrors)++;
            [report appendFormat:@"  %s sel=%u: FastPath baseline selection failed kr=0x%08x; selector skipped\n",
             KPFuzzSelectorKindName(plan->kind).UTF8String,
             plan->selector, (uint32_t)selectKR];
            KPFuzzLogSelectorStats(plan, &stats, report);
            return stats;
        }
    }
    BOOL perIteration = KPFuzzNeedsSessionPerIteration(plan->kind);
    if (!perIteration) {
        kern_return_t setupKR = KPFuzzSessionStart(plan, fastPathService, &session, report);
        if (setupKR == KERN_SUCCESS) session.serviceIndex = fastPathServiceIndex;
        if (setupKR != KERN_SUCCESS) {
            stats.setupFailed = 1;
            stats.skipped = plan->budget;
            (*globalHardErrors)++;
            if (fastPathService != IO_OBJECT_NULL) IOObjectRelease(fastPathService);
            [report appendFormat:@"  %s sel=%u: setup skipped, kr=0x%08x\n",
             KPFuzzSelectorKindName(plan->kind).UTF8String,
             plan->selector, (uint32_t)setupKR];
            KPFuzzLogSelectorStats(plan, &stats, report);
            return stats;
        }
    }
    uint32_t consecutiveHardErrors = 0;
    kern_return_t consecutiveKR = KERN_SUCCESS;
    for (uint32_t iteration = 0; iteration < plan->budget && *globalHardErrors < 250; iteration++) {
        @autoreleasepool {
            if (perIteration) {
                kern_return_t setupKR = KPFuzzSessionStart(plan, fastPathService, &session, report);
                if (setupKR != KERN_SUCCESS) {
                    stats.setupFailed++;
                    stats.skipped++;
                    (*globalHardErrors)++;
                    if (iteration == 0) {
                        stats.baselineFailed++;
                        stats.skipped += plan->budget - 1;
                        [report appendFormat:@"  %s sel=%u: baseline setup failed kr=0x%08x; selector skipped\n",
                         KPFuzzSelectorKindName(plan->kind).UTF8String,
                         plan->selector, (uint32_t)setupKR];
                        break;
                    }
                    if (stats.setupFailed >= 3 || *globalHardErrors >= 250) {
                        stats.skipped += plan->budget - iteration - 1;
                        [report appendFormat:@"  %s sel=%u: setup threshold; remaining %u iterations skipped\n",
                         KPFuzzSelectorKindName(plan->kind).UTF8String,
                         plan->selector, plan->budget - iteration - 1];
                        break;
                    }
                    continue;
                }
                session.serviceIndex = fastPathServiceIndex;
            }
            if (plan->kind == KPFuzzSelectorIOSurfaceDecrement) {
                uint64_t baseline[] = {session.surfaceID, 0};
                kern_return_t baselineKR = IOConnectCallMethod(session.connection, 14,
                                                               baseline, 2,
                                                               NULL, 0,
                                                               NULL, NULL, NULL, NULL);
                if (baselineKR != KERN_SUCCESS) {
                    stats.setupFailed++;
                    stats.skipped += plan->budget - iteration;
                    (*globalHardErrors)++;
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
            if (kr == KERN_SUCCESS) {
                stats.succeeded++;
                consecutiveHardErrors = 0;
                consecutiveKR = KERN_SUCCESS;
            } else if (KPFuzzExpectedMutationRejection(plan, &call, kr)) {
                stats.rejected++;
                consecutiveHardErrors = 0;
                consecutiveKR = KERN_SUCCESS;
            } else {
                stats.failed++;
                (*globalHardErrors)++;
                if (consecutiveHardErrors && consecutiveKR == kr) {
                    consecutiveHardErrors++;
                } else {
                    consecutiveHardErrors = 1;
                    consecutiveKR = kr;
                }
            }
            if (plan->kind == KPFuzzSelectorAGXSubmit && call.scalarOutputCount && call.scalarOutput[0]) {
                stats.statusErrors++;
            }
            if (iteration == 0 && kr != KERN_SUCCESS) {
                stats.baselineFailed++;
                stats.skipped += plan->budget - 1;
                [report appendFormat:@"  %s sel=%u: unmutated baseline failed kr=0x%08x; remaining %u iterations skipped\n",
                 KPFuzzSelectorKindName(plan->kind).UTF8String,
                 plan->selector, (uint32_t)kr, plan->budget - 1];
                break;
            }
            if (consecutiveHardErrors >= 8) {
                stats.skipped += plan->budget - iteration - 1;
                [report appendFormat:@"  %s sel=%u: eight consecutive identical hard errors kr=0x%08x; remaining iterations skipped\n",
                 KPFuzzSelectorKindName(plan->kind).UTF8String,
                 plan->selector, (uint32_t)kr];
                break;
            }
            if (*globalHardErrors >= 250) {
                stats.skipped += plan->budget - iteration - 1;
                [report appendFormat:@"  %s sel=%u: global hard-error threshold; remaining iterations skipped\n",
                 KPFuzzSelectorKindName(plan->kind).UTF8String, plan->selector];
                break;
            }
        }
    }
    if (!perIteration) KPFuzzSessionEnd(plan, &session);
    if (fastPathService != IO_OBJECT_NULL) IOObjectRelease(fastPathService);
    KPFuzzLogSelectorStats(plan, &stats, report);
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
    [report appendString:@"Mode: ARMED explicit-tap only; deterministic SplitMix64-derived inputs; sync calls only; no spray, KRW, async API or race threads. Baseline-first; expected mutation rejections do not consume the hard-error budget.\n"];
    KPFuzzRepro repro;
    NSError *reproError = nil;
    if (!KPFuzzReproStart(&repro, runSeed, &reproError)) {
        [report appendFormat:@"REPRO SETUP FAILED: %@; no fuzz calls were made.\n", reproError.localizedDescription];
        return report;
    }
    [report appendFormat:@"Repro: %s\n", repro.path.fileSystemRepresentation];
    uint32_t globalHardErrors = 0;
    uint32_t attempted = 0;
    uint32_t succeeded = 0;
    uint32_t rejected = 0;
    uint32_t hardFailed = 0;
    uint32_t setupFailed = 0;
    uint32_t baselineFailed = 0;
    uint32_t statusErrors = 0;
    BOOL aborted = NO;
    for (KPFuzzFamily family = 0; family < KPFuzzFamilyCount && !aborted; family++) {
        uint32_t familySetupFailures = 0;
        NSUInteger first = KPFuzzFirstPlanIndexForFamily(family);
        NSUInteger count = KPFuzzPlanCountForFamily(family);
        if (count == 0) continue;
        [report appendFormat:@"\n[%s]\n", KPFuzzFamilyName(family).UTF8String];
        for (NSUInteger offset = 0; offset < count && !aborted; offset++) {
            NSUInteger planIndex = first + offset;
            const KPFuzzSelectorPlan *plan = &KPFuzzPlans[planIndex];
            if (familySetupFailures >= 3 || globalHardErrors >= 250) {
                [report appendFormat:@"  %s sel=%u: skipped by family/global threshold\n",
                 KPFuzzSelectorKindName(plan->kind).UTF8String, plan->selector];
                continue;
            }
            KPFuzzSelectorStats stats = KPFuzzRunSelector(plan, planIndex, &repro, runSeed, &globalHardErrors, report);
            attempted += stats.attempted;
            succeeded += stats.succeeded;
            rejected += stats.rejected;
            hardFailed += stats.failed;
            setupFailed += stats.setupFailed;
            baselineFailed += stats.baselineFailed;
            statusErrors += stats.statusErrors;
            familySetupFailures += stats.setupFailed;
            aborted = globalHardErrors >= 250;
        }
    }
    KPFuzzReproFinish(&repro);
    uint32_t skipped = (uint32_t)KPFuzzTotalBudget - attempted;
    [report appendFormat:@"\n=== Run summary ===\nplanned=%lu attempted=%u skipped=%u succeeded=%u rejected=%u hardErrors=%u setupFailed=%u baselineFailed=%u statusErrors=%u globalHardErrors=%u aborted=%s\n",
     (unsigned long)KPFuzzTotalBudget, attempted, skipped, succeeded, rejected,
     hardFailed, setupFailed, baselineFailed, statusErrors, globalHardErrors,
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
