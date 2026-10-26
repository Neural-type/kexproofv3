#import "KPFuzzPlan.h"

const KPFuzzSelectorPlan KPFuzzPlans[] = {
    {KPFuzzFamilyIOGPU, KPFuzzSelectorAGXQueue, 6, 100, 0, 0x410, 0x10},
    {KPFuzzFamilyIOGPU, KPFuzzSelectorAGXShmem, 12, 100, 2, 0, 0x10},
    {KPFuzzFamilyIOGPU, KPFuzzSelectorAGXNotification, 14, 100, 2, 0, 0x10},
    {KPFuzzFamilyIOGPU, KPFuzzSelectorAGXSubmit, 25, 100, 4, 0x40, 0},
    {KPFuzzFamilyIOGPU, KPFuzzSelectorAGXCreateIOQueue, 42, 150, 2, 0, 0},
    {KPFuzzFamilyIOGPU, KPFuzzSelectorAGXSubmitIOCommands, 45, 150, 1, 8, 0},
    {KPFuzzFamilyIOSurface, KPFuzzSelectorIOSurfaceLookup, 4, 150, 1, 0, 0xc68},
    {KPFuzzFamilyIOSurface, KPFuzzSelectorIOSurfaceCreate, 6, 133, 0, 0x20, 0xc68},
    {KPFuzzFamilyIOSurface, KPFuzzSelectorIOSurfaceScalarQuery, 8, 150, 1, 0, 0},
    {KPFuzzFamilyIOSurface, KPFuzzSelectorIOSurfaceGetValue, 10, 150, 0, 26, 4096},
    {KPFuzzFamilyIOSurface, KPFuzzSelectorIOSurfaceRemoveValue, 11, 150, 0, 26, 4},
    {KPFuzzFamilyIOSurface, KPFuzzSelectorIOSurfaceIncrement, 14, 133, 2, 0, 0},
    {KPFuzzFamilyIOSurface, KPFuzzSelectorIOSurfaceDecrement, 15, 134, 2, 0, 0},
    {KPFuzzFamilyIOSurface, KPFuzzSelectorIOSurfaceScalarQuery, 16, 150, 1, 0, 0},
    {KPFuzzFamilyM2Scaler, KPFuzzSelectorM2Submit, 1, 150, 3, 0x1b0, 0},
    {KPFuzzFamilyM2Scaler, KPFuzzSelectorM2Credit, 10, 150, 3, 0x18, 0},
    {KPFuzzFamilyIOMobileFramebuffer, KPFuzzSelectorIOMFBQuery, 3, 150, 2, 0, 0},
    {KPFuzzFamilyIOMobileFramebuffer, KPFuzzSelectorIOMFBScalar, 13, 150, 1, 0, 0},
    {KPFuzzFamilyIOMobileFramebuffer, KPFuzzSelectorIOMFBQuery, 14, 150, 2, 0, 0},
    {KPFuzzFamilyIOMobileFramebuffer, KPFuzzSelectorIOMFBQuery, 15, 150, 2, 0, 0},
    {KPFuzzFamilyJPEG, KPFuzzSelectorJPEGDecode, 1, 150, 0, 0x58, 0x58},
    {KPFuzzFamilyJPEG, KPFuzzSelectorJPEGEncode, 3, 150, 0, 0x58, 0x58},
};

const NSUInteger KPFuzzPlanCount = sizeof(KPFuzzPlans) / sizeof(KPFuzzPlans[0]);
const NSUInteger KPFuzzTotalBudget = 3050;
const uint64_t KPFuzzDefaultRunSeed = 0x4b50465a5a000002ULL;
NSString * const KPFuzzBuildVersion = @"3.3.1";

NSString *KPFuzzFamilyName(KPFuzzFamily family) {
    switch (family) {
        case KPFuzzFamilyIOGPU: return @"IOGPUDeviceUserClient";
        case KPFuzzFamilyIOSurface: return @"IOSurfaceRootUserClient";
        case KPFuzzFamilyM2Scaler: return @"IOSurfaceAcceleratorClient";
        case KPFuzzFamilyIOMobileFramebuffer: return @"IOMobileFramebufferUserClient";
        case KPFuzzFamilyFastPath: return @"IOHIDEventServiceFastPathUserClient";
        case KPFuzzFamilyJPEG: return @"AppleJPEGDriverUserClient";
        case KPFuzzFamilyCount: break;
    }
    return @"UnknownUserClient";
}

NSString *KPFuzzFamilyService(KPFuzzFamily family) {
    switch (family) {
        case KPFuzzFamilyIOGPU: return @"IOGPU";
        case KPFuzzFamilyIOSurface: return @"IOSurfaceRoot";
        case KPFuzzFamilyM2Scaler: return @"AppleM2ScalerCSCDriver";
        case KPFuzzFamilyIOMobileFramebuffer: return @"IOMobileFramebuffer";
        case KPFuzzFamilyFastPath: return @"IOHIDEventService";
        case KPFuzzFamilyJPEG: return @"AppleJPEGDriver";
        case KPFuzzFamilyCount: break;
    }
    return @"";
}

uint32_t KPFuzzFamilyOpenType(KPFuzzFamily family) {
    switch (family) {
        case KPFuzzFamilyIOGPU: return 1;
        case KPFuzzFamilyIOSurface:
        case KPFuzzFamilyM2Scaler:
        case KPFuzzFamilyIOMobileFramebuffer:
        case KPFuzzFamilyJPEG: return 0;
        case KPFuzzFamilyFastPath: return 2;
        case KPFuzzFamilyCount: break;
    }
    return UINT32_MAX;
}

NSString *KPFuzzSelectorKindName(KPFuzzSelectorKind kind) {
    switch (kind) {
        case KPFuzzSelectorAGXQueue: return @"agx.queue-create";
        case KPFuzzSelectorAGXShmem: return @"agx.shmem-create";
        case KPFuzzSelectorAGXNotification: return @"agx.notification-create";
        case KPFuzzSelectorAGXSubmit: return @"agx.submit";
        case KPFuzzSelectorAGXCreateIOQueue: return @"agx.io-queue-create";
        case KPFuzzSelectorAGXSubmitIOCommands: return @"agx.submit-io-commands";
        case KPFuzzSelectorIOSurfaceCreate: return @"iosurface.fast-create";
        case KPFuzzSelectorIOSurfaceLookup: return @"iosurface.lookup";
        case KPFuzzSelectorIOSurfaceScalarQuery: return @"iosurface.scalar-query";
        case KPFuzzSelectorIOSurfaceGetValue: return @"iosurface.get-value";
        case KPFuzzSelectorIOSurfaceRemoveValue: return @"iosurface.remove-value";
        case KPFuzzSelectorIOSurfaceIncrement: return @"iosurface.use-increment";
        case KPFuzzSelectorIOSurfaceDecrement: return @"iosurface.use-decrement";
        case KPFuzzSelectorM2Submit: return @"m2.tsd-submit";
        case KPFuzzSelectorM2Credit: return @"m2.credit";
        case KPFuzzSelectorIOMFBScalar: return @"iomfb.scalar";
        case KPFuzzSelectorIOMFBQuery: return @"iomfb.query";
        case KPFuzzSelectorFastPathOpen: return @"fastpath.open";
        case KPFuzzSelectorFastPathCopy: return @"fastpath.copy-event";
        case KPFuzzSelectorJPEGDecode: return @"jpeg.decode";
        case KPFuzzSelectorJPEGEncode: return @"jpeg.encode";
    }
    return @"unknown";
}

NSString *KPFuzzPlanSummary(void) {
    return [NSString stringWithFormat:
            @"Wave 2: 5 families / 22 active selectors / %lu fuzz calls max\n"
            @"IOGPU sel 6,12,14,25,42,45 (700) · IOSurface sel 4,6,8,10,11,14,15,16 (1150)\n"
            @"M2 sel 1,10 (300) · IOMFB sel 3,13,14,15 (600) · JPEG sel 1,3 (300)\n"
            @"Dropped: FastPath sel 0,2 (32/32 exclusive) and IOMFB sel 6 (NoPower). IOGPU sel 8/22 not added.\n"
            @"Real baseline objects and selector-specific ID policies; sync calls; no spray, KRW, async API or race threads.",
            (unsigned long)KPFuzzTotalBudget];
}

NSUInteger KPFuzzFirstPlanIndexForFamily(KPFuzzFamily family) {
    for (NSUInteger index = 0; index < KPFuzzPlanCount; index++) {
        if (KPFuzzPlans[index].family == family) return index;
    }
    return NSNotFound;
}

NSUInteger KPFuzzPlanCountForFamily(KPFuzzFamily family) {
    NSUInteger count = 0;
    for (NSUInteger index = 0; index < KPFuzzPlanCount; index++) {
        if (KPFuzzPlans[index].family == family) count++;
    }
    return count;
}
