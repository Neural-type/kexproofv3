#import "KPFuzzPlan.h"

#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurfaceRef.h>

NS_ASSUME_NONNULL_BEGIN

#define KPFuzzMaxStructSize 4096
#define KPFuzzMaxScalarCount 8

typedef struct {
    uint64_t scalarInput[KPFuzzMaxScalarCount];
    uint32_t scalarInputCount;
    uint8_t structInput[KPFuzzMaxStructSize];
    size_t structInputCount;
    uint64_t scalarOutput[KPFuzzMaxScalarCount];
    uint32_t scalarOutputCount;
    uint8_t structOutput[KPFuzzMaxStructSize];
    size_t structOutputCount;
    size_t structOutputCapacity;
} KPFuzzCall;

typedef struct {
    uint32_t identifier;
    uint64_t address;
    uint64_t size;
} KPFuzzShmem;

typedef struct {
    io_connect_t connection;
    io_connect_t surfaceConnection;
    uint32_t queueID;
    uint32_t notificationID;
    KPFuzzShmem command;
    KPFuzzShmem segments;
    uint32_t surfaceID;
    uint32_t sourceID;
    uint32_t destID;
    uint32_t serviceIndex;
    IOSurfaceRef jpegSource;
    IOSurfaceRef jpegDest;
    NSData *jpegData;
    uint32_t jpegByteCount;
} KPFuzzSession;

typedef struct {
    int descriptor;
    NSString *path;
} KPFuzzRepro;

uint64_t KPFuzzCallSeed(uint64_t runSeed, NSUInteger planIndex, uint32_t iteration);
uint64_t KPFuzzCallHash(const KPFuzzCall *call);

BOOL KPFuzzReproStart(KPFuzzRepro *repro, uint64_t runSeed, NSError **error);
void KPFuzzReproFinish(KPFuzzRepro *repro);

kern_return_t KPFuzzFastPathSelectService(io_service_t *selectedService, uint32_t *selectedIndex, NSMutableString *report);
kern_return_t KPFuzzSessionStart(const KPFuzzSelectorPlan *plan, io_service_t fastPathService, KPFuzzSession *session, NSMutableString *report);
void KPFuzzSessionEnd(const KPFuzzSelectorPlan *plan, KPFuzzSession *session);
void KPFuzzPrepareCall(const KPFuzzSelectorPlan *plan, NSUInteger planIndex, const KPFuzzSession *session, uint32_t iteration, uint64_t runSeed, KPFuzzCall *call);
kern_return_t KPFuzzInvoke(const KPFuzzSelectorPlan *plan, NSUInteger planIndex, uint32_t iteration, KPFuzzCall *call, const KPFuzzSession *session, KPFuzzRepro *repro, uint64_t runSeed);

NS_ASSUME_NONNULL_END
