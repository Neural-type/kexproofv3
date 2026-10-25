#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, KPFuzzFamily) {
    KPFuzzFamilyIOGPU = 0,
    KPFuzzFamilyIOSurface,
    KPFuzzFamilyM2Scaler,
    KPFuzzFamilyIOMobileFramebuffer,
    KPFuzzFamilyFastPath,
    KPFuzzFamilyJPEG,
    KPFuzzFamilyCount
};

typedef NS_ENUM(NSUInteger, KPFuzzSelectorKind) {
    KPFuzzSelectorAGXQueue = 0,
    KPFuzzSelectorAGXShmem,
    KPFuzzSelectorAGXNotification,
    KPFuzzSelectorAGXSubmit,
    KPFuzzSelectorIOSurfaceCreate,
    KPFuzzSelectorIOSurfaceIncrement,
    KPFuzzSelectorIOSurfaceDecrement,
    KPFuzzSelectorM2Submit,
    KPFuzzSelectorM2Credit,
    KPFuzzSelectorIOMFBScalar,
    KPFuzzSelectorFastPathOpen,
    KPFuzzSelectorFastPathCopy,
    KPFuzzSelectorJPEGDecode,
    KPFuzzSelectorJPEGEncode
};

typedef struct {
    KPFuzzFamily family;
    KPFuzzSelectorKind kind;
    uint32_t selector;
    uint32_t budget;
    uint32_t scalarInputCount;
    size_t structInputSize;
    size_t structOutputSize;
} KPFuzzSelectorPlan;

extern const KPFuzzSelectorPlan KPFuzzPlans[];
extern const NSUInteger KPFuzzPlanCount;
extern const NSUInteger KPFuzzTotalBudget;
extern const uint64_t KPFuzzDefaultRunSeed;
extern NSString * const KPFuzzBuildVersion;

NSString *KPFuzzFamilyName(KPFuzzFamily family);
NSString *KPFuzzFamilyService(KPFuzzFamily family);
uint32_t KPFuzzFamilyOpenType(KPFuzzFamily family);
NSString *KPFuzzSelectorKindName(KPFuzzSelectorKind kind);
NSString *KPFuzzPlanSummary(void);
NSUInteger KPFuzzFirstPlanIndexForFamily(KPFuzzFamily family);
NSUInteger KPFuzzPlanCountForFamily(KPFuzzFamily family);

NS_ASSUME_NONNULL_END
