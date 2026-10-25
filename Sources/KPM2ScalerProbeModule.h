#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

@interface KPM2ScalerProbeModule : NSObject <KPTestModule>
@property (nonatomic, readonly, getter=isArmed) BOOL armed;
- (instancetype)initWithArmed:(BOOL)armed;
@end

NS_ASSUME_NONNULL_END
