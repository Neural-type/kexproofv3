#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

@interface KPByteStreamProbeModule : NSObject <KPTestModule>
@property (nonatomic, assign, readonly, getter=isArmed) BOOL armed;
- (instancetype)initWithArmed:(BOOL)armed;
@end

NS_ASSUME_NONNULL_END
