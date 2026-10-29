#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

@interface KPCGType5StackProbeModule : NSObject <KPTestModule>
@property (nonatomic, readonly, getter=isArmed) BOOL armed;
@property (nonatomic, readonly, getter=isSweep) BOOL sweep;
- (instancetype)initWithArmed:(BOOL)armed;
- (instancetype)initWithArmed:(BOOL)armed sweep:(BOOL)sweep;
@end

NS_ASSUME_NONNULL_END
