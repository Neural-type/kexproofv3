#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

@interface KPCMCA27ProbeModule : NSObject <KPTestModule>
@property (nonatomic, assign, readonly, getter=isArmed) BOOL armed;
- (instancetype)initWithArmed:(BOOL)armed;
- (instancetype)initWithArmed:(BOOL)armed component:(NSUInteger)component;
@end

NS_ASSUME_NONNULL_END
