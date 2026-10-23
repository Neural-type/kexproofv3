#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

@interface KPStubTestModule : NSObject <KPTestModule>
- (instancetype)initWithIdentifier:(NSString *)identifier
                             title:(NSString *)title
                          subtitle:(NSString *)subtitle
                              icon:(NSString *)icon
                           details:(NSString *)details;
@end

NS_ASSUME_NONNULL_END
