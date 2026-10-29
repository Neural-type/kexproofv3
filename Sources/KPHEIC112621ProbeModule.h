#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

@interface KPHEIC112621ProbeModule : NSObject <KPTestModule>

@property (nonatomic, assign, readonly, getter=isArmed) BOOL armed;
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;

- (instancetype)initWithArmed:(BOOL)armed;

@end

NS_ASSUME_NONNULL_END
