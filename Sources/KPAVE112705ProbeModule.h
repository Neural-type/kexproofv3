#import "KPTestModule.h"

NS_ASSUME_NONNULL_BEGIN

@interface KPAVE112705ProbeModule : NSObject <KPTestModule>

@property (nonatomic, assign, readonly, getter=isArmed) BOOL armed;
@property (nonatomic, assign, readonly) NSUInteger temporalLayers;
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;

- (instancetype)initWithTemporalLayers:(NSUInteger)temporalLayers;

@end

NS_ASSUME_NONNULL_END
