#import "KPStubTestModule.h"

@interface KPStubTestModule ()
@property (nonatomic, copy) NSString *identifier;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *subtitle;
@property (nonatomic, copy) NSString *icon;
@property (nonatomic, assign) KPTestSection section;
@property (nonatomic, copy) NSString *details;
@end

@implementation KPStubTestModule

- (instancetype)initWithIdentifier:(NSString *)identifier
                             title:(NSString *)title
                          subtitle:(NSString *)subtitle
                              icon:(NSString *)icon
                           details:(NSString *)details {
    self = [super init];
    if (self) {
        _identifier = [identifier copy];
        _title = [title copy];
        _subtitle = [subtitle copy];
        _icon = [icon copy];
        _details = [details copy];
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (NSString *)runReport {
    return [NSString stringWithFormat:
            @"=== KexProofV3 %@ ===\n"
            @"Module: %@\n"
            @"Status: NOT IMPLEMENTED\n"
            @"Target: iPhone 15 Pro / iOS 27.0.1\n"
            @"Scope: %@\n"
            @"No probe, exploit primitive or kernel operation was executed.\n",
            self.title, self.identifier, self.details];
}

@end
