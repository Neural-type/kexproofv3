#import "KPViewController.h"
#import "KPDeviceInfoModule.h"
#import "KPAGXSpillProbeModule.h"
#import "KPIOSurfaceProbeModule.h"
#import "KPIOAudioCodecsProbeModule.h"
#import "KPM2ScalerProbeModule.h"
#import "KPFuzzModule.h"
#import "KPGlyphProbeModule.h"
#import "KPCGType5ProbeModule.h"
#import "KPLog.h"
#import "KPLogViewController.h"
#import "KPReportStore.h"
#import "KPResourceLoaderModule.h"
#import "KPStatusView.h"
#import "KPStubTestModule.h"
#import "KPTestCell.h"
#import "KPTestModule.h"

@interface KPViewController () <UITableViewDataSource, UITableViewDelegate>
@property (nonatomic, strong) UITableView *tableView;
@property (nonatomic, strong) UIView *headerView;
@property (nonatomic, strong) KPStatusView *statusView;
@property (nonatomic, strong) UIButton *runButton;
@property (nonatomic, copy) NSArray<id<KPTestModule>> *modules;
@property (nonatomic, copy) NSArray<NSArray<id<KPTestModule>> *> *groupedModules;
@property (nonatomic, copy) NSArray<NSString *> *sectionTitles;
@property (nonatomic, copy, nullable) NSString *runningModuleID;
@property (nonatomic, assign) BOOL jobRunning;
@property (nonatomic, strong) dispatch_queue_t workQueue;
@end

@implementation KPViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    NSLog(@"[KexProofV3] screen: workbench");
    self.title = @"KexProof";
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;
    self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeAlways;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithImage:[UIImage systemImageNamed:@"square.and.arrow.up"]
        style:UIBarButtonItemStylePlain
        target:self
        action:@selector(shareTapped:)];

    self.workQueue = dispatch_queue_create("com.stealth.kexproofv3.tests", DISPATCH_QUEUE_SERIAL);
    self.sectionTitles = @[@"Device", @"Resources", @"Kernel Probes"];
    [self configureModules];
    [self configureHeader];
    [self configureTable];
    [self updateRunButton];

    NSString *version = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"3.4.0";
    [KPLog.shared appendFormat:@"=== KexProofV3 %@ started @ %@ ===", version, [NSDate date]];
    [KPLog.shared append:@"Clean iOS 27 research workbench. No exploit engine or legacy binary resources bundled."];
}

- (void)configureModules {
    self.modules = @[
        [[KPDeviceInfoModule alloc] init],
        [[KPResourceLoaderModule alloc] init],
        [[KPStubTestModule alloc] initWithIdentifier:@"sptm.tlbi-remap"
                                               title:@"SPTM TLBI / Remap Probe"
                                            subtitle:@"TLBI invalidation and SPTM remapping research"
                                                icon:@"memorychip"
                                             details:@"SPTM translation invalidation, remap sequencing and validation hooks."],
        [[KPIOSurfaceProbeModule alloc] init],
        [[KPIOSurfaceProbeModule alloc] initWithArmed:YES],
        [[KPIOAudioCodecsProbeModule alloc] init],
        [[KPIOAudioCodecsProbeModule alloc] initWithArmed:YES],
        [[KPAGXSpillProbeModule alloc] init],
        [[KPAGXSpillProbeModule alloc] initWithArmed:YES],
        [[KPStubTestModule alloc] initWithIdentifier:@"amfi.der-entitlements"
                                               title:@"AMFI DER Entitlement Probe"
                                            subtitle:@"DER entitlement parsing and validation behavior"
                                                icon:@"checkmark.shield"
                                             details:@"AMFI DER entitlement input generation and trust-validation hooks."],
        [[KPM2ScalerProbeModule alloc] init],
        [[KPM2ScalerProbeModule alloc] initWithArmed:YES],
        [[KPGlyphProbeModule alloc] initWithArmed:NO],
        [[KPGlyphProbeModule alloc] initWithArmed:YES],
        [[KPCGType5ProbeModule alloc] initWithArmed:NO],
        [[KPCGType5ProbeModule alloc] initWithArmed:YES],
        [[KPFuzzModule alloc] initWithArmed:NO],
        [[KPFuzzModule alloc] initWithArmed:YES]
    ];
    NSMutableArray<NSMutableArray<id<KPTestModule>> *> *groups = [NSMutableArray arrayWithCapacity:self.sectionTitles.count];
    for (NSUInteger index = 0; index < self.sectionTitles.count; index++) {
        [groups addObject:[NSMutableArray array]];
    }
    for (id<KPTestModule> module in self.modules) {
        [groups[(NSUInteger)module.section] addObject:module];
    }
    self.groupedModules = [[NSArray alloc] initWithArray:groups copyItems:YES];
}

- (void)configureHeader {
    self.headerView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 390, 260)];

    UILabel *versionLabel = [[UILabel alloc] init];
    NSString *version = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"3.4.0";
    versionLabel.text = [NSString stringWithFormat:@"KexProofV3 · %@", version];
    versionLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
    versionLabel.textColor = UIColor.labelColor;

    UILabel *targetLabel = [[UILabel alloc] init];
    targetLabel.text = @"iOS 27+ research workbench\nTarget: iPhone 15 Pro / iOS 27.0.1";
    targetLabel.numberOfLines = 0;
    targetLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightRegular];
    targetLabel.textColor = UIColor.secondaryLabelColor;

    self.statusView = [[KPStatusView alloc] init];
    [self.statusView updateWithState:KPStatusStateIdle
                               title:@"Ready"
                              detail:@"2 system checks · probes + fuzzer info · armed rows excluded from Run All"];

    self.runButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.runButton.translatesAutoresizingMaskIntoConstraints = NO;
    UIButtonConfiguration *configuration = [UIButtonConfiguration filledButtonConfiguration];
    configuration.title = @"Run All Tests";
    configuration.image = [UIImage systemImageNamed:@"play.fill"];
    configuration.imagePadding = 8;
    configuration.baseBackgroundColor = UIColor.systemIndigoColor;
    configuration.baseForegroundColor = UIColor.whiteColor;
    configuration.cornerStyle = UIButtonConfigurationCornerStyleLarge;
    configuration.contentInsets = NSDirectionalEdgeInsetsMake(14, 20, 14, 20);
    self.runButton.configuration = configuration;
    self.runButton.accessibilityIdentifier = @"run-all-tests";
    [self.runButton addTarget:self action:@selector(runAllTapped) forControlEvents:UIControlEventTouchUpInside];

    UILabel *footnote = [[UILabel alloc] init];
    footnote.text = @"Native Objective-C · reports saved locally · no exploit bundled";
    footnote.font = [UIFont systemFontOfSize:12 weight:UIFontWeightRegular];
    footnote.textColor = UIColor.tertiaryLabelColor;
    footnote.textAlignment = NSTextAlignmentCenter;
    footnote.numberOfLines = 0;

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[versionLabel, targetLabel, self.statusView, self.runButton, footnote]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 12;
    [stack setCustomSpacing:16 afterView:targetLabel];
    [stack setCustomSpacing:14 afterView:self.statusView];
    [self.headerView addSubview:stack];

    [NSLayoutConstraint activateConstraints:@[
        [stack.topAnchor constraintEqualToAnchor:self.headerView.topAnchor constant:8],
        [stack.leadingAnchor constraintEqualToAnchor:self.headerView.leadingAnchor constant:20],
        [stack.trailingAnchor constraintEqualToAnchor:self.headerView.trailingAnchor constant:-20],
        [stack.bottomAnchor constraintEqualToAnchor:self.headerView.bottomAnchor constant:-18],
        [self.runButton.heightAnchor constraintEqualToConstant:52]
    ]];
}

- (void)configureTable {
    self.tableView = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStyleInsetGrouped];
    self.tableView.translatesAutoresizingMaskIntoConstraints = NO;
    self.tableView.backgroundColor = UIColor.systemGroupedBackgroundColor;
    self.tableView.dataSource = self;
    self.tableView.delegate = self;
    self.tableView.rowHeight = UITableViewAutomaticDimension;
    self.tableView.estimatedRowHeight = 72;
    self.tableView.tableHeaderView = self.headerView;
    [self.tableView registerClass:KPTestCell.class forCellReuseIdentifier:@"KPTestCell"];
    [self.view addSubview:self.tableView];
    [NSLayoutConstraint activateConstraints:@[
        [self.tableView.topAnchor constraintEqualToAnchor:self.view.topAnchor],
        [self.tableView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.tableView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [self.tableView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor]
    ]];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGFloat width = self.tableView.bounds.size.width;
    if (width <= 0) return;
    CGSize fitting = [self.headerView systemLayoutSizeFittingSize:CGSizeMake(width, UILayoutFittingCompressedSize.height)
                                    withHorizontalFittingPriority:UILayoutPriorityRequired
                                          verticalFittingPriority:UILayoutPriorityFittingSizeLevel];
    CGFloat height = ceil(fitting.height);
    if (ABS(CGRectGetWidth(self.headerView.frame) - width) > 0.5 || ABS(CGRectGetHeight(self.headerView.frame) - height) > 0.5) {
        self.headerView.frame = CGRectMake(0, 0, width, height);
        self.tableView.tableHeaderView = self.headerView;
    }
}

- (void)updateRunButton {
    UIButtonConfiguration *configuration = self.runButton.configuration ?: [UIButtonConfiguration filledButtonConfiguration];
    configuration.title = self.jobRunning ? @"Running Tests…" : @"Run All Tests";
    configuration.image = self.jobRunning ? nil : [UIImage systemImageNamed:@"play.fill"];
    configuration.showsActivityIndicator = self.jobRunning;
    self.runButton.configuration = configuration;
    self.runButton.enabled = !self.jobRunning;
}

- (void)runAllTapped {
    if (self.jobRunning) return;
    NSMutableArray<id<KPTestModule>> *safeModules = [NSMutableArray arrayWithCapacity:self.modules.count];
    for (id<KPTestModule> module in self.modules) {
        if ([module.identifier isEqualToString:@"iosurface.race"]) continue;
        if ([module.identifier isEqualToString:@"ioaudio27.panic"]) continue;
        if ([module.identifier isEqualToString:@"m2scaler27.race"]) continue;
        if ([module.identifier isEqualToString:@"agx27.spill.armed"]) continue;
        if ([module.identifier isEqualToString:@"glyph27.render.armed"]) continue;
        if ([module.identifier isEqualToString:@"cgtype527.render.armed"]) continue;
        if ([module.identifier isEqualToString:@"iokit.fuzzer.armed"]) continue;
        [safeModules addObject:module];
    }
    [self startModules:safeModules];
}

- (void)startModules:(NSArray<id<KPTestModule>> *)modules {
    if (self.jobRunning || !modules.count) return;
    self.jobRunning = YES;
    self.runningModuleID = nil;
    [self.statusView updateWithState:KPStatusStateRunning
                               title:@"Running"
                              detail:modules.count == 1 ? modules.firstObject.title : @"Preparing complete workbench run"];
    [self updateRunButton];
    [self.tableView reloadData];

    NSArray<id<KPTestModule>> *queue = [modules copy];
    NSMutableArray<NSString *> *failures = [NSMutableArray array];
    dispatch_async(self.workQueue, ^{
        for (id<KPTestModule> module in queue) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.runningModuleID = module.identifier;
                [self.statusView updateWithState:KPStatusStateRunning
                                           title:@"Running"
                                          detail:module.title];
                [self.tableView reloadData];
            });
            @try {
                NSString *report = [module runReport];
                if (!report.length) {
                    [NSException raise:@"KPEmptyReport" format:@"%@ returned an empty report", module.identifier];
                }
                [KPLog.shared appendFormat:@"\n=== %@ [%@] ===\n%@", module.title, module.identifier, report];
                NSError *saveError = nil;
                NSURL *savedURL = [KPReportStore saveReport:report identifier:module.identifier error:&saveError];
                if (savedURL) {
                    [KPLog.shared appendFormat:@"Report saved: %@", savedURL.lastPathComponent];
                } else {
                    [failures addObject:[NSString stringWithFormat:@"%@: %@", module.title, saveError.localizedDescription]];
                    [KPLog.shared appendFormat:@"Report save failed for %@: %@", module.identifier, saveError.localizedDescription];
                }
            } @catch (NSException *exception) {
                NSString *reason = exception.reason ?: exception.name;
                [failures addObject:[NSString stringWithFormat:@"%@: %@", module.title, reason]];
                [KPLog.shared appendFormat:@"Module %@ failed: %@", module.identifier, reason];
            }
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            self.jobRunning = NO;
            self.runningModuleID = nil;
            if (failures.count) {
                [self.statusView updateWithState:KPStatusStateError
                                           title:@"Completed with errors"
                                          detail:failures.firstObject];
            } else {
                [self.statusView updateWithState:KPStatusStateSuccess
                                           title:queue.count == 1 ? @"Test Complete" : @"Run Complete"
                                          detail:[NSString stringWithFormat:@"%lu report(s) appended to the session log and saved", (unsigned long)queue.count]];
            }
            [self updateRunButton];
            [self.tableView reloadData];
        });
    });
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return self.groupedModules.count + 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return section < (NSInteger)self.groupedModules.count ? self.groupedModules[(NSUInteger)section].count : 2;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return section < (NSInteger)self.sectionTitles.count ? self.sectionTitles[(NSUInteger)section] : @"Logs";
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
    if (section == KPTestSectionKernelProbes) {
        return @"Defaults are non-destructive. Fuzzer info returns the bounded target plan only. Dedicated armed rows, including Glyph Grift and IOKit Fuzzer, may crash the app or panic the kernel and are excluded from Run All. Remaining probes return NOT IMPLEMENTED.";
    }
    return nil;
}

- (void)iosurfaceRaceSwitchChanged:(UISwitch *)sender {
    [NSUserDefaults.standardUserDefaults setBool:sender.isOn forKey:@"KexProofIOSurfaceRaceEnabled"];
    NSString *detail = sender.isOn
        ? @"Next IOSurface 27 Probe run will execute the notify/stop race (race-enabled build only). The kernel may panic."
        : @"IOSurface 27 Probe is back to open/start/stop reachability only.";
    [self.statusView updateWithState:sender.isOn ? KPStatusStateRunning : KPStatusStateIdle
                               title:sender.isOn ? @"Race Armed" : @"Race Disarmed"
                              detail:detail];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    KPTestCell *cell = [tableView dequeueReusableCellWithIdentifier:@"KPTestCell" forIndexPath:indexPath];
    if (indexPath.section == (NSInteger)self.groupedModules.count) {
        if (indexPath.row == 0) {
            [cell configureWithTitle:@"Session Log"
                            subtitle:@"Live monospaced output and complete transcript"
                                icon:@"doc.plaintext"
                           showsPlay:NO];
        } else {
            [cell configureWithTitle:@"Export Report"
                            subtitle:@"Share the transcript, saved reports and live logs"
                                icon:@"square.and.arrow.up"
                           showsPlay:NO];
        }
        [cell setRunning:NO];
        [cell setModuleEnabled:YES];
        return cell;
    }

    id<KPTestModule> module = self.groupedModules[(NSUInteger)indexPath.section][(NSUInteger)indexPath.row];
    [cell configureWithTitle:module.title subtitle:module.subtitle icon:module.icon showsPlay:YES];
    if ([module.identifier isEqualToString:@"iosurface.probe"]) {
        UISwitch *raceSwitch = [[UISwitch alloc] init];
        raceSwitch.on = [NSUserDefaults.standardUserDefaults boolForKey:@"KexProofIOSurfaceRaceEnabled"];
        raceSwitch.onTintColor = UIColor.systemRedColor;
        raceSwitch.accessibilityLabel = @"Enable IOSurface notify/stop race";
        [raceSwitch addTarget:self action:@selector(iosurfaceRaceSwitchChanged:) forControlEvents:UIControlEventValueChanged];
        cell.accessoryView = raceSwitch;
    } else {
        cell.accessoryView = nil;
    }
    BOOL running = self.jobRunning && [self.runningModuleID isEqualToString:module.identifier];
    [cell setRunning:running];
    [cell setModuleEnabled:!self.jobRunning];
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if (indexPath.section == (NSInteger)self.groupedModules.count) {
        if (indexPath.row == 0) {
            KPLogViewController *logs = [[KPLogViewController alloc] init];
            [self.navigationController pushViewController:logs animated:YES];
        } else {
            [self shareTapped:tableView];
        }
        return;
    }
    if (self.jobRunning) return;
    id<KPTestModule> module = self.groupedModules[(NSUInteger)indexPath.section][(NSUInteger)indexPath.row];
    [self startModules:@[module]];
}

- (void)shareTapped:(id)sender {
    NSError *error = nil;
    NSURL *URL = [KPReportStore createShareURLWithError:&error];
    if (!URL) {
        [self.statusView updateWithState:KPStatusStateError title:@"Export Failed" detail:error.localizedDescription];
        return;
    }
    UIActivityViewController *activity = [[UIActivityViewController alloc] initWithActivityItems:@[URL]
                                                                           applicationActivities:nil];
    if ([sender isKindOfClass:UIBarButtonItem.class]) {
        activity.popoverPresentationController.barButtonItem = sender;
    } else {
        activity.popoverPresentationController.sourceView = self.tableView;
        activity.popoverPresentationController.sourceRect = self.tableView.bounds;
    }
    [self presentViewController:activity animated:YES completion:nil];
}

@end
