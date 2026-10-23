#import "KPLogViewController.h"
#import "KPLog.h"
#import "KPReportStore.h"

@interface KPLogViewController ()
@property (nonatomic, strong) UITextView *logView;
@end

@implementation KPLogViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Session Log";
    self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeNever;
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithImage:[UIImage systemImageNamed:@"square.and.arrow.up"]
        style:UIBarButtonItemStylePlain
        target:self
        action:@selector(shareTapped:)];

    self.logView = [[UITextView alloc] init];
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    self.logView.editable = NO;
    self.logView.selectable = YES;
    self.logView.alwaysBounceVertical = YES;
    self.logView.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    self.logView.textColor = UIColor.labelColor;
    self.logView.backgroundColor = UIColor.secondarySystemGroupedBackgroundColor;
    self.logView.layer.cornerRadius = 14;
    self.logView.layer.cornerCurve = kCACornerCurveContinuous;
    self.logView.textContainerInset = UIEdgeInsetsMake(14, 12, 14, 12);
    self.logView.accessibilityLabel = @"KexProof session log";
    [self.view addSubview:self.logView];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [self.logView.topAnchor constraintEqualToAnchor:safe.topAnchor constant:12],
        [self.logView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [self.logView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],
        [self.logView.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-12]
    ]];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    self.logView.text = KPLog.shared.transcript;
    __weak typeof(self) weakSelf = self;
    KPLog.shared.onAppend = ^(NSString *text) {
        [weakSelf appendLogText:text];
    };
    [self scrollToBottom];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    KPLog.shared.onAppend = nil;
}

- (void)appendLogText:(NSString *)text {
    if (!text.length) return;
    NSTextStorage *storage = self.logView.textStorage;
    NSDictionary *attributes = @{
        NSFontAttributeName: self.logView.font,
        NSForegroundColorAttributeName: UIColor.labelColor
    };
    [storage appendAttributedString:[[NSAttributedString alloc] initWithString:text attributes:attributes]];
    if (storage.length > 524288) {
        [storage deleteCharactersInRange:NSMakeRange(0, storage.length - 393216)];
    }
    [self scrollToBottom];
}

- (void)scrollToBottom {
    if (!self.logView.text.length) return;
    [self.logView scrollRangeToVisible:NSMakeRange(self.logView.text.length - 1, 1)];
}

- (void)shareTapped:(id)sender {
    NSError *error = nil;
    NSURL *URL = [KPReportStore createShareURLWithError:&error];
    if (!URL) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Export Failed"
                                                                       message:error.localizedDescription
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    UIActivityViewController *activity = [[UIActivityViewController alloc] initWithActivityItems:@[URL]
                                                                           applicationActivities:nil];
    activity.popoverPresentationController.barButtonItem = self.navigationItem.rightBarButtonItem;
    [self presentViewController:activity animated:YES completion:nil];
}

@end
