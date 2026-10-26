#import "KPGlyphProbeModule.h"

#import "KPLog.h"

#import <CommonCrypto/CommonDigest.h>
#import <CoreGraphics/CoreGraphics.h>
#import <errno.h>
#import <fcntl.h>
#import <signal.h>
#import <stdint.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>
#import <zlib.h>

#ifndef KP_GLYPH27_ENABLE_ARMED
#define KP_GLYPH27_ENABLE_ARMED 0
#endif

#define KP_GLYPH_CANARY_SIZE 4096
#define KP_GLYPH_RENDER_SIZE 256
#define KP_GLYPH_SIGNAL_COUNT 6

typedef struct {
    const char *identifier;
    const char *resource;
    const char *operation;
    const char *arena;
    const char *note;
    int32_t triggerX;
    int32_t dx;
    int32_t depth;
} KPGlyphVariant;

static const KPGlyphVariant KPGlyphBenign = {
    .identifier = "benign-standard",
    .resource = "glyph-benign",
    .operation = "standard-PDF",
    .arena = "none",
    .note = "non-extreme render control",
    .triggerX = 0,
    .dx = 0,
    .depth = 0
};

static const KPGlyphVariant KPGlyphArmedVariants[] = {
    {
        .identifier = "g3",
        .resource = "glyph-g3",
        .operation = "aa_lineto/edgepool",
        .arena = "heap",
        .note = "minimal line trigger; static 27.0.1 match",
        .triggerX = 32000,
        .dx = 33,
        .depth = 9
    },
    {
        .identifier = "calif-trigger",
        .resource = "glyph-calif-trigger",
        .operation = "aa_lineto/edgepool",
        .arena = "heap",
        .note = "Calif source PDF; same outline as g3",
        .triggerX = 32000,
        .dx = 33,
        .depth = 9
    },
    {
        .identifier = "trigger",
        .resource = "glyph-trigger",
        .operation = "aa_lineto/edgepool",
        .arena = "heap",
        .note = "regenerated trigger PDF; same outline as g3",
        .triggerX = 32000,
        .dx = 33,
        .depth = 9
    },
    {
        .identifier = "w1a",
        .resource = "glyph-w1a",
        .operation = "aa_lineto/edgepool",
        .arena = "heap",
        .note = "yscale=1; tm_a=0.99999868; 18.6 SPRAY_HIT=1 only",
        .triggerX = 32842,
        .dx = 32,
        .depth = 9
    },
    {
        .identifier = "w4b",
        .resource = "glyph-w4b",
        .operation = "aa_lineto/edgepool",
        .arena = "heap",
        .note = "yscale=1; tm_a=1.0; 18.6 SPRAY_HIT=1 only",
        .triggerX = 16454,
        .dx = 32,
        .depth = 10
    },
    {
        .identifier = "g1-stack",
        .resource = "glyph-g1",
        .operation = "aa_lineto/edgepool",
        .arena = "stack/alloca",
        .note = "DX below heap threshold; exploratory arena check",
        .triggerX = 32000,
        .dx = 31,
        .depth = 9
    },
    {
        .identifier = "curve",
        .resource = "glyph-curve",
        .operation = "aa_quadto/edgepool",
        .arena = "heap",
        .note = "off-curve exploratory case; not the minimal g3 path",
        .triggerX = 32000,
        .dx = 33,
        .depth = 9
    }
};

static const size_t KPGlyphArmedVariantCount = sizeof(KPGlyphArmedVariants) / sizeof(KPGlyphArmedVariants[0]);
static const int KPGlyphSignals[KP_GLYPH_SIGNAL_COUNT] = {SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE, SIGTRAP};
static volatile sig_atomic_t gGlyphActive;
static volatile sig_atomic_t gGlyphIndex;
static int gGlyphJournalFD = -1;
static const char *gGlyphIdentifier;
static size_t gGlyphIdentifierLength;

@interface KPGlyphProbeModule ()
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *title;
@property (nonatomic, copy, readwrite) NSString *subtitle;
@property (nonatomic, copy, readwrite) NSString *icon;
@property (nonatomic, assign, readwrite) KPTestSection section;
@end

@implementation KPGlyphProbeModule

- (instancetype)initWithArmed:(BOOL)armed {
    self = [super init];
    if (self) {
        _armed = armed;
        _identifier = armed ? @"glyph27.render.armed" : @"glyph27.render.safe";
        _title = armed ? @"Glyph Grift ARMED" : @"Glyph Grift PDF Probe";
        _subtitle = armed
            ? @"Explicit tap · 7 bounded variants · crash may terminate app"
            : @"Parse bundled PDFs · render standard benign only";
        _icon = armed ? @"exclamationmark.triangle" : @"doc.text.magnifyingglass";
        _section = KPTestSectionKernelProbes;
    }
    return self;
}

static NSError *KPGlyphError(NSString *description) {
    return [NSError errorWithDomain:@"KPGlyphProbe" code:1 userInfo:@{NSLocalizedDescriptionKey: description}];
}

static NSUInteger KPGlyphFind(NSData *data, const char *literal, NSUInteger start) {
    if (start >= data.length) return NSNotFound;
    NSData *needle = [NSData dataWithBytes:literal length:strlen(literal)];
    NSRange range = [data rangeOfData:needle options:0 range:NSMakeRange(start, data.length - start)];
    return range.location;
}

static BOOL KPGlyphReadSize(NSData *data, const char *key, NSUInteger start, NSUInteger limit, NSUInteger *value) {
    NSUInteger location = KPGlyphFind(data, key, start);
    if (location == NSNotFound || location >= limit) return NO;
    NSUInteger position = location + strlen(key);
    NSUInteger result = 0;
    BOOL foundDigit = NO;
    while (position < limit && position < data.length) {
        uint8_t byte = ((const uint8_t *)data.bytes)[position];
        if (byte < '0' || byte > '9') {
            if (foundDigit) break;
            position++;
            continue;
        }
        foundDigit = YES;
        if (result > (NSUIntegerMax - 9) / 10) return NO;
        result = result * 10 + (NSUInteger)(byte - '0');
        position++;
    }
    if (!foundDigit) return NO;
    *value = result;
    return YES;
}

static uint16_t KPGlyphBE16(const uint8_t *bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static uint32_t KPGlyphBE32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static NSString *KPGlyphSHA256(NSData *data) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger index = 0; index < sizeof(digest); index++) {
        [result appendFormat:@"%02x", digest[index]];
    }
    return result;
}

static NSString *KPGlyphContentStream(NSData *data) {
    NSUInteger start = KPGlyphFind(data, "BT /F1", 0);
    if (start == NSNotFound) return @"<not found>";
    NSUInteger end = KPGlyphFind(data, " ET", start);
    if (end == NSNotFound || end + 3 <= start || end + 3 - start > 512) return @"<unterminated>";
    NSString *content = [[NSString alloc] initWithBytes:(const uint8_t *)data.bytes + start
                                                length:end + 3 - start
                                              encoding:NSISOLatin1StringEncoding];
    content = [content stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    return [content stringByReplacingOccurrencesOfString:@"\n" withString:@"\\n"];
}

static BOOL KPGlyphTable(NSData *ttf, const char tag[4], NSUInteger *tableOffset, NSUInteger *tableLength) {
    if (ttf.length < 12) return NO;
    const uint8_t *bytes = ttf.bytes;
    uint16_t count = KPGlyphBE16(bytes + 4);
    for (NSUInteger index = 0; index < count; index++) {
        NSUInteger entry = 12 + index * 16;
        if (entry + 16 > ttf.length) return NO;
        if (memcmp(bytes + entry, tag, 4) != 0) continue;
        NSUInteger offset = KPGlyphBE32(bytes + entry + 8);
        NSUInteger length = KPGlyphBE32(bytes + entry + 12);
        if (offset > ttf.length || length > ttf.length - offset) return NO;
        *tableOffset = offset;
        *tableLength = length;
        return YES;
    }
    return NO;
}

static NSDictionary *KPGlyphInspectTTF(NSData *ttf, NSError **error) {
    if (ttf.length < 12 || KPGlyphBE32(ttf.bytes) != 0x00010000) {
        if (error) *error = KPGlyphError(@"Embedded font is not a TrueType sfnt");
        return nil;
    }
    NSUInteger headOffset = 0, headLength = 0;
    NSUInteger maxpOffset = 0, maxpLength = 0;
    NSUInteger glyfOffset = 0, glyfLength = 0;
    if (!KPGlyphTable(ttf, "head", &headOffset, &headLength) || headLength < 20 ||
        !KPGlyphTable(ttf, "maxp", &maxpOffset, &maxpLength) || maxpLength < 32 ||
        !KPGlyphTable(ttf, "glyf", &glyfOffset, &glyfLength)) {
        if (error) *error = KPGlyphError(@"Required head/maxp/glyf tables are missing or truncated");
        return nil;
    }
    const uint8_t *bytes = ttf.bytes;
    NSData *glyf = [ttf subdataWithRange:NSMakeRange(glyfOffset, glyfLength)];
    return @{
        @"upm": @(KPGlyphBE16(bytes + headOffset + 18)),
        @"glyphCount": @(KPGlyphBE16(bytes + maxpOffset + 4)),
        @"componentDepth": @(KPGlyphBE16(bytes + maxpOffset + 30)),
        @"glyfBytes": @(glyfLength),
        @"glyfSHA256": KPGlyphSHA256(glyf)
    };
}

static NSDictionary *KPGlyphInspectPDF(NSURL *URL, NSError **error) {
    NSData *data = [NSData dataWithContentsOfURL:URL options:0 error:error];
    if (!data) return nil;
    if (data.length < 8 || memcmp(data.bytes, "%PDF-", 5) != 0) {
        if (error) *error = KPGlyphError(@"Missing PDF header");
        return nil;
    }
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"size"] = @(data.length);
    result[@"sha256"] = KPGlyphSHA256(data);
    result[@"content"] = KPGlyphContentStream(data);
    result[@"pageMarker"] = @(KPGlyphFind(data, "/Type /Page", 0) != NSNotFound);
    result[@"embeddedFont"] = @NO;
    NSUInteger fontMarker = KPGlyphFind(data, "/FontFile2", 0);
    if (fontMarker == NSNotFound) return result;

    NSUInteger streamMarker = KPGlyphFind(data, "stream", fontMarker);
    if (streamMarker == NSNotFound) {
        if (error) *error = KPGlyphError(@"FontFile2 stream not found");
        return nil;
    }
    NSUInteger compressedLength = 0, originalLength = 0;
    if (!KPGlyphReadSize(data, "/Length ", fontMarker, streamMarker, &compressedLength) ||
        !KPGlyphReadSize(data, "/Length1 ", fontMarker, streamMarker, &originalLength) ||
        !originalLength || originalLength > 4 * 1024 * 1024) {
        if (error) *error = KPGlyphError(@"Invalid FontFile2 Length/Length1");
        return nil;
    }
    NSUInteger streamStart = streamMarker + 6;
    const uint8_t *bytes = data.bytes;
    if (streamStart < data.length && bytes[streamStart] == '\r') streamStart++;
    if (streamStart < data.length && bytes[streamStart] == '\n') streamStart++;
    if (streamStart > data.length || compressedLength > data.length - streamStart) {
        if (error) *error = KPGlyphError(@"Truncated FontFile2 stream");
        return nil;
    }
    NSData *compressed = [data subdataWithRange:NSMakeRange(streamStart, compressedLength)];
    NSMutableData *ttf = [NSMutableData dataWithLength:originalLength];
    z_stream stream = {0};
    stream.next_in = (Bytef *)compressed.bytes;
    stream.avail_in = (uInt)compressed.length;
    stream.next_out = ttf.mutableBytes;
    stream.avail_out = (uInt)ttf.length;
    int status = inflateInit_(&stream, ZLIB_VERSION, (int)sizeof(z_stream));
    if (status != Z_OK) {
        if (error) *error = KPGlyphError([NSString stringWithFormat:@"FontFile2 inflateInit failed: %d", status]);
        return nil;
    }
    status = inflate(&stream, Z_FINISH);
    int endStatus = inflateEnd(&stream);
    if (status != Z_STREAM_END || endStatus != Z_OK || stream.total_out != originalLength) {
        if (error) *error = KPGlyphError([NSString stringWithFormat:@"FontFile2 inflate failed: status=%d end=%d produced=%llu expected=%lu",
                                         status, endStatus, (unsigned long long)stream.total_out, (unsigned long)originalLength]);
        return nil;
    }
    NSDictionary *font = KPGlyphInspectTTF(ttf, error);
    if (!font) return nil;
    [result addEntriesFromDictionary:font];
    result[@"embeddedFont"] = @YES;
    return result;
}

static BOOL KPGlyphStructureMatches(const KPGlyphVariant *variant, NSDictionary *info) {
    if (![info[@"pageMarker"] boolValue]) return NO;
    if (variant->depth == 0) return ![info[@"embeddedFont"] boolValue];
    if (![info[@"embeddedFont"] boolValue]) return NO;
    if ([info[@"upm"] unsignedIntValue] != 16384) return NO;
    if ([info[@"componentDepth"] unsignedIntValue] != (NSUInteger)variant->depth) return NO;
    if ([info[@"glyphCount"] unsignedIntValue] != (NSUInteger)variant->depth + 2) return NO;
    return [info[@"content"] containsString:@"1024 Tf"];
}

static BOOL KPGlyphAppendInspection(NSMutableString *report, const KPGlyphVariant *variant, NSURL *URL) {
    [report appendFormat:@"\n[%s] resource=%s.pdf tx=%d dx=%d n=%d operation=%s arena=%s\n",
     variant->identifier, variant->resource, variant->triggerX, variant->dx, variant->depth,
     variant->operation, variant->arena];
    [report appendFormat:@"  note: %s\n", variant->note];
    NSError *error = nil;
    NSDictionary *info = KPGlyphInspectPDF(URL, &error);
    if (!info) {
        [report appendFormat:@"  STRUCTURE ERROR: %@\n", error.localizedDescription];
        return NO;
    }
    [report appendFormat:@"  size=%@ sha256=%@ content=%@\n", info[@"size"], info[@"sha256"], info[@"content"]];
    if ([info[@"embeddedFont"] boolValue]) {
        [report appendFormat:@"  TTF upm=%@ glyphs=%@ maxComponentDepth=%@ glyfBytes=%@ glyfSHA256=%@\n",
         info[@"upm"], info[@"glyphCount"], info[@"componentDepth"], info[@"glyfBytes"], info[@"glyfSHA256"]];
    } else {
        [report appendString:@"  embedded TTF: none (standard PDF control)\n"];
    }
    BOOL matches = KPGlyphStructureMatches(variant, info);
    [report appendFormat:@"  structure=%@\n", matches ? @"MATCH" : @"MISMATCH"];
    return matches;
}

static NSDictionary *KPGlyphRenderPDF(NSURL *URL) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    CGPDFDocumentRef document = NULL;
    CGColorSpaceRef colorSpace = NULL;
    CGContextRef context = NULL;
    CGImageRef image = NULL;
    @try {
        document = CGPDFDocumentCreateWithURL((__bridge CFURLRef)URL);
        if (!document) {
            result[@"status"] = @"PDF_OPEN_FAILED";
            return result;
        }
        size_t pages = CGPDFDocumentGetNumberOfPages(document);
        result[@"pages"] = @(pages);
        CGPDFPageRef page = CGPDFDocumentGetPage(document, 1);
        if (!page) {
            result[@"status"] = @"PDF_PAGE_FAILED";
            return result;
        }
        CGRect box = CGPDFPageGetBoxRect(page, kCGPDFMediaBox);
        if (box.size.width <= 0 || box.size.height <= 0) {
            result[@"status"] = @"PDF_MEDIABOX_FAILED";
            return result;
        }
        colorSpace = CGColorSpaceCreateDeviceRGB();
        if (!colorSpace) {
            result[@"status"] = @"COLORSPACE_FAILED";
            return result;
        }
        context = CGBitmapContextCreate(NULL, KP_GLYPH_RENDER_SIZE, KP_GLYPH_RENDER_SIZE,
                                        8, KP_GLYPH_RENDER_SIZE * 4, colorSpace,
                                        kCGImageAlphaPremultipliedLast);
        if (!context) {
            result[@"status"] = @"CONTEXT_CREATE_FAILED";
            return result;
        }
        CGContextSetRGBFillColor(context, 1, 1, 1, 1);
        CGContextFillRect(context, CGRectMake(0, 0, KP_GLYPH_RENDER_SIZE, KP_GLYPH_RENDER_SIZE));
        CGContextSetShouldSmoothFonts(context, false);
        CGContextScaleCTM(context, KP_GLYPH_RENDER_SIZE / box.size.width,
                          KP_GLYPH_RENDER_SIZE / box.size.height);
        CGContextTranslateCTM(context, -box.origin.x, -box.origin.y);
        CGContextDrawPDFPage(context, page);
        CGContextFlush(context);
        image = CGBitmapContextCreateImage(context);
        if (!image) {
            result[@"status"] = @"DRAW_RETURNED_NO_IMAGE";
            return result;
        }
        result[@"status"] = @"RENDERED_SURVIVED";
        result[@"image"] = [NSString stringWithFormat:@"%zux%zu", CGImageGetWidth(image), CGImageGetHeight(image)];
        return result;
    } @catch (NSException *exception) {
        result[@"status"] = @"EXCEPTION";
        result[@"detail"] = exception.reason ?: exception.name;
        return result;
    } @finally {
        if (image) CGImageRelease(image);
        if (context) CGContextRelease(context);
        if (colorSpace) CGColorSpaceRelease(colorSpace);
        if (document) CGPDFDocumentRelease(document);
    }
}

static NSString *KPGlyphCheckCanary(uint8_t *canary) {
    if (!canary) return @"unavailable";
    for (NSUInteger index = 0; index < KP_GLYPH_CANARY_SIZE; index++) {
        if (canary[index] == 0x41) continue;
        uint16_t current = 0;
        if (index + 1 < KP_GLYPH_CANARY_SIZE) memcpy(&current, canary + index, sizeof(current));
        int32_t delta = (int32_t)current - 0x4141;
        return [NSString stringWithFormat:@"CHANGED_CANDIDATE offset=%lu old=0x41 new=0x%02x u16=0x%04x delta16=%ld",
                (unsigned long)index, canary[index], current, (long)delta];
    }
    return @"unchanged (local only; no layout verdict)";
}

static BOOL KPGlyphWriteFD(int fd, const void *bytes, size_t length) {
    const uint8_t *position = bytes;
    while (length) {
        ssize_t written = write(fd, position, length);
        if (written < 0) {
            if (errno == EINTR) continue;
            return NO;
        }
        if (!written) return NO;
        position += written;
        length -= (size_t)written;
    }
    return YES;
}

static BOOL KPGlyphJournalLine(int fd, NSString *line, BOOL synchronize) {
    NSString *terminated = [line hasSuffix:@"\n"] ? line : [line stringByAppendingString:@"\n"];
    NSData *data = [terminated dataUsingEncoding:NSUTF8StringEncoding];
    if (!KPGlyphWriteFD(fd, data.bytes, data.length)) return NO;
    return !synchronize || fsync(fd) == 0;
}

static NSString *KPGlyphDocumentsPath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
}

static int KPGlyphOpenJournal(NSError **error) {
    NSString *documents = KPGlyphDocumentsPath();
    if (![[NSFileManager defaultManager] createDirectoryAtPath:documents
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:error]) {
        return -1;
    }
    NSString *path = [documents stringByAppendingPathComponent:@"kexproofv3-glyph-armed-journal.log"];
    int fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0 && error) *error = KPGlyphError([NSString stringWithFormat:@"open %@: %s", path, strerror(errno)]);
    return fd;
}

static NSString *KPGlyphJournalPath(void) {
    return [KPGlyphDocumentsPath() stringByAppendingPathComponent:@"kexproofv3-glyph-armed-journal.log"];
}

static NSString *KPGlyphCursorPath(void) {
    return [KPGlyphDocumentsPath() stringByAppendingPathComponent:@"kexproofv3-glyph-next.txt"];
}

static NSUInteger KPGlyphReadCursor(void) {
    NSString *body = [NSString stringWithContentsOfFile:KPGlyphCursorPath() encoding:NSUTF8StringEncoding error:nil];
    NSInteger value = body ? body.integerValue : 0;
    if (value < 0 || value >= (NSInteger)KPGlyphArmedVariantCount) return 0;
    return (NSUInteger)value;
}

static BOOL KPGlyphWriteCursor(NSUInteger value) {
    NSString *body = [NSString stringWithFormat:@"%lu\n", (unsigned long)value];
    NSData *data = [body dataUsingEncoding:NSUTF8StringEncoding];
    int fd = open(KPGlyphCursorPath().fileSystemRepresentation,
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return NO;
    BOOL ok = KPGlyphWriteFD(fd, data.bytes, data.length) && fsync(fd) == 0;
    close(fd);
    return ok;
}

static NSString *KPGlyphJournalTail(void) {
    NSString *body = [NSString stringWithContentsOfFile:KPGlyphJournalPath() encoding:NSUTF8StringEncoding error:nil];
    if (!body.length) return @"<empty>";
    NSArray<NSString *> *lines = [body componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet];
    NSMutableArray<NSString *> *events = [NSMutableArray array];
    for (NSString *line in lines) {
        if ([line hasPrefix:@"BEGIN "] || [line hasPrefix:@"END "] || [line hasPrefix:@"CRASH "]) {
            [events addObject:line];
        }
    }
    NSUInteger start = events.count > 24 ? events.count - 24 : 0;
    return [[events subarrayWithRange:NSMakeRange(start, events.count - start)] componentsJoinedByString:@"\n"];
}

static size_t KPGlyphCStringLength(const char *string) {
    size_t length = 0;
    while (string[length]) length++;
    return length;
}

static size_t KPGlyphUnsignedString(char *output, uint64_t value, unsigned base) {
    char reversed[32];
    size_t count = 0;
    do {
        unsigned digit = (unsigned)(value % base);
        reversed[count++] = (char)(digit < 10 ? '0' + digit : 'a' + digit - 10);
        value /= base;
    } while (value && count < sizeof(reversed));
    for (size_t index = 0; index < count; index++) output[index] = reversed[count - index - 1];
    return count;
}

static const char *KPGlyphSignalName(int signalNumber) {
    switch (signalNumber) {
        case SIGSEGV: return "SIGSEGV";
        case SIGBUS: return "SIGBUS";
        case SIGABRT: return "SIGABRT";
        case SIGILL: return "SIGILL";
        case SIGFPE: return "SIGFPE";
        case SIGTRAP: return "SIGTRAP";
        default: return "UNKNOWN";
    }
}

static void KPGlyphCrashHandler(int signalNumber, siginfo_t *info, void *context) {
    (void)context;
    if (gGlyphActive && gGlyphJournalFD >= 0) {
        const char *identifier = gGlyphIdentifier ? gGlyphIdentifier : "unknown";
        size_t identifierLength = gGlyphIdentifier ? gGlyphIdentifierLength : 7;
        const char *signalName = KPGlyphSignalName(signalNumber);
        char number[32];
        size_t length;
        KPGlyphWriteFD(gGlyphJournalFD, "CRASH id=", 9);
        KPGlyphWriteFD(gGlyphJournalFD, identifier, identifierLength);
        KPGlyphWriteFD(gGlyphJournalFD, " index=", 7);
        length = KPGlyphUnsignedString(number, (uint64_t)gGlyphIndex, 10);
        KPGlyphWriteFD(gGlyphJournalFD, number, length);
        KPGlyphWriteFD(gGlyphJournalFD, " signal=", 8);
        KPGlyphWriteFD(gGlyphJournalFD, signalName, KPGlyphCStringLength(signalName));
        KPGlyphWriteFD(gGlyphJournalFD, " sig=", 5);
        length = KPGlyphUnsignedString(number, (uint64_t)signalNumber, 10);
        KPGlyphWriteFD(gGlyphJournalFD, number, length);
        KPGlyphWriteFD(gGlyphJournalFD, " code=", 6);
        length = KPGlyphUnsignedString(number, info ? (uint64_t)info->si_code : 0, 10);
        KPGlyphWriteFD(gGlyphJournalFD, number, length);
        KPGlyphWriteFD(gGlyphJournalFD, " address=0x", 11);
        length = KPGlyphUnsignedString(number, (uint64_t)(uintptr_t)(info ? info->si_addr : NULL), 16);
        KPGlyphWriteFD(gGlyphJournalFD, number, length);
        KPGlyphWriteFD(gGlyphJournalFD, "\n", 1);
    }
    _exit(128 + signalNumber);
}

static NSUInteger KPGlyphArmSignals(int journalFD, NSUInteger index, const KPGlyphVariant *variant, struct sigaction oldActions[KP_GLYPH_SIGNAL_COUNT]) {
    gGlyphJournalFD = journalFD;
    gGlyphIndex = (sig_atomic_t)index;
    gGlyphIdentifier = variant->identifier;
    gGlyphIdentifierLength = strlen(variant->identifier);
    gGlyphActive = 1;
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = KPGlyphCrashHandler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_SIGINFO;
    NSUInteger installed = 0;
    for (; installed < KP_GLYPH_SIGNAL_COUNT; installed++) {
        if (sigaction(KPGlyphSignals[installed], &action, &oldActions[installed]) != 0) {
            for (NSUInteger rollback = 0; rollback < installed; rollback++) {
                sigaction(KPGlyphSignals[rollback], &oldActions[rollback], NULL);
            }
            gGlyphActive = 0;
            gGlyphJournalFD = -1;
            gGlyphIdentifier = NULL;
            return 0;
        }
    }
    gGlyphActive = 1;
    return installed;
}

static void KPGlyphRestoreSignals(struct sigaction oldActions[KP_GLYPH_SIGNAL_COUNT], NSUInteger installed) {
    gGlyphActive = 0;
    for (NSUInteger index = 0; index < installed; index++) {
        sigaction(KPGlyphSignals[index], &oldActions[index], NULL);
    }
    gGlyphJournalFD = -1;
    gGlyphIdentifier = NULL;
    gGlyphIdentifierLength = 0;
}

- (NSString *)runSafe {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV3 Glyph Grift safe PDF probe ===\n"];
    [report appendFormat:@"App version: %@\nDevice OS: %@\n",
     [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"3.3.0",
     NSProcessInfo.processInfo.operatingSystemVersionString];
    [report appendString:@"Route: CGPDFDocument -> CGBitmapContext -> CGContextDrawPDFPage; font smoothing disabled. Safe row parses all bundled PDFs but renders only the standard non-extreme control. No armed PDF is rendered here.\n"];
    BOOL allMatched = YES;
    NSURL *benignURL = nil;
    const KPGlyphVariant *variants[1 + KPGlyphArmedVariantCount];
    variants[0] = &KPGlyphBenign;
    for (NSUInteger index = 0; index < KPGlyphArmedVariantCount; index++) variants[index + 1] = &KPGlyphArmedVariants[index];
    for (NSUInteger index = 0; index < 1 + KPGlyphArmedVariantCount; index++) {
        const KPGlyphVariant *variant = variants[index];
        NSString *resource = [NSString stringWithUTF8String:variant->resource];
        NSURL *URL = [NSBundle.mainBundle URLForResource:resource withExtension:@"pdf"];
        if (!URL) {
            allMatched = NO;
            [report appendFormat:@"\n[%s] RESOURCE MISSING: %s.pdf\n", variant->identifier, variant->resource];
            continue;
        }
        BOOL matched = KPGlyphAppendInspection(report, variant, URL);
        allMatched = allMatched && matched;
        if (index == 0) benignURL = matched ? URL : nil;
    }
    [report appendFormat:@"\n=== Structure summary ===\n%@\n", allMatched ? @"ALL 8 PDF STRUCTURES MATCH" : @"STRUCTURE CHECK FAILED"];
    if (!benignURL) {
        [report appendString:@"BENIGN RENDER SKIPPED: standard PDF missing or malformed.\n"];
        return report;
    }
    NSDictionary *rendered = KPGlyphRenderPDF(benignURL);
    [report appendFormat:@"BENIGN id=benign-standard result=%@ pages=%@ image=%@ detail=%@\n",
     rendered[@"status"], rendered[@"pages"] ?: @0, rendered[@"image"] ?: @"none", rendered[@"detail"] ?: @"none"];
    [report appendString:@"The benign result validates only this generic CGPDF render route. It does not prove reachability of the vulnerable glyph cache path.\n"];
    return report;
}

#if KP_GLYPH27_ENABLE_ARMED
- (NSString *)runArmed {
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"=== KexProofV3 Glyph Grift ARMED render probe ===\n"];
    [report appendFormat:@"App version: %@\nDevice OS: %@\n",
     [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"3.3.0",
     NSProcessInfo.processInfo.operatingSystemVersionString];
    [report appendString:@"Bounded to at most seven single-page renders. Route is direct CGPDFDocument/CGContextDrawPDFPage, not the original ImageIO thumbnail harness. No spray, reclaim, CFData corruption, kernel operation or legacy exploit engine is used.\n"];
    [report appendString:@"WARNING: a CRASH record is evidence for triage, not a proven primitive. RENDERED_SURVIVED or an unchanged local canary does not disprove OOB corruption.\n"];
    [report appendFormat:@"Journal: %@\nCursor: %@\n", KPGlyphJournalPath(), KPGlyphCursorPath()];
    [report appendFormat:@"Previous journal events (last 24):\n%@\n", KPGlyphJournalTail()];

    NSError *error = nil;
    int journalFD = KPGlyphOpenJournal(&error);
    if (journalFD < 0) {
        [report appendFormat:@"JOURNAL SETUP FAILED: %@; no armed render was attempted.\n", error.localizedDescription];
        return report;
    }
    NSUInteger start = KPGlyphReadCursor();
    [report appendFormat:@"\nStarting variant index=%lu of %lu\n", (unsigned long)start, (unsigned long)KPGlyphArmedVariantCount];
    for (NSUInteger index = start; index < KPGlyphArmedVariantCount; index++) {
        const KPGlyphVariant *variant = &KPGlyphArmedVariants[index];
        if (!KPGlyphWriteCursor(index + 1)) {
            [report appendFormat:@"CURSOR WRITE FAILED before index=%lu; no further armed render was attempted.\n", (unsigned long)index];
            break;
        }
        NSString *resource = [NSString stringWithUTF8String:variant->resource];
        NSURL *URL = [NSBundle.mainBundle URLForResource:resource withExtension:@"pdf"];
        error = nil;
        NSDictionary *info = URL ? KPGlyphInspectPDF(URL, &error) : nil;
        NSString *sha = info[@"sha256"] ?: @"unavailable";
        NSString *begin = [NSString stringWithFormat:
                           @"BEGIN id=%s index=%lu resource=%s.pdf tx=%d dx=%d n=%d operation=%s arena=%s canaryBytes=%u sha256=%@ os=%@",
                           variant->identifier, (unsigned long)index, variant->resource,
                           variant->triggerX, variant->dx, variant->depth, variant->operation,
                           variant->arena, KP_GLYPH_CANARY_SIZE, sha,
                           NSProcessInfo.processInfo.operatingSystemVersionString];
        if (!KPGlyphJournalLine(journalFD, begin, YES)) {
            [report appendFormat:@"JOURNAL BEGIN FAILED for id=%s; no further armed render was attempted.\n", variant->identifier];
            break;
        }
        [KPLog.shared appendFormat:@"GLYPH %@\nJournal: %@", begin, KPGlyphJournalPath()];
        [report appendFormat:@"\n%@\n", begin];

        NSString *status = nil;
        NSString *detail = nil;
        if (!URL) {
            status = @"RESOURCE_MISSING";
            detail = resource;
        } else if (!info) {
            status = @"STRUCTURE_ERROR";
            detail = error.localizedDescription;
        } else if (!KPGlyphStructureMatches(variant, info)) {
            status = @"STRUCTURE_MISMATCH";
            detail = [NSString stringWithFormat:@"upm=%@ depth=%@ glyphs=%@ content=%@",
                      info[@"upm"], info[@"componentDepth"], info[@"glyphCount"], info[@"content"]];
        }
        if (status) {
            NSString *end = [NSString stringWithFormat:@"END id=%s index=%lu result=%@ detail=%@",
                             variant->identifier, (unsigned long)index, status, detail];
            KPGlyphJournalLine(journalFD, end, YES);
            [KPLog.shared append:end];
            [report appendFormat:@"%@\n", end];
            continue;
        }

        uint8_t *canary = malloc(KP_GLYPH_CANARY_SIZE);
        if (!canary) {
            NSString *end = [NSString stringWithFormat:@"END id=%s index=%lu result=CANARY_ALLOC_FAILED",
                             variant->identifier, (unsigned long)index];
            KPGlyphJournalLine(journalFD, end, YES);
            [report appendFormat:@"%@\n", end];
            continue;
        }
        memset(canary, 0x41, KP_GLYPH_CANARY_SIZE);
        struct sigaction oldActions[KP_GLYPH_SIGNAL_COUNT];
        NSUInteger installed = KPGlyphArmSignals(journalFD, index, variant, oldActions);
        if (installed != KP_GLYPH_SIGNAL_COUNT) {
            free(canary);
            NSString *end = [NSString stringWithFormat:@"END id=%s index=%lu result=SIGNAL_SETUP_FAILED errno=%d",
                             variant->identifier, (unsigned long)index, errno];
            KPGlyphJournalLine(journalFD, end, YES);
            [report appendFormat:@"%@\n", end];
            continue;
        }
        NSDictionary *rendered = KPGlyphRenderPDF(URL);
        KPGlyphRestoreSignals(oldActions, installed);
        NSString *canaryResult = KPGlyphCheckCanary(canary);
        free(canary);
        NSString *end = [NSString stringWithFormat:
                         @"END id=%s index=%lu result=%@ pages=%@ image=%@ canary=%@ detail=%@",
                         variant->identifier, (unsigned long)index,
                         rendered[@"status"], rendered[@"pages"] ?: @0,
                         rendered[@"image"] ?: @"none", canaryResult,
                         rendered[@"detail"] ?: @"none"];
        if (!KPGlyphJournalLine(journalFD, end, YES)) {
            [KPLog.shared appendFormat:@"GLYPH journal END failed for id=%s", variant->identifier];
        }
        [KPLog.shared append:end];
        [report appendFormat:@"%@\n", end];
    }
    close(journalFD);
    [report appendFormat:@"\nNext variant index: %lu (0 starts a new cycle)\n", (unsigned long)KPGlyphReadCursor()];
    [report appendString:@"If the process terminated during a render, reopen the app and this row: the persisted CRASH line identifies the exact variant, signal, code and fault address; the cursor already points to the next variant.\n"];
    return report;
}
#endif

- (NSString *)runReport {
    if (!self.isArmed) return [self runSafe];
#if KP_GLYPH27_ENABLE_ARMED
    return [self runArmed];
#else
    return @"Armed execution was NOT COMPILED. KP_GLYPH27_ENABLE_ARMED=1 is required; no PDF was rendered by this row.\n";
#endif
}

@end
