#import <Foundation/Foundation.h>

#import "KPCMCA27ProbeModule.h"

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc != 3) {
            fprintf(stderr, "usage: cmca27_probe <cm|ca> <control|armed>\n");
            return 2;
        }
        NSString *component = [NSString stringWithUTF8String:argv[1]];
        NSString *mode = [NSString stringWithUTF8String:argv[2]];
        NSUInteger index = [component isEqualToString:@"cm"] ? 0 : 1;
        BOOL armed = [mode isEqualToString:@"armed"];
        KPCMCA27ProbeModule *module = [[KPCMCA27ProbeModule alloc] initWithArmed:armed component:index];
        NSString *report = [module runReport];
        printf("%s\n", report.UTF8String);
        return 0;
    }
}
