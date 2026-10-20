#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int fl_gpu_install(void);

int main(void) { @autoreleasepool {
    assert(fl_gpu_install() == 0);
    uint32_t (*version)(void) = dlsym(RTLD_DEFAULT, "fl_gpu_abi_version");
    size_t (*device_report)(char *, size_t) = dlsym(RTLD_DEFAULT, "fl_gpu_device_report");
    assert(version && device_report && version() == 1);
    size_t size = device_report(NULL, 0); assert(size > 1 && size < 16384);
    char small[1] = {'x'}; assert(device_report(small, 1) == size && small[0] == 'x');
    char *bytes = malloc(size); assert(bytes && device_report(bytes, size) == size && !bytes[size - 1]);
    NSDictionary *value = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:bytes length:size - 1] options:0 error:nil];
    free(bytes); assert(value && [value[@"abiVersion"] unsignedIntegerValue] == 1);
    assert([value[@"osBuild"] isEqualToString:NSProcessInfo.processInfo.operatingSystemVersionString]);
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    NSString *identity = [NSString stringWithFormat:@"%016llx", (unsigned long long)device.registryID];
    assert(([value[@"devices"] isEqualToArray:@[@{@"name": device.name, @"registryId": identity}]]));
    puts("versioned ABI, bounded device report, actual Metal identity and OS build: PASS");
} return 0; }
