#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/runtime.h>
#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int fl_gpu_install(void);
extern int fl_gpu_begin(uint64_t identifier);
extern int fl_gpu_end(uint64_t identifier);
extern size_t fl_gpu_report(char *output, size_t capacity);

static NSArray *scopes(void) {
    size_t size = fl_gpu_report(NULL, 0); assert(size > 1 && size < 1024 * 1024);
    char *bytes = malloc(size); assert(bytes && fl_gpu_report(bytes, size) == size);
    NSDictionary *value = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:bytes length:size - 1] options:0 error:nil];
    free(bytes); assert(value); return value[@"scopes"];
}
static void encode(id<MTLCommandBuffer> command, id<MTLComputePipelineState> pipeline, id<MTLBuffer> value) {
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder]; assert(encoder);
    [encoder setComputePipelineState:pipeline]; [encoder setBuffer:value offset:0 atIndex:0];
    [encoder dispatchThreads:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(1,1,1)];
    [encoder endEncoding];
}
int main(int argc, const char *argv[]) { @autoreleasepool {
    assert(fl_gpu_install() == 0);
    int (*reset)(void) = dlsym(RTLD_DEFAULT, "fl_gpu_reset"); assert(reset);
    id<MTLDevice> device = MTLCreateSystemDefaultDevice(); assert(device);
    id<MTLCommandQueue> queue = [device newCommandQueue]; assert(queue);
    if (argc == 2 && !strcmp(argv[1], "hooks")) {
        Method method = class_getInstanceMethod(object_getClass([queue commandBuffer]), @selector(commit));
        IMP previous = method_getImplementation(method);
        IMP replacement = imp_implementationWithBlock(^(id object) {
            ((void (*)(id, SEL))previous)(object, @selector(commit));
        });
        method_setImplementation(method, replacement);
        assert(reset() != 0);
        method_setImplementation(method, previous);
        assert(reset() != 0 && fl_gpu_begin(1) != 0);
        puts("reset cannot erase hook tampering, including after restoration: PASS"); return 0;
    }
    assert(reset() == 0);
    for (uint64_t i = 1; i <= 64; ++i) {
        assert(fl_gpu_begin(i) == 0 && reset() != 0 && fl_gpu_end(i) == 0);
    }
    assert(scopes().count == 64 && fl_gpu_begin(65) != 0 && reset() == 0 && scopes().count == 0);
    NSError *error = nil;
    id<MTLLibrary> library = [device newLibraryWithSource:@"#include <metal_stdlib>\nusing namespace metal;\nkernel void addone(device uint *a [[buffer(0)]]) { a[0] += 1; }" options:nil error:&error]; assert(library && !error);
    id<MTLComputePipelineState> pipeline = [device newComputePipelineStateWithFunction:[library newFunctionWithName:@"addone"] error:&error]; assert(pipeline && !error);
    id<MTLBuffer> value = [device newBufferWithLength:sizeof(uint32_t) options:MTLResourceStorageModeShared];
    memset(value.contents, 0, value.length);
    for (uint64_t i = 0; i < 130; ++i) {
        assert(fl_gpu_begin(100 + i) == 0);
        id<MTLCommandBuffer> command = [queue commandBuffer]; encode(command, pipeline, value);
        [command commit]; [command waitUntilCompleted]; assert(command.status == MTLCommandBufferStatusCompleted);
        assert(fl_gpu_end(100 + i) == 0);
        if ((i + 1) % 64 == 0 || i == 129) {
            for (NSDictionary *scope in scopes())
                assert([scope[@"valid"] boolValue] && [scope[@"computeBuffers"] unsignedIntegerValue] == 1);
            assert(reset() == 0 && scopes().count == 0);
        }
    }
    assert(((uint32_t *)value.contents)[0] == 130);
    id<MTLSharedEvent> gate = [device newSharedEvent]; assert(gate && fl_gpu_begin(1000) == 0);
    id<MTLCommandBuffer> delayed = [queue commandBuffer]; [delayed encodeWaitForEvent:gate value:1];
    encode(delayed, pipeline, value); [delayed commit];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{ gate.signaledValue = 1; });
    assert(fl_gpu_end(1000) != 0 && reset() != 0);
    [delayed waitUntilCompleted]; assert(reset() != 0 && scopes().count == 1);
    puts("130 GPU calls across drained batches; active, pending and late completion cannot be reset: PASS");
} return 0; }
