#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int fl_gpu_install(void);
extern int fl_gpu_begin(uint64_t identifier);
extern int fl_gpu_end(uint64_t identifier);
extern size_t fl_gpu_report(char *output, size_t capacity);

static NSDictionary *report(void) {
    size_t size = fl_gpu_report(NULL, 0); assert(size > 0 && size < 1024 * 1024);
    char *buffer = malloc(size); assert(buffer);
    assert(fl_gpu_report(buffer, size) == size);
    NSError *error = nil;
    NSDictionary *value = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:buffer length:size - 1]
        options:0 error:&error];
    free(buffer); assert(value && !error); return value;
}
static NSDictionary *scope(uint64_t identifier) {
    for (NSDictionary *value in report()[@"scopes"])
        if ([value[@"callId"] unsignedLongLongValue] == identifier) return value;
    abort();
}
static void encode(id<MTLCommandBuffer> command, id<MTLComputePipelineState> pipeline, id<MTLBuffer> buffer) {
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder]; assert(encoder);
    [encoder setComputePipelineState:pipeline]; [encoder setBuffer:buffer offset:0 atIndex:0];
    [encoder dispatchThreadgroups:MTLSizeMake(16,1,1) threadsPerThreadgroup:MTLSizeMake(256,1,1)];
    [encoder endEncoding];
}
int main(void) { @autoreleasepool {
    assert(fl_gpu_install() == 0);
    assert(fl_gpu_install() == 0);
    assert(fl_gpu_begin(0) != 0);
    id<MTLDevice> device = MTLCreateSystemDefaultDevice(); assert(device);
    id<MTLCommandQueue> queue = [device newCommandQueue]; assert(queue);
    NSError *error = nil;
    NSString *source = @"#include <metal_stdlib>\nusing namespace metal;\nkernel void addone(device float *a [[buffer(0)]],uint n [[thread_position_in_grid]]) { a[n] += 1.0f; }";
    id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error]; assert(library && !error);
    id<MTLComputePipelineState> pipeline = [device newComputePipelineStateWithFunction:[library newFunctionWithName:@"addone"] error:&error]; assert(pipeline && !error);
    id<MTLBuffer> buffer = [device newBufferWithLength:4096 * sizeof(float) options:MTLResourceStorageModeShared]; assert(buffer);
    memset(buffer.contents, 0, buffer.length);

    assert(fl_gpu_begin(1) == 0);
    volatile uint64_t sum = 0;
    for (uint64_t i = 0; i < 100000; ++i) sum += i;
    assert(sum == 4999950000ULL && fl_gpu_end(1) == 0);
    assert([scope(1)[@"valid"] boolValue] && [scope(1)[@"computeBuffers"] unsignedIntegerValue] == 0);

    assert(fl_gpu_begin(2) == 0 && fl_gpu_begin(22) != 0 && fl_gpu_end(23) != 0);
    id<MTLCommandBuffer> blit = [queue commandBuffer];
    id<MTLBlitCommandEncoder> blitEncoder = [blit blitCommandEncoder];
    [blitEncoder fillBuffer:buffer range:NSMakeRange(0, buffer.length) value:0]; [blitEncoder endEncoding];
    [blit commit]; [blit waitUntilCompleted];
    assert(blit.status == MTLCommandBufferStatusCompleted && fl_gpu_end(2) == 0);
    assert([scope(2)[@"valid"] boolValue] && [scope(2)[@"computeBuffers"] unsignedIntegerValue] == 0);

    assert(fl_gpu_begin(3) == 0);
    for (int i = 0; i < 3; ++i) {
        id<MTLCommandBuffer> command = [queue commandBuffer]; encode(command, pipeline, buffer);
        [command commit]; [command waitUntilCompleted]; assert(command.status == MTLCommandBufferStatusCompleted);
    }
    assert(fl_gpu_end(3) == 0);
    for (int i = 0; i < 4096; ++i) assert(((float *)buffer.contents)[i] == 3.0f);
    assert([scope(3)[@"valid"] boolValue] && [scope(3)[@"computeBuffers"] unsignedIntegerValue] == 3);
    assert([scope(3)[@"computeDispatches"] unsignedIntegerValue] >= 3 && [scope(3)[@"gpuNanoseconds"] doubleValue] > 0);
    assert([scope(3)[@"deviceNames"] isEqualToArray:@[device.name]]);

    assert(fl_gpu_begin(4) == 0);
    id<MTLCommandBuffer> empty = [queue commandBuffer]; [empty commit]; [empty waitUntilCompleted];
    assert(fl_gpu_end(4) == 0 && [scope(4)[@"computeBuffers"] unsignedIntegerValue] == 0);

    id<MTLCommandBuffer> outside = [queue commandBuffer]; encode(outside, pipeline, buffer);
    [outside commit]; [outside waitUntilCompleted];
    assert(fl_gpu_begin(5) == 0 && fl_gpu_end(5) == 0 && [scope(5)[@"computeBuffers"] unsignedIntegerValue] == 0);

    id<MTLSharedEvent> gate = [device newSharedEvent]; assert(gate);
    assert(fl_gpu_begin(6) == 0);
    id<MTLCommandBuffer> delayed = [queue commandBuffer]; [delayed encodeWaitForEvent:gate value:1];
    encode(delayed, pipeline, buffer); [delayed commit];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC), dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{ gate.signaledValue = 1; });
    assert(fl_gpu_end(6) == 0);
    [delayed waitUntilCompleted];
    assert(![scope(6)[@"valid"] boolValue] && [scope(6)[@"computeBuffers"] unsignedIntegerValue] == 0);

    assert(fl_gpu_begin(7) == 0 && ![scope(7)[@"valid"] boolValue] && fl_gpu_end(7) == 0);
    assert(fl_gpu_begin(3) != 0);

    assert(fl_gpu_begin(8) == 0);
    id<MTLCommandBuffer> zero = [queue commandBuffer];
    id<MTLComputeCommandEncoder> zeroEncoder = [zero computeCommandEncoder];
    [zeroEncoder setComputePipelineState:pipeline]; [zeroEncoder setBuffer:buffer offset:0 atIndex:0];
    [zeroEncoder dispatchThreadgroups:MTLSizeMake(0,1,1) threadsPerThreadgroup:MTLSizeMake(256,1,1)];
    [zeroEncoder endEncoding]; [zero commit]; [zero waitUntilCompleted];
    assert(fl_gpu_end(8) == 0 && [scope(8)[@"computeBuffers"] unsignedIntegerValue] == 0);

    assert(fl_gpu_begin(9) == 0);
    uint32_t counts[] = {0,1,1};
    id<MTLBuffer> arguments = [device newBufferWithBytes:counts length:sizeof(counts) options:MTLResourceStorageModeShared];
    id<MTLCommandBuffer> indirect = [queue commandBuffer];
    id<MTLComputeCommandEncoder> indirectEncoder = [indirect computeCommandEncoder];
    [indirectEncoder setComputePipelineState:pipeline]; [indirectEncoder setBuffer:buffer offset:0 atIndex:0];
    [indirectEncoder dispatchThreadgroupsWithIndirectBuffer:arguments indirectBufferOffset:0 threadsPerThreadgroup:MTLSizeMake(256,1,1)];
    [indirectEncoder endEncoding]; [indirect commit]; [indirect waitUntilCompleted];
    assert(fl_gpu_end(9) == 0 && [scope(9)[@"computeBuffers"] unsignedIntegerValue] == 0);
    for (int i = 0; i < 4096; ++i) assert(((float *)buffer.contents)[i] == 5.0f);
    for (uint64_t i = 10; i <= 64; ++i) assert(fl_gpu_begin(i) == 0 && fl_gpu_end(i) == 0);
    assert(fl_gpu_begin(65) != 0);
    char small[8]; memset(small, 'x', sizeof(small)); assert(fl_gpu_report(small, sizeof(small)) > sizeof(small));
    for (size_t i = 0; i < sizeof(small); ++i) assert(small[i] == 'x');

    NSDictionary *result = @{@"diagnosticOnly": @YES, @"device": device.name,
        @"cpuNegative": scope(1), @"blitNegative": scope(2), @"computePositive": scope(3),
        @"emptyNegative": scope(4), @"outsideNegative": scope(5), @"delayedNegative": scope(6),
        @"zeroGridNegative": scope(8), @"zeroIndirectNegative": scope(9),
        @"overlapDuplicateOpenAndLimitChecks": @YES, @"correctGpuOutput": @YES, @"approvalChanged": @NO};
    NSData *json = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:&error]; assert(json && !error);
    fwrite(json.bytes, 1, json.length, stdout); putchar('\n');
} return 0; }
