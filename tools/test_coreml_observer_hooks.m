#import "../native/coreml_observer.m"
#include <assert.h>

@interface FLTestEncoder : NSObject
@property NSUInteger calls;
- (void)dispatchThreads:(MTLSize)grid threadsPerThreadgroup:(MTLSize)group;
@end
@implementation FLTestEncoder
- (void)dispatchThreads:(MTLSize)grid threadsPerThreadgroup:(MTLSize)group {
    (void)grid; (void)group; self.calls++;
}
@end
@interface FLTestInheritedEncoder : FLTestEncoder @end
@implementation FLTestInheritedEncoder @end
@interface FLTestOverrideEncoder : FLTestEncoder @end
@implementation FLTestOverrideEncoder
- (void)dispatchThreads:(MTLSize)grid threadsPerThreadgroup:(MTLSize)group {
    [super dispatchThreads:grid threadsPerThreadgroup:group];
}
@end

int main(void) { @autoreleasepool {
    assert(fl_gpu_install() == 0);
    for (Class cls in @[[FLTestEncoder class], [FLTestInheritedEncoder class], [FLTestOverrideEncoder class]]) {
        NSObject *buffer = [NSObject new]; FLTestEncoder *encoder = [cls new];
        attach(buffer, encoder); attach(buffer, encoder);
        [encoder dispatchThreads:MTLSizeMake(1, 1, 1) threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
        FLBuffer *record = objc_getAssociatedObject(buffer, &bufferKey);
        assert(encoder.calls == 1 && record.dispatches == 1);
    }
    assert(fl_gpu_begin(1) == 0 && fl_gpu_end(1) == 0);
    assert(fl_gpu_begin(2) == 0);
    Class cls = [FLTestEncoder class]; SEL selector = @selector(dispatchThreads:threadsPerThreadgroup:);
    IMP previous = method_getImplementation(class_getInstanceMethod(cls, selector));
    IMP replacement = imp_implementationWithBlock(^(id object, MTLSize grid, MTLSize group) {
        ((void (*)(id, SEL, MTLSize, MTLSize))previous)(object, selector, grid, group);
    });
    method_setImplementation(class_getInstanceMethod(cls, selector), replacement);
    FLTestEncoder *changed = [FLTestEncoder new]; attach([NSObject new], changed);
    [changed dispatchThreads:MTLSizeMake(1, 1, 1) threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
    assert(changed.calls == 1 && fl_gpu_end(2) != 0 && fl_gpu_begin(3) != 0);
    size_t size = fl_gpu_report(NULL, 0); char *json = malloc(size); assert(json);
    assert(fl_gpu_report(json, size) == size);
    NSDictionary *report = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:json length:size - 1] options:0 error:nil];
    free(json); assert(![report[@"scopes"][0][@"valid"] boolValue]);
    puts("immutable originals, inherited and super calls, repeat attach, late hook rejection: PASS");
} return 0; }
