#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

// Process-local diagnostic only. Missing selectors/evidence never imply GPU readiness.
@interface FLBuffer : NSObject
@property NSUInteger dispatches;
@property NSUInteger indirectDispatches;
@property BOOL committed;
@end
@implementation FLBuffer
@end

@interface FLScope : NSObject
@property uint64_t identifier;
@property double begin;
@property double end;
@property NSUInteger pending;
@property BOOL invalid;
@property(strong) NSMutableArray<NSDictionary *> *events;
@end
@implementation FLScope
@end

@interface FLHook : NSObject
@property Class cls;
@property SEL selector;
@property IMP replacement;
@end
@implementation FLHook
@end

static NSCondition *state;
static NSMutableDictionary<NSNumber *, FLScope *> *scopes;
static NSMutableDictionary<NSString *, FLHook *> *hooks;
static BOOL hookChanged;
static _Thread_local void *dispatchingEncoder;
static FLScope *active;
static BOOL installed;
static char bufferKey, encoderKey;

uint32_t fl_gpu_abi_version(void) { return 1; }
static NSString *device_identity(id<MTLDevice> device) {
    return [NSString stringWithFormat:@"%016llx", (unsigned long long)device.registryID];
}
size_t fl_gpu_device_report(char *output, size_t capacity) { @autoreleasepool {
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    if (!device) return 0;
    NSData *json = [NSJSONSerialization dataWithJSONObject:@{
        @"abiVersion": @(fl_gpu_abi_version()),
        @"osBuild": NSProcessInfo.processInfo.operatingSystemVersionString,
        @"devices": @[@{@"name": device.name, @"registryId": device_identity(device)}]}
        options:0 error:nil];
    size_t required = json.length + 1;
    if (output && capacity >= required) { memcpy(output, json.bytes, json.length); output[json.length] = 0; }
    return required;
} }

static NSString *key(Class cls, SEL selector) {
    return [NSString stringWithFormat:@"%p/%s", cls, sel_getName(selector)];
}
static BOOL hooks_intact(void) {
    @synchronized(hooks) {
        for (FLHook *entry in hooks.allValues)
            if (method_getImplementation(class_getInstanceMethod(entry.cls, entry.selector)) != entry.replacement)
                hookChanged = YES;
        return !hookChanged;
    }
}
static BOOL hook(Class cls, SEL selector, id (^wrapper)(IMP)) {
    @synchronized(hooks) {
        if (!hooks_intact()) return NO;
        Method method = class_getInstanceMethod(cls, selector);
        if (!method) return NO;
        if (hooks[key(cls, selector)]) return YES;
        IMP previous = method_getImplementation(method);
        // Reuse an inherited wrapper instead of wrapping it a second time.
        for (Class parent = class_getSuperclass(cls); parent; parent = class_getSuperclass(parent)) {
            FLHook *entry = hooks[key(parent, selector)];
            if (entry && entry.replacement == previous) return YES;
        }
        IMP replacement = imp_implementationWithBlock(wrapper(previous));
        FLHook *entry = [FLHook new]; entry.cls = cls; entry.selector = selector; entry.replacement = replacement;
        hooks[key(cls, selector)] = entry;
        if (!class_addMethod(cls, selector, replacement, method_getTypeEncoding(method)))
            method_setImplementation(class_getInstanceMethod(cls, selector), replacement);
        return YES;
    }
}
static void dispatched(id encoder) {
    FLBuffer *record = objc_getAssociatedObject(encoder, &encoderKey);
    if (record) {
        [state lock]; record.dispatches++; [state unlock];
    }
}
static void dispatch_grid(IMP previous, id self, SEL selector, MTLSize grid, MTLSize group) {
    void *outer = dispatchingEncoder; dispatchingEncoder = (__bridge void *)self;
    @try {
        if (outer != dispatchingEncoder && grid.width && grid.height && grid.depth && group.width && group.height && group.depth)
            dispatched(self);
        ((void (*)(id, SEL, MTLSize, MTLSize))previous)(self, selector, grid, group);
    } @finally { dispatchingEncoder = outer; }
}
static void dispatch_indirect(IMP previous, id self, SEL selector, id buffer, NSUInteger offset, MTLSize group) {
    // Indirect argument buffers can encode zero work, so they are not positive dispatch proof.
    FLBuffer *record = objc_getAssociatedObject(self, &encoderKey);
    void *outer = dispatchingEncoder; dispatchingEncoder = (__bridge void *)self;
    @try {
        if (record && outer != dispatchingEncoder) { [state lock]; record.indirectDispatches++; [state unlock]; }
        ((void (*)(id, SEL, id, NSUInteger, MTLSize))previous)(self, selector, buffer, offset, group);
    } @finally { dispatchingEncoder = outer; }
}
static id attach(id buffer, id encoder) {
    if (!encoder) return encoder;
    @synchronized(buffer) {
        FLBuffer *record = objc_getAssociatedObject(buffer, &bufferKey);
        if (!record) {
            record = [FLBuffer new];
            objc_setAssociatedObject(buffer, &bufferKey, record, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        objc_setAssociatedObject(encoder, &encoderKey, record, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    Class cls = object_getClass(encoder);
    for (NSString *name in @[@"dispatchThreadgroups:threadsPerThreadgroup:", @"dispatchThreads:threadsPerThreadgroup:"]) {
        SEL selector = NSSelectorFromString(name);
        hook(cls, selector, ^id(IMP previous) {
            return ^(id self, MTLSize grid, MTLSize group) { dispatch_grid(previous, self, selector, grid, group); };
        });
    }
    SEL selector = @selector(dispatchThreadgroupsWithIndirectBuffer:indirectBufferOffset:threadsPerThreadgroup:);
    hook(cls, selector, ^id(IMP previous) {
        return ^(id self, id buffer, NSUInteger offset, MTLSize group) {
            dispatch_indirect(previous, self, selector, buffer, offset, group);
        };
    });
    return encoder;
}
static void commit(IMP previous, id<MTLCommandBuffer> self, SEL selector) {
    FLBuffer *record = objc_getAssociatedObject(self, &bufferKey);
    [state lock];
    FLScope *scope = active;
    BOOL observe = scope && record && (record.dispatches > 0 || record.indirectDispatches > 0) && !record.committed;
    if (observe) {
        record.committed = YES;
        if (scope.events.count + scope.pending >= 2048) {
            scope.invalid = YES; observe = NO;
        } else scope.pending++;
    }
    [state unlock];
    if (observe) {
        [self addCompletedHandler:^(id<MTLCommandBuffer> command) {
            [state lock];
            [scope.events addObject:@{@"start": @(command.GPUStartTime), @"end": @(command.GPUEndTime),
                @"completed": @(command.status == MTLCommandBufferStatusCompleted),
                @"dispatches": @(record.dispatches), @"indirectDispatches": @(record.indirectDispatches),
                @"deviceName": command.commandQueue.device.name ?: @"",
                @"deviceRegistryId": device_identity(command.commandQueue.device)}];
            scope.pending--; [state broadcast]; [state unlock];
        }];
    }
    ((void (*)(id, SEL))previous)(self, selector);
}

int fl_gpu_install(void) { @autoreleasepool { @synchronized([FLHook class]) {
    if (installed) return hooks_intact() ? 0 : -2;
    if (!state) { state = [NSCondition new]; scopes = [NSMutableDictionary new]; hooks = [NSMutableDictionary new]; }
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    id<MTLCommandQueue> queue = [device newCommandQueue];
    id<MTLCommandBuffer> buffer = [queue commandBuffer];
    if (!buffer) return -1;
    Class cls = object_getClass(buffer);
    SEL commitSelector = @selector(commit), computeSelector = @selector(computeCommandEncoder);
    if (!hook(cls, commitSelector, ^id(IMP previous) {
            return ^(id self) { commit(previous, self, commitSelector); };
        }) || !hook(cls, computeSelector, ^id(IMP previous) {
            return ^id(id self) { return attach(self, ((id (*)(id, SEL))previous)(self, computeSelector)); };
        })) return -2;
    SEL descriptorSelector = @selector(computeCommandEncoderWithDescriptor:);
    hook(cls, descriptorSelector, ^id(IMP previous) {
        return ^id(id self, id descriptor) {
            return attach(self, ((id (*)(id, SEL, id))previous)(self, descriptorSelector, descriptor));
        };
    });
    SEL typeSelector = @selector(computeCommandEncoderWithDispatchType:);
    hook(cls, typeSelector, ^id(IMP previous) {
        return ^id(id self, NSUInteger type) {
            return attach(self, ((id (*)(id, SEL, NSUInteger))previous)(self, typeSelector, type));
        };
    });
    installed = YES;
    return 0;
} } }
int fl_gpu_begin(uint64_t identifier) { @autoreleasepool {
    if (!installed || !identifier || !hooks_intact()) return -1;
    [state lock];
    if (active || scopes[@(identifier)] || scopes.count >= 64) { [state unlock]; return -2; }
    FLScope *scope = [FLScope new]; scope.identifier = identifier;
    scope.events = [NSMutableArray new]; scope.begin = CACurrentMediaTime();
    scopes[@(identifier)] = scope; active = scope;
    [state unlock]; return 0;
} }
int fl_gpu_end(uint64_t identifier) { @autoreleasepool {
    if (!installed) return -1;
    BOOL intact = hooks_intact();
    [state lock];
    if (!active || active.identifier != identifier) { [state unlock]; return -2; }
    if (!intact) active.invalid = YES;
    FLScope *scope = active; scope.end = CACurrentMediaTime(); active = nil;
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:0.5];
    while (scope.pending && [state waitUntilDate:deadline]) {}
    if (scope.pending) scope.invalid = YES;
    [state unlock]; return scope.invalid ? -3 : 0;
} }
int fl_gpu_reset(void) { @autoreleasepool {
    if (!installed || !hooks_intact()) return -1;
    [state lock];
    if (active) { [state unlock]; return -2; }
    for (FLScope *scope in scopes.allValues) {
        BOOL valid = !scope.invalid && !scope.pending && scope.end > scope.begin;
        for (NSDictionary *event in scope.events) {
            double start = [event[@"start"] doubleValue], end = [event[@"end"] doubleValue];
            if (![event[@"completed"] boolValue] || !isfinite(start) || !isfinite(end) ||
                start <= 0 || start < scope.begin || end <= start || end > scope.end) valid = NO;
        }
        if (!valid) { [state unlock]; return -3; }
    }
    [scopes removeAllObjects];
    [state unlock]; return 0;
} }
size_t fl_gpu_report(char *output, size_t capacity) { @autoreleasepool {
    if (!installed) return 0;
    BOOL intact = hooks_intact();
    [state lock];
    NSMutableArray *results = [NSMutableArray new];
    for (NSNumber *identifier in [[scopes allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
        FLScope *scope = scopes[identifier];
        NSUInteger count = 0, dispatches = 0; double elapsed = 0;
        NSUInteger unverifiedIndirect = 0;
        NSMutableSet<NSString *> *devices = [NSMutableSet new];
        NSMutableSet<NSString *> *identities = [NSMutableSet new];
        BOOL valid = intact && !scope.invalid && scope.end > scope.begin && !scope.pending;
        for (NSDictionary *event in scope.events) {
            double start = [event[@"start"] doubleValue], end = [event[@"end"] doubleValue];
            BOOL contained = [event[@"completed"] boolValue] && isfinite(start) && isfinite(end) &&
                start > 0 && start >= scope.begin && end > start && end <= scope.end;
            if (!contained) { valid = NO; continue; }
            if ([event[@"dispatches"] unsignedIntegerValue] == 0) { unverifiedIndirect++; continue; }
            count++; dispatches += [event[@"dispatches"] unsignedIntegerValue]; elapsed += (end - start) * 1e9;
            [devices addObject:event[@"deviceName"]];
            [identities addObject:event[@"deviceRegistryId"]];
        }
        [results addObject:@{@"callId": identifier, @"valid": @(valid), @"computeBuffers": @(count),
            @"computeDispatches": @(dispatches), @"gpuNanoseconds": @(elapsed), @"pending": @(scope.pending),
            @"unverifiedIndirectBuffers": @(unverifiedIndirect),
            @"deviceNames": [[devices allObjects] sortedArrayUsingSelector:@selector(compare:)],
            @"deviceRegistryIds": [[identities allObjects] sortedArrayUsingSelector:@selector(compare:)]}];
    }
    NSData *json = [NSJSONSerialization dataWithJSONObject:@{@"abiVersion": @(fl_gpu_abi_version()), @"diagnosticOnly": @YES, @"positiveDirectDispatchRequired": @YES, @"scopes": results}
        options:0 error:nil];
    size_t required = json.length + 1;
    if (output && capacity >= required) { memcpy(output, json.bytes, json.length); output[json.length] = 0; }
    [state unlock]; return required;
} }
