#import "../photos.m"
#include <assert.h>
int main(void) { @autoreleasepool {
    NSDictionary *expected = @{ @"asset":@"synthetic-id", @"created":@1000, @"modified":@2000, @"index":@0, @"kind":@1, @"filename":@"original.HEIC" };
    NSMutableDictionary *current = [expected mutableCopy]; current[@"index"] = @7;
    assert(matches_snapshot(current, expected, true));
    current[@"modified"] = @3000;
    assert(!matches_snapshot(current, expected, true));
    assert(matches_snapshot(current, expected, false));
    for (NSString *key in @[@"asset",@"filename"]) {
        NSMutableDictionary *foreign = [current mutableCopy]; foreign[key] = @"foreign";
        assert(!matches_snapshot(foreign, expected, false));
    }
    current[@"kind"] = @9; assert(!matches_snapshot(current, expected, false));
    current[@"kind"] = @1; current[@"extra"] = @1; assert(!matches_snapshot(current, expected, false));
    printf("PhotoKit snapshot matching: PASS\n");
} return 0; }
