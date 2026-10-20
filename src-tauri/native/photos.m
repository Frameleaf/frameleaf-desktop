// Read-only PhotoKit bridge. No filesystem access to a Photos library or private KVC.
#import <Foundation/Foundation.h>
#import <Photos/Photos.h>
#include <stdbool.h>
#include <stdlib.h>

typedef bool (*FLPhotosSink)(void *, const unsigned char *, size_t);
static bool authorized(void) {
    if (@available(macOS 11.0, *)) {
        PHAuthorizationStatus status = [PHPhotoLibrary authorizationStatusForAccessLevel:PHAccessLevelReadWrite];
        return status == PHAuthorizationStatusAuthorized || status == PHAuthorizationStatusLimited;
    }
    return false;
}
bool fl_photos_authorized(void) { @autoreleasepool { return authorized(); } }
static char *json(id value) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
    if (!data || data.length > 196608) return strdup("{\"error\":\"photos_metadata_invalid\"}");
    return strndup(data.bytes, data.length);
}
static NSNumber *created(PHAsset *asset) {
    return @((long long)((asset.creationDate ?: asset.modificationDate).timeIntervalSince1970 * 1000));
}
static NSNumber *modified(PHAsset *asset) {
    return @((long long)((asset.modificationDate ?: asset.creationDate).timeIntervalSince1970 * 1000));
}
static bool original(PHAssetResource *resource) API_AVAILABLE(macos(11.0)) {
    return resource.type == PHAssetResourceTypePhoto || resource.type == PHAssetResourceTypeVideo ||
           resource.type == PHAssetResourceTypeAlternatePhoto || resource.type == PHAssetResourceTypePairedVideo;
}
static NSDictionary *describe(PHAsset *asset, PHAssetResource *resource, NSUInteger index) API_AVAILABLE(macos(11.0)) {
    return @{ @"asset":asset.localIdentifier, @"created":created(asset), @"modified":modified(asset), @"index":@(index),
              @"kind":@(resource.type), @"filename":resource.originalFilename };
}
static char *preview(unsigned int count) API_AVAILABLE(macos(11.0)) { @autoreleasepool {
    if (!count || count > 100) return json(@{@"error":@"photos_scope_invalid"});
    if ([PHPhotoLibrary authorizationStatusForAccessLevel:PHAccessLevelReadWrite] == PHAuthorizationStatusNotDetermined) {
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        dispatch_async(dispatch_get_main_queue(), ^{
            [PHPhotoLibrary requestAuthorizationForAccessLevel:PHAccessLevelReadWrite handler:^(PHAuthorizationStatus status) {
                dispatch_semaphore_signal(done);
            }];
        });
        if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 120 * NSEC_PER_SEC)))
            return json(@{@"error":@"photos_permission_pending"});
    }
    if (!authorized()) return json(@{@"error":@"photos_permission_required"});
    PHFetchOptions *options = [PHFetchOptions new];
    options.fetchLimit = count;
    options.sortDescriptors = @[[NSSortDescriptor sortDescriptorWithKey:@"creationDate" ascending:NO]];
    options.predicate = [NSPredicate predicateWithFormat:@"mediaType == %d OR mediaType == %d", PHAssetMediaTypeImage, PHAssetMediaTypeVideo];
    PHFetchResult<PHAsset *> *assets = [PHAsset fetchAssetsWithOptions:options];
    NSMutableArray *resources = [NSMutableArray new];
    for (PHAsset *asset in assets) {
        NSArray<PHAssetResource *> *all = [PHAssetResource assetResourcesForAsset:asset];
        NSUInteger before = resources.count;
        bool paired = false;
        for (NSUInteger index = 0; index < all.count; index++) {
            PHAssetResource *resource = all[index];
            if (!original(resource)) continue;
            [resources addObject:describe(asset, resource, index)];
            paired |= resource.type == PHAssetResourceTypePairedVideo;
        }
        if (resources.count == before || ((asset.mediaSubtypes & PHAssetMediaSubtypePhotoLive) && !paired))
            return json(@{@"error":@"photos_original_resources_unavailable"});
        if (resources.count > 100) return json(@{@"error":@"photos_scope_too_large"});
    }
    if (!authorized()) return json(@{@"error":@"photos_permission_required"});
    return json(@{@"assets":@(assets.count), @"resources":resources});
} }
char *fl_photos_preview(unsigned int count) { @autoreleasepool {
    if (@available(macOS 11.0, *)) return preview(count);
    return json(@{@"error":@"photos_macos_update_required"});
} }
// A NULL/zero-length callback is a local policy/cancellation check, never media data.
static int export_resource(const char *description, bool allow_hydration, FLPhotosSink sink, void *context) API_AVAILABLE(macos(11.0)) { @autoreleasepool {
    if (!authorized()) return 1;
    NSData *data = [[NSString stringWithUTF8String:description] dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *expected = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![expected isKindOfClass:NSDictionary.class]) return 2;
    PHAsset *asset = [PHAsset fetchAssetsWithLocalIdentifiers:@[expected[@"asset"]] options:nil].firstObject;
    if (!asset) return 2;
    NSArray<PHAssetResource *> *all = [PHAssetResource assetResourcesForAsset:asset];
    NSUInteger index = [expected[@"index"] unsignedIntegerValue];
    if (index >= all.count || !original(all[index]) || ![describe(asset, all[index], index) isEqual:expected]) return 2;
    PHAssetResourceRequestOptions *options = [PHAssetResourceRequestOptions new];
    options.networkAccessAllowed = allow_hydration; // Explicit consent; false unless separately approved.
    PHAssetResourceManager *manager = [PHAssetResourceManager defaultManager];
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    NSLock *lock = [NSLock new];
    __block int result = 0;
    PHAssetResourceDataRequestID request = [manager requestDataForAssetResource:all[index] options:options
        dataReceivedHandler:^(NSData *chunk) {
            [lock lock];
            if (!result && (!authorized() || !sink(context, chunk.bytes, chunk.length))) result = 3;
            [lock unlock];
        } completionHandler:^(NSError *error) {
            [lock lock];
            if (error && !result) result = 4;
            [lock unlock];
            dispatch_semaphore_signal(done);
        }];
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:600];
    while (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC / 4))) {
        [lock lock];
        if (!result && (!authorized() || !sink(context, NULL, 0))) result = 3;
        if (!result && deadline.timeIntervalSinceNow < 0) result = 4;
        bool cancel = result != 0;
        [lock unlock];
        if (cancel) [manager cancelDataRequest:request];
        // Wait for the completion callback before returning: its Rust context must remain alive.
    }
    if (!authorized()) return 1;
    PHAsset *after = [PHAsset fetchAssetsWithLocalIdentifiers:@[asset.localIdentifier] options:nil].firstObject;
    if (!after || ![modified(after) isEqual:modified(asset)]) return 2;
    return result;
} }

int fl_photos_export(const char *description, bool allow_hydration, FLPhotosSink sink, void *context) {
    if (@available(macOS 11.0, *)) return export_resource(description, allow_hydration, sink, context);
    return 1;
}
