#import <AppKit/AppKit.h>

typedef void (*FrameleafFileSelection)(const char *const *paths, size_t count);
static FrameleafFileSelection deliver;

@interface FrameleafFinderImport : NSObject
- (void)importSelection:(NSPasteboard *)pasteboard userData:(NSString *)data error:(NSString **)error;
@end

@implementation FrameleafFinderImport
- (void)importSelection:(NSPasteboard *)pasteboard userData:(NSString *)data error:(NSString **)error {
    (void)data;
    (void)error;
    NSArray<NSURL *> *urls = [pasteboard readObjectsForClasses:@[NSURL.class]
        options:@{NSPasteboardURLReadingFileURLsOnlyKey: @YES}];
    const char *paths[100];
    if (urls.count == 0 || urls.count > sizeof(paths) / sizeof(*paths)) {
        deliver(NULL, urls.count);
        return;
    }
    // Keep the paths alive while the synchronous Rust callback copies them.
    NSMutableArray<NSString *> *strings = [NSMutableArray arrayWithCapacity:urls.count];
    for (NSURL *url in urls) {
        if (!url.isFileURL || (url.host.length && ![url.host isEqualToString:@"localhost"]) || !url.path) {
            deliver(NULL, urls.count);
            return;
        }
        [strings addObject:url.path];
    }
    for (NSUInteger i = 0; i < strings.count; i++) {
        paths[i] = strings[i].fileSystemRepresentation;
    }
    deliver(paths, strings.count);
}
@end

void frameleaf_register_finder_service(FrameleafFileSelection callback) {
    static FrameleafFinderImport *provider;
    deliver = callback;
    provider = [FrameleafFinderImport new];
    [NSApplication sharedApplication].servicesProvider = provider;
}
