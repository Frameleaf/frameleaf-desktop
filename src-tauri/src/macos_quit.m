#import <AppKit/AppKit.h>
#import <objc/runtime.h>

// Dock-menu Quit and a logout, restart or shutdown reach the app as `terminate:`, which asks the
// app delegate's `applicationShouldTerminate:`. The window toolkit's delegate does not implement
// it, so those quits ended the process without asking anything. This adds the method and hands
// the question to Rust (macos_quit.rs).

// 0: an ordinary quit (the Dock, another app). 1: the session is ending.
typedef int (*FrameleafShouldTerminate)(int sessionEnding);
static FrameleafShouldTerminate decide;

static BOOL sessionEnding(void) {
    NSAppleEventDescriptor *event = NSAppleEventManager.sharedAppleEventManager.currentAppleEvent;
    if (event.eventClass != kCoreEventClass || event.eventID != kAEQuitApplication) return NO;
    switch ([event attributeDescriptorForKeyword:kAEQuitReason].typeCodeValue) {
        case kAELogOut:
        case kAEReallyLogOut:
        case kAEShowRestartDialog:
        case kAERestart:
        case kAEShowShutdownDialog:
        case kAEShutDown:
            return YES;
        default:
            return NO;
    }
}

static NSApplicationTerminateReply shouldTerminate(id self, SEL _cmd, NSApplication *sender) {
    (void)self;
    (void)_cmd;
    (void)sender;
    switch (decide ? decide(sessionEnding() ? 1 : 0) : 1) {
        case 0: return NSTerminateCancel;
        case 2: return NSTerminateLater;
        default: return NSTerminateNow;
    }
}

// Returns whether the question now reaches `callback`. Call on the main thread, once the app has
// its delegate.
bool frameleaf_guard_terminate(FrameleafShouldTerminate callback) {
    id<NSApplicationDelegate> delegate = NSApp.delegate;
    if (!delegate || !callback) return false;
    Class class = object_getClass(delegate);
    if (class_getInstanceMethod(class, @selector(applicationShouldTerminate:))) return false;
    decide = callback;
    // NSUInteger (NSApplicationTerminateReply) from an object, a selector and an object.
    if (!class_addMethod(class, @selector(applicationShouldTerminate:), (IMP)shouldTerminate, "Q@:@")) {
        decide = NULL;
        return false;
    }
    return true;
}

// Answers an earlier NSTerminateLater. Safe from any thread.
void frameleaf_reply_terminate(bool terminate) {
    // While it waits for this answer the app runs its loop in the modal-panel mode, which is one
    // of the common modes.
    CFRunLoopPerformBlock(CFRunLoopGetMain(), kCFRunLoopCommonModes, ^{
        [NSApp replyToApplicationShouldTerminate:terminate];
    });
    CFRunLoopWakeUp(CFRunLoopGetMain());
}
