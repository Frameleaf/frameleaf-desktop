// FD-77: Touch ID, or the Mac's password, before Computer backup shows the recovery key or deletes backups.
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

bool frameleaf_confirm_owner(const char *reason) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;
        if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) return false;
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        __block bool confirmed = false;
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                localizedReason:[NSString stringWithUTF8String:reason]
                          reply:^(BOOL success, NSError *_Nullable failure) {
                              (void)failure;
                              confirmed = success;
                              dispatch_semaphore_signal(done);
                          }];
        dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
        return confirmed;
    }
}
