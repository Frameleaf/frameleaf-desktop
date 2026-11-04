// Run only from the separately signed, provisioned test app on a disposable macOS account.
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern OSStatus frameleaf_keychain(unsigned operation, const char *name, bool presence, unsigned prompt,
                                  const void *bytes, size_t size, CFDataRef *output);

static OSStatus check(unsigned op, NSString *account, bool presence, NSData *bytes, CFDataRef *output) {
    return frameleaf_keychain(op, account.UTF8String, presence, 0, bytes.bytes, bytes.length, output);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static OSStatus classic(NSString *account, NSData *seed) {
    const char *service = "app.frameleaf.desktop";
    SecKeychainRef keychain = NULL;
    OSStatus status = SecKeychainCopyDomainDefault(kSecPreferencesDomainUser, &keychain);
    if (status) return status;
    UInt32 length = (UInt32)[account lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    if (seed) status = SecKeychainAddGenericPassword(keychain, (UInt32)strlen(service), service,
        length, account.UTF8String, (UInt32)seed.length, seed.bytes, NULL);
    else status = SecKeychainFindGenericPassword(keychain, (UInt32)strlen(service), service,
        length, account.UTF8String, NULL, NULL, NULL);
    CFRelease(keychain);
    return status;
}
#pragma clang diagnostic pop

int main(void) {
    @autoreleasepool {
        NSString *suffix = NSUUID.UUID.UUIDString;
        NSString *worker = [@"qualification.worker." stringByAppendingString:suffix];
        NSString *login = [@"qualification.login." stringByAppendingString:suffix];
        NSData *fixture = [suffix dataUsingEncoding:NSUTF8StringEncoding];
        CFDataRef result = NULL;
        int failed = 0;
        for (NSString *account in @[worker, login]) {
            bool presence = [account isEqual:login];
            OSStatus status = check(0, account, presence, nil, &result);
            if (status != errSecItemNotFound) { NSLog(@"Expected an unused generated account; status %d", (int)status); return 1; }
            status = check(1, account, presence, fixture, NULL);
            if (status) { NSLog(@"Cannot add synthetic credential; status %d", (int)status); failed = 1; break; }
            status = check(0, account, presence, nil, &result);
            if (presence) {
                if (status != errSecInteractionNotAllowed || result) { NSLog(@"Unattended protected read did not refuse as expected; status %d", (int)status); failed = 1; }
            } else if (status || ![(__bridge NSData *)result isEqual:fixture]) {
                NSLog(@"Unattended worker credential did not round-trip; status %d", (int)status); failed = 1;
            }
            if (result) { CFRelease(result); result = NULL; }
            if (failed) break;
        }
        NSString *oldWorker = [@"qualification.oldworker." stringByAppendingString:suffix];
        NSString *oldLogin = [@"qualification.oldlogin." stringByAppendingString:suffix];
        for (NSString *account in @[oldWorker, oldLogin]) {
            if (failed) break;
            bool presence = [account isEqual:oldLogin];
            OSStatus status = classic(account, fixture);
            if (status) { NSLog(@"Legacy fixture creation failed; status %d", (int)status); failed = 1; break; }
            status = check(0, account, presence, nil, &result);
            if (presence) {
                if (status != errSecInteractionNotAllowed || result || classic(account, nil) != errSecSuccess) failed = 1;
                // The second read must obey the new ACL even though a recoverable legacy copy exists.
                if (!failed && check(0, account, true, nil, &result) != errSecInteractionNotAllowed) failed = 1;
            } else if (status || ![(__bridge NSData *)result isEqual:fixture] || classic(account, nil) != errSecItemNotFound) {
                failed = 1;
            }
            if (result) { CFRelease(result); result = NULL; }
            if (failed) NSLog(@"Legacy migration or noninteractive denial failed; status %d", (int)status);
        }
        for (NSString *account in @[worker, login, oldWorker, oldLogin]) {
            OSStatus status = check(2, account, [account isEqual:login], nil, NULL);
            if (status && status != errSecItemNotFound) { NSLog(@"Synthetic credential cleanup failed; status %d", (int)status); failed = 1; }
        }
        if (!failed) NSLog(@"Data Protection Keychain worker round trip and protected unattended refusal passed");
        return failed;
    }
}
