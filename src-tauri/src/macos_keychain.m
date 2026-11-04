// Security.framework evaluates user presence on the read itself, using Touch ID or the Mac password.
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import "macos_keychain.h"

#define KEY(x) ((__bridge id)(x))
static NSString *const service = @"app.frameleaf.desktop";
static LAContext *session;
static bool cancelled;
static NSMutableSet<NSString *> *legacyCleared;

static NSMutableDictionary *query(NSString *account) {
    return [@{KEY(kSecClass): KEY(kSecClassGenericPassword), KEY(kSecAttrService): service,
              KEY(kSecAttrAccount): account, KEY(kSecUseDataProtectionKeychain): @YES,
              KEY(kSecUseAuthenticationContext): session} mutableCopy];
}

static OSStatus add(NSString *account, NSData *value, bool presence) {
    NSMutableDictionary *item = query(account);
    if (presence) {
        SecAccessControlRef access = SecAccessControlCreateWithFlags(NULL,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlUserPresence, NULL);
        if (!access) return errSecParam;
        item[KEY(kSecAttrAccessControl)] = CFBridgingRelease(access);
    } else {
        item[KEY(kSecAttrAccessible)] = KEY(kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
    }
    item[KEY(kSecValueData)] = value;
    return SecItemAdd((__bridge CFDictionaryRef)item, NULL);
}

static OSStatus readModern(NSString *account, CFDataRef *output) {
    NSMutableDictionary *item = query(account);
    item[KEY(kSecReturnData)] = @YES;
    return SecItemCopyMatching((__bridge CFDictionaryRef)item, (CFTypeRef *)output);
}

// Limit legacy lookup to exactly the user-domain default Keychain used by keyring 3.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static OSStatus legacy(NSString *account, bool remove, bool interactive, NSData **value, NSData *expected) {
    Boolean previous;
    OSStatus status = SecKeychainGetUserInteractionAllowed(&previous);
    if (status) return status;
    status = SecKeychainSetUserInteractionAllowed(previous && interactive);
    if (status) return status;
    SecKeychainRef keychain = NULL;
    SecKeychainItemRef item = NULL;
    UInt32 size = 0;
    void *bytes = NULL;
    status = SecKeychainCopyDomainDefault(kSecPreferencesDomainUser, &keychain);
    if (!status) {
        status = SecKeychainFindGenericPassword(keychain, (UInt32)[service lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
            service.UTF8String, (UInt32)[account lengthOfBytesUsingEncoding:NSUTF8StringEncoding], account.UTF8String,
            remove && !expected ? NULL : &size, remove && !expected ? NULL : &bytes, &item);
    }
    if (!status) {
        if (remove) {
            // An older installed version might have updated the classic record since migration.
            if (!expected || (expected.length == size && !memcmp(bytes, expected.bytes, size)))
                status = SecKeychainItemDelete(item);
            else status = errSecDataNotAvailable;
        }
        else *value = [NSData dataWithBytes:bytes length:size];
    }
    if (bytes) SecKeychainItemFreeContent(NULL, bytes);
    if (item) CFRelease(item);
    if (keychain) CFRelease(keychain);
    OSStatus restored = SecKeychainSetUserInteractionAllowed(previous);
    return restored ? restored : status;
}
#pragma clang diagnostic pop

static OSStatus readAccount(NSString *account, bool presence, bool interactive, CFDataRef *output) {
    OSStatus status = readModern(account, output);
    if (!status && [legacyCleared containsObject:account]) return status;
    if (status != errSecItemNotFound && status != errSecSuccess) return status;
    if (status == errSecItemNotFound) {
        NSData *old = nil;
        status = legacy(account, false, false, &old, nil);
        bool approvedLegacy = status == errSecInteractionNotAllowed && interactive;
        if (approvedLegacy) status = legacy(account, false, true, &old, nil);
        if (status) return status;
        status = add(account, old, presence);
        if (status && status != errSecDuplicateItem) return status;
        bool inserted = status == errSecSuccess;
        if (inserted && approvedLegacy) {
            // The OS just authorized this legacy read. Retain the original until a modern read succeeds.
            *output = (__bridge_retained CFDataRef)old;
            return errSecSuccess;
        }
        // A racing insert wins; only its real ACL can authorize returning bytes.
        status = readModern(account, output);
        if (status) return status;
        if (inserted && ![old isEqual:(__bridge NSData *)*output]) {
            CFRelease(*output);
            *output = NULL;
            return errSecDecode;
        }
    }
    // Resume an interrupted migration only after the new protected item is readable.
    status = legacy(account, true, false, NULL, (__bridge NSData *)*output);
    if (!status || status == errSecItemNotFound) [legacyCleared addObject:account];
    // A locked legacy ACL delays cleanup, not a separately authorized modern read.
    return errSecSuccess;
}

OSStatus frameleaf_keychain(FrameleafKeychainOperation operation, const char *name, bool presence, unsigned prompt,
                            const void *bytes, size_t size, CFDataRef *output) {
    @autoreleasepool {
        @synchronized ([LAContext class]) {
            if (!session) session = [[LAContext alloc] init];
            if (!legacyCleared) legacyCleared = [NSMutableSet set];
            // Concurrent startup reads share both a successful context and a cancellation until an explicit retry.
            if (prompt == 2) cancelled = false; // An explicit user retry re-arms the sheet.
            bool interactive = prompt != 0 && !cancelled;
            session.interactionNotAllowed = !interactive || !presence;
            session.localizedReason = @"Unlock your saved Frameleaf sign-in";
            NSString *account = [NSString stringWithUTF8String:name];
            if (!account.length) return errSecParam;
            OSStatus status;
            if (operation == FrameleafKeychainRead) {
                status = readAccount(account, presence, interactive, output);
            } else if (operation == FrameleafKeychainConfirm) {
                // Verify the item just written; never consult a legacy item in its place.
                status = readModern(account, output);
            } else if (operation == FrameleafKeychainWrite) {
                NSData *value = [NSData dataWithBytesNoCopy:(void *)bytes length:size freeWhenDone:NO];
                status = add(account, value, presence);
                if (status == errSecDuplicateItem) {
                    status = SecItemUpdate((__bridge CFDictionaryRef)query(account),
                        (__bridge CFDictionaryRef)@{KEY(kSecValueData): value});
                }
            } else if (operation == FrameleafKeychainDelete) {
                // Delete legacy first so an interrupted sign-out can never resurrect an old grant.
                status = legacy(account, true, false, NULL, nil);
                if (!status || status == errSecItemNotFound)
                    status = SecItemDelete((__bridge CFDictionaryRef)query(account));
            } else {
                return errSecParam;
            }
            session.interactionNotAllowed = YES;
            if (status == errSecUserCanceled || (interactive && status == errSecAuthFailed)) {
                cancelled = true;
                [session invalidate];
                session = nil;
            }
            return status;
        }
    }
}
