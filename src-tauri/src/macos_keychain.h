#import <Security/Security.h>

typedef enum : unsigned {
    FrameleafKeychainRead, FrameleafKeychainWrite, FrameleafKeychainDelete, FrameleafKeychainConfirm
} FrameleafKeychainOperation;

OSStatus frameleaf_keychain(FrameleafKeychainOperation operation, const char *name, bool presence,
                            unsigned prompt, const void *bytes, size_t size, CFDataRef *output);
