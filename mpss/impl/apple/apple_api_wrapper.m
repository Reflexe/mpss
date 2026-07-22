// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include "mpss/impl/apple/apple_result.h"
#include "mpss/log_c.h"

// Global dictionary to store SecKeyRef instances.
static dispatch_queue_t _keyStoreQueue; // NOLINT(bugprone-reserved-identifier)
static NSMutableDictionary<NSString *, id> *_keyStore; // NOLINT(bugprone-reserved-identifier)

void InitializeKeyStore() {
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    _keyStoreQueue = dispatch_queue_create("com.microsoft.mpss.KeyStore", DISPATCH_QUEUE_SERIAL);
    _keyStore = [[NSMutableDictionary alloc] init];
  });
}

void SetThreadLocalError(NSString *error) {
  [[NSThread currentThread].threadDictionary setObject:error forKey:@"MyThreadLocalError"];
}

NSString *GetThreadLocalError() {
  return [[NSThread currentThread].threadDictionary objectForKey:@"MyThreadLocalError"];
}

void ClearThreadLocalError() {
  [[NSThread currentThread].threadDictionary removeObjectForKey:@"MyThreadLocalError"];
}

NSString *GetKeyLabel(const char *keyName) {
  NSString *keyLabel = [NSString stringWithUTF8String:keyName];
  NSString *keyNameWithPrefix = [NSString stringWithFormat:@"com.microsoft.mpss.%@", keyLabel];
  return keyNameWithPrefix;
}

void StoreKey(NSString *keyLabel, SecKeyRef keyRef) {
  InitializeKeyStore();

  if (keyLabel && keyRef) {
    dispatch_sync(_keyStoreQueue, ^{
      _keyStore[keyLabel] = (__bridge id)keyRef;
    });
  }
}

SecKeyRef CopyKey(NSString *keyLabel) {
  InitializeKeyStore();

  __block SecKeyRef result = NULL;
  dispatch_sync(_keyStoreQueue, ^{
    result = (__bridge SecKeyRef)(_keyStore[keyLabel]);
    if (result) {
      CFRetain(result);
    }
  });
  return result;
}

void RemoveKey(NSString *keyLabel) {
  InitializeKeyStore();

  dispatch_sync(_keyStoreQueue, ^{
    if (_keyStore[keyLabel]) {
      [_keyStore removeObjectForKey:keyLabel];
    }
  });
}

int GetKeySize(SecKeyRef keyRef) {
  // Retrieve the key size.
  CFDictionaryRef attrs = SecKeyCopyAttributes(keyRef);
  NSNumber *keySizeNumber =
      (__bridge NSNumber *)CFDictionaryGetValue(attrs, kSecAttrKeySizeInBits);
  int bitSize = [keySizeNumber intValue];
  CFRelease(attrs);

  return bitSize;
}

SecKeyAlgorithm GetAlgorithm(int signatureType) {
  switch (signatureType) {
  case 1: // ECDSA SHA 256
    return kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
  case 2: // ECDSA SHA 384
    return kSecKeyAlgorithmECDSASignatureDigestX962SHA384;
  case 3: // ECDSA SHA 512
    return kSecKeyAlgorithmECDSASignatureDigestX962SHA512;
  default:
    mpss_log_warning("Unsupported signature type.");
    return NULL;
  }
}

int GetKeyBitSize(int signatureType) {
  switch (signatureType) {
  case 1: // ECDSA SHA 256
    return 256;
  case 2: // ECDSA SHA 384
    return 384;
  case 3: // ECDSA SHA 512
    return 521;
  default:
    mpss_log_warning("Unsupported signature type.");
    return -1;
  }
}

// The Keychain key type every MPSS-created key uses on this platform. Centralized so the create,
// open, and delete match filters stay in lockstep: the open/delete filters accept exactly what
// create produces. Adding a non-EC scheme is a single-point change here (the open query would then
// need to match a set of types rather than one).
static id SupportedKeychainKeyType() {
  return (id)kSecAttrKeyTypeECSECPrimeRandom;
}

static bool IsExpectedVerificationFailure(CFErrorRef error) {
  return error != NULL &&
         CFEqual(CFErrorGetDomain(error), kCFErrorDomainOSStatus) &&
         CFErrorGetCode(error) == errSecVerifyFailed;
}

static int32_t OpenExistingKeyInternal(NSString *keyLabel, int *bitSize) {
  SecKeyRef keyRef = CopyKey(keyLabel);

  if (keyRef) {
    mpss_log_debug("Found existing key in local dictionary.");
    *bitSize = GetKeySize(keyRef);
    CFRelease(keyRef);
    return MPSS_APPLE_RESULT_SUCCESS;
  }

  mpss_log_debug("Did not find key in local dictionary, querying from OS.");

  NSDictionary *query = @{
    (id)kSecClass : (__bridge id)kSecClassKey,
    (id)kSecAttrKeyType : SupportedKeychainKeyType(),
    (id)kSecAttrApplicationTag :
        [keyLabel dataUsingEncoding:NSUTF8StringEncoding],
    (id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPrivate,
    (id)kSecReturnRef : @YES,
    (id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne
  };

  OSStatus status =
      SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&keyRef);

  if (status == errSecSuccess) {
    mpss_log_debug("Retrieved key from OS.");
    StoreKey(keyLabel, keyRef);
    *bitSize = GetKeySize(keyRef);
    CFRelease(keyRef);
    return MPSS_APPLE_RESULT_SUCCESS;
  }

  if (status == errSecItemNotFound) {
    return MPSS_APPLE_RESULT_EXPECTED_NEGATIVE;
  }

  NSString *error = [NSString
      stringWithFormat:@"Failed to retrieve key with status: %d", (int)status];
  SetThreadLocalError(error);
  return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
}

////////////////////////////////////////////////////////
// From here on below, the public functions.
////////////////////////////////////////////////////////

void MPSS_RemoveKey(const char *keyName) {
  @autoreleasepool {
    NSString *keyLabel = GetKeyLabel(keyName);
    RemoveKey(keyLabel);
  }
}

int32_t MPSS_OpenExistingKey(const char *keyName, int *bitSize) {
  ClearThreadLocalError();
  if (keyName == NULL || bitSize == NULL) {
    SetThreadLocalError(@"Invalid parameters (keyName or bitSize is NULL).");
    return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
  }

  @autoreleasepool {
    NSString *keyLabel = GetKeyLabel(keyName);
    return OpenExistingKeyInternal(keyLabel, bitSize);
  }
}

bool MPSS_CreateKey(const char *keyName, int bitSize) {
  ClearThreadLocalError();
  if (keyName == NULL) {
    SetThreadLocalError(@"Invalid parameter (keyName is NULL).");
    return false;
  }

  // Define key attributes.
  @autoreleasepool {
    int existingBitSize = 0;
    NSString *keyLabel = GetKeyLabel(keyName);
    const int32_t openResult =
        OpenExistingKeyInternal(keyLabel, &existingBitSize);
    if (openResult == MPSS_APPLE_RESULT_SUCCESS) {
      NSString *error = [NSString stringWithFormat:@"Key %s already exists.", keyName];
      SetThreadLocalError(error);
      return false;
    }
    if (openResult == MPSS_APPLE_RESULT_OPERATIONAL_ERROR) {
      return false;
    }
    if (openResult != MPSS_APPLE_RESULT_EXPECTED_NEGATIVE) {
      NSString *error = [NSString
          stringWithFormat:@"Open returned invalid result: %d", openResult];
      SetThreadLocalError(error);
      return false;
    }

    int keyBitSize = GetKeyBitSize(bitSize);
    mpss_log_debug([[NSString stringWithFormat:@"Key bit size: %d", keyBitSize] UTF8String]);
    if (keyBitSize == -1) {
      NSString *error = [NSString stringWithFormat:@"Unsupported bit size: %d", bitSize];
      SetThreadLocalError(error);
      return false;
    }

    mpss_log_debug([[NSString stringWithFormat:@"Creating key with bit size %d", keyBitSize] UTF8String]);
    NSDictionary *privateKeyAttributes = @{
      (id)kSecAttrIsPermanent : @YES,
      (id)kSecAttrLabel : keyLabel,
      (id)kSecAttrApplicationTag :
          [keyLabel dataUsingEncoding:NSUTF8StringEncoding],
      (id)kSecAttrAccessible :
          (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    };
    NSDictionary *keyAttributes = @{
      (id)kSecAttrKeyType : SupportedKeychainKeyType(),
      (id)kSecAttrKeySizeInBits : @(keyBitSize), // NOLINT(readability-redundant-parentheses)
      (id)kSecPrivateKeyAttrs : privateKeyAttributes
    };

    // Generate the key.
    CFErrorRef error = NULL;
    SecKeyRef keyRef =
        SecKeyCreateRandomKey((__bridge CFDictionaryRef)keyAttributes, &error);

    if (keyRef == NULL) {
      NSError *err = CFBridgingRelease(error);
      NSString *error =
          [NSString stringWithFormat:@"Failed to generate key: %@", err];
      SetThreadLocalError(error);
      return false;
    }

    mpss_log_trace("Key generated successfully.");
    StoreKey(keyLabel, keyRef);
    CFRelease(keyRef);

    return true;
  }
}

bool MPSS_SignHash(const char *keyName, int signatureType, const uint8_t *hash,
                   size_t hashSize, uint8_t *signature, size_t *signatureSize) {
  ClearThreadLocalError();
  if (keyName == NULL || hash == NULL || signature == NULL ||
      signatureSize == NULL) {
    SetThreadLocalError(
        @"Invalid parameters (keyName, hash, signature, or signatureSize is NULL).");
    return false;
  }

  @autoreleasepool {
    NSString *keyLabel = GetKeyLabel(keyName);
    SecKeyRef keyRef = CopyKey(keyLabel);

    if (keyRef == NULL) {
      mpss_log_debug("Key not found.");
      SetThreadLocalError(@"Key not found.");
      return false;
    }

    NSData *hashData = [NSData dataWithBytes:hash length:hashSize];

    SecKeyAlgorithm algorithm = GetAlgorithm(signatureType);
    if (algorithm == NULL) {
      NSString *error = [NSString stringWithFormat:@"Unsupported signature type: %d", signatureType];
      SetThreadLocalError(error);
      CFRelease(keyRef);
      return false;
    }

    CFErrorRef error = NULL;
    CFDataRef signatureData = SecKeyCreateSignature(keyRef, algorithm, (__bridge CFDataRef)hashData, &error);
    CFRelease(keyRef);

    if (signatureData == NULL) {
      NSError *err = CFBridgingRelease(error);
      NSString *error = [NSString stringWithFormat:@"Failed to sign hash: %@", err];
      SetThreadLocalError(error);
      return false;
    }

    size_t signatureDataSize = CFDataGetLength(signatureData);
    if (*signatureSize < signatureDataSize) {
      NSString *error =
          [NSString stringWithFormat:@"Insufficient buffer provided. Buffer "
                                     @"size: %lu, signature size: %lu",
                                     *signatureSize, signatureDataSize];
      SetThreadLocalError(error);
      CFRelease(signatureData);
      return false;
    }

    // Actual signature size.
    *signatureSize = signatureDataSize;

    // Copy signature.
    memcpy(signature, CFDataGetBytePtr(signatureData), signatureDataSize);
    mpss_log_debug([[NSString stringWithFormat:@"Signature created successfully. Signature size: %lu",
          signatureDataSize] UTF8String]);

    CFRelease(signatureData);

    return true;
  }
}

int32_t MPSS_VerifySignature(const char *keyName, int signatureType,
                             const uint8_t *hash, size_t hashSize,
                             const uint8_t *signature,
                             size_t signatureSize) {
  ClearThreadLocalError();
  if (keyName == NULL || hash == NULL || signature == NULL) {
    SetThreadLocalError(
        @"Invalid parameters (keyName, hash, or signature is NULL).");
    return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
  }

  @autoreleasepool {
    NSString *keyLabel = GetKeyLabel(keyName);
    SecKeyRef keyRef = CopyKey(keyLabel);

    if (keyRef == NULL) {
      NSString *error = @"Key not found.";
      SetThreadLocalError(error);
      return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
    }

    NSData *hashData = [NSData dataWithBytes:hash length:hashSize];
    NSData *signatureData = [NSData dataWithBytes:signature length:signatureSize];

    SecKeyAlgorithm algorithm = GetAlgorithm(signatureType);
    if (algorithm == NULL) {
      NSString *error = [NSString stringWithFormat:@"Unsupported signature type: %d", signatureType];
      SetThreadLocalError(error);
      CFRelease(keyRef);
      return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
    }

    SecKeyRef publicKeyRef = SecKeyCopyPublicKey(keyRef);
    CFRelease(keyRef);
    if (!publicKeyRef) {
      NSString *error = @"Could not copy public key.";
      SetThreadLocalError(error);
      return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
    }

    CFErrorRef error = NULL;
    bool result = SecKeyVerifySignature(
        publicKeyRef, algorithm, (__bridge CFDataRef)hashData,
        (__bridge CFDataRef)signatureData, &error);

    // Release public key.
    CFRelease(publicKeyRef);

    if (result) {
      if (error != NULL) {
        CFRelease(error);
      }
      return MPSS_APPLE_RESULT_SUCCESS;
    }

    const bool expectedNegative = IsExpectedVerificationFailure(error);
    if (!expectedNegative) {
      NSString *detail =
          error == NULL ? @"No platform error detail."
                        : [(__bridge NSError *)error description];
      NSString *errorMessage =
          [NSString stringWithFormat:@"Failed to verify signature: %@", detail];
      SetThreadLocalError(errorMessage);
    }
    if (error != NULL) {
      CFRelease(error);
    }
    return expectedNegative ? MPSS_APPLE_RESULT_EXPECTED_NEGATIVE
                            : MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
  }
}

int32_t MPSS_VerifyStandaloneSignature(
    int signatureType, const uint8_t *hash, size_t hashSize,
    const uint8_t *publicKey, size_t publicKeySize,
    const uint8_t *signature, size_t signatureSize) {
  ClearThreadLocalError();
  if (hash == NULL || publicKey == NULL || signature == NULL) {
    SetThreadLocalError(@"Invalid parameters (hash, publicKey, or signature is NULL).");
    return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
  }

  @autoreleasepool {
    NSData *hashData = [NSData dataWithBytes:hash length:hashSize];
    NSData *signatureData = [NSData dataWithBytes:signature length:signatureSize];
    NSData *publicKeyData = [NSData dataWithBytes:publicKey length:publicKeySize];

    SecKeyAlgorithm algorithm = GetAlgorithm(signatureType);
    mpss_log_debug([[NSString stringWithFormat:@"Algorithm: %@", algorithm] UTF8String]);
    if (algorithm == NULL) {
      NSString *error = [NSString stringWithFormat:@"Unsupported signature type: %d", signatureType];
      SetThreadLocalError(error);
      return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
    }

    int keyBitSize = GetKeyBitSize(signatureType);
    mpss_log_debug([[NSString stringWithFormat:@"Key bit size: %d", keyBitSize] UTF8String]);

    if (keyBitSize == -1) {
      NSString *error = [NSString stringWithFormat:@"Unsupported signature type: %d", signatureType];
      SetThreadLocalError(error);
      return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
    }

    // Create public key attributes.
    NSDictionary *keyAttributes = @{
      (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
      (id)kSecAttrKeyClass : (id)kSecAttrKeyClassPublic,
      (id)kSecAttrKeySizeInBits : @(keyBitSize), // NOLINT(readability-redundant-parentheses)
      (id)kSecAttrIsPermanent : @NO
    };

    // Create public key from raw bytes.
    CFErrorRef error = NULL;
    SecKeyRef publicKeyRef =
        SecKeyCreateWithData((__bridge CFDataRef)publicKeyData,
                             (__bridge CFDictionaryRef)keyAttributes, &error);

    if (!publicKeyRef) {
      NSError *err = CFBridgingRelease(error);
      NSString *error = [NSString stringWithFormat:@"Failed to create public key from data: %@", err];
      SetThreadLocalError(error);
      return MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
    }

    // Verify the signature.
    bool result = SecKeyVerifySignature(
        publicKeyRef, algorithm, (__bridge CFDataRef)hashData,
        (__bridge CFDataRef)signatureData, &error);

    // Release public key.
    CFRelease(publicKeyRef);

    if (result) {
      if (error != NULL) {
        CFRelease(error);
      }
      return MPSS_APPLE_RESULT_SUCCESS;
    }

    const bool expectedNegative = IsExpectedVerificationFailure(error);
    if (!expectedNegative) {
      NSString *detail =
          error == NULL ? @"No platform error detail."
                        : [(__bridge NSError *)error description];
      NSString *errorMessage = [NSString
          stringWithFormat:@"Failed to verify standalone signature: %@", detail];
      SetThreadLocalError(errorMessage);
    }
    if (error != NULL) {
      CFRelease(error);
    }
    return expectedNegative ? MPSS_APPLE_RESULT_EXPECTED_NEGATIVE
                            : MPSS_APPLE_RESULT_OPERATIONAL_ERROR;
  }
}

bool MPSS_GetPublicKey(const char *keyName, uint8_t *pk, size_t *pkSize) {
  ClearThreadLocalError();
  if (NULL == keyName || NULL == pk || NULL == pkSize) {
    SetThreadLocalError(
        @"Invalid parameters (keyName, pk, or pkSize is NULL).");
    return false;
  }

  @autoreleasepool {
    NSString *keyLabel = GetKeyLabel(keyName);
    SecKeyRef keyRef = CopyKey(keyLabel);

    if (keyRef == NULL) {
      NSString *error = @"Key not found.";
      SetThreadLocalError(error);
      return false;
    }

    SecKeyRef publicKeyRef = SecKeyCopyPublicKey(keyRef);
    CFRelease(keyRef);
    if (publicKeyRef == NULL) {
      NSString *error = @"Could not copy public key.";
      SetThreadLocalError(error);
      return false;
    }

    // Get PK data.
    CFErrorRef error = NULL;
    CFDataRef pkData = SecKeyCopyExternalRepresentation(publicKeyRef, &error);

    if (!pkData) {
      NSError *err = CFBridgingRelease(error);
      NSString *errStr = [NSString
          stringWithFormat:@"Failed to copy public key external representation: %@", err];
      SetThreadLocalError(errStr);
      CFRelease(publicKeyRef);
      return false;
    }

    // Get raw bytes.
    CFIndex length = CFDataGetLength(pkData);
    const UInt8 *pkBytes = CFDataGetBytePtr(pkData);

    if (*pkSize < length) {
      NSString *errStr = [NSString
          stringWithFormat:@"Insufficient buffer. Provided: %lu, needed: %lu", *pkSize, length];
      SetThreadLocalError(errStr);
      CFRelease(pkData);
      CFRelease(publicKeyRef);
      return false;
    }

    memcpy(pk, pkBytes, length);
    // Actual size.
    *pkSize = length;

    CFRelease(pkData);
    CFRelease(publicKeyRef);

    return true;
  }
}

bool MPSS_DeleteKey(const char *keyName) {
  ClearThreadLocalError();
  if (keyName == NULL) {
    SetThreadLocalError(@"Invalid parameter (keyName is NULL).");
    return false;
  }

  @autoreleasepool {
    NSString *keyLabel = GetKeyLabel(keyName);
    RemoveKey(keyLabel);

    NSString *op_status = @"";

    // Create query to delete private key.
    NSMutableDictionary *query = [@{
      (id)kSecClass : (__bridge id)kSecClassKey,
      (id)kSecAttrKeyType : SupportedKeychainKeyType(),
      (id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPrivate,
      (id)kSecAttrApplicationTag : [keyLabel dataUsingEncoding:NSUTF8StringEncoding]
    } mutableCopy];

    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);

    if (status == errSecSuccess) {
      mpss_log_trace("Deleted private key.");
    } else if (status == errSecItemNotFound) {
      mpss_log_trace("Private key not found, nothing to delete.");
    } else {
      // Append to status.
      op_status = [op_status
          stringByAppendingFormat:@"Private key deletion failed with status: %d", (int)status];
    }

    // Modify query to delete now public key.
    query[(id)kSecAttrKeyClass] = (__bridge id)kSecAttrKeyClassPublic;

    status = SecItemDelete((__bridge CFDictionaryRef)query);

    if (status == errSecSuccess) {
      mpss_log_trace("Deleted public key.");
    } else if (status == errSecItemNotFound) {
      mpss_log_trace("Public key not found, nothing to delete.");
    } else {
      // Append to status.
      op_status = [op_status
          stringByAppendingFormat:@"Public key deletion failed with status: %d", (int)status];
    }

    if ([op_status length] > 0) {
      SetThreadLocalError(op_status);
      return false;
    }

    return true;
  }
}

size_t MPSS_GetLastError(char *error, size_t errorSize) {
  @autoreleasepool {
    NSString *lastError = GetThreadLocalError() ?: @"";
    const char *utf8 = [lastError UTF8String];
    size_t need = strlen(utf8);
    if (error == NULL) {
      // Size query: report the needed length without consuming the error.
      return need;
    }
    if (errorSize < need) {
      return 0;
    }
    // Copy while the autorelease pool (and thus utf8) is still alive.
    memcpy(error, utf8, need);
    // Clear on read so a later failure that sets no error cannot surface this stale one.
    ClearThreadLocalError();
    return need;
  }
}
