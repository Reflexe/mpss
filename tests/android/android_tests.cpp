// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/android/JNIHelper.h"
#include "mpss/impl/android/JNIObject.h"
#include "mpss/impl/android/android_keypair.h"
#include "mpss/impl/android/android_utils.h"
#include "mpss/log.h"
#include "mpss/mpss.h"
#include "mpss/utils/scope_guard.h"
#include "mpss/utils/utilities.h"
#include <array>
#include <cstddef>
#include <future>
#include <gtest/gtest.h>
#include <latch>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace mpss::tests
{

namespace
{

using jni_bytearray = mpss::impl::os::utils::JNIObj<jbyteArray>;
using jni_object = mpss::impl::os::utils::JNIObj<jobject>;
using jni_string = mpss::impl::os::utils::JNIObj<jstring>;

std::vector<std::byte> java_sign_hash(std::string_view key_name, std::span<const std::byte> hash)
{
    mpss::impl::os::JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::GetLogger()->error("Could not get JNI environment.");
        return {};
    }
    JNIEnv *const env = guard.env();

    jclass key_management = mpss::impl::os::JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::GetLogger()->error("Could not get KeyManagement Java class.");
        return {};
    }

    jmethodID method = env->GetStaticMethodID(key_management, "SignHash", "(Ljava/lang/String;[B)[B");
    if (mpss::impl::os::utils::check_and_clear_exception(env, "resolving KeyManagement.SignHash"))
    {
        return {};
    }
    if (nullptr == method)
    {
        mpss::GetLogger()->error("Could not get KeyManagement.SignHash Java method.");
        return {};
    }

    const std::string key_name_string{key_name};
    jni_string java_key_name(env, env->NewStringUTF(key_name_string.c_str()));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return {};
    }
    jni_bytearray java_hash(env, mpss::impl::os::utils::to_jbyte_array(env, hash));
    if (java_key_name.is_null() || java_hash.is_null())
    {
        mpss::GetLogger()->error("Could not convert standalone-signing inputs to Java.");
        return {};
    }

    jni_bytearray java_signature(env, reinterpret_cast<jbyteArray>(env->CallStaticObjectMethod(
                                          key_management, method, java_key_name.get(), java_hash.get())));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "calling KeyManagement.SignHash"))
    {
        return {};
    }
    if (java_signature.is_null())
    {
        mpss::impl::os::utils::report_java_error(env, "KeyManagement.SignHash");
        mpss::GetLogger()->error("{}", mpss::get_error());
        return {};
    }

    const jsize signature_size = env->GetArrayLength(java_signature.get());
    if (mpss::impl::os::utils::check_and_clear_exception(env, "getting a Java signature length"))
    {
        return {};
    }
    if (0 >= signature_size)
    {
        mpss::GetLogger()->error("KeyManagement.SignHash returned an empty signature.");
        return {};
    }

    std::vector<std::byte> signature(static_cast<std::size_t>(signature_size));
    const std::size_t copied = mpss::impl::os::utils::copy_jbyte_array_to_span(env, java_signature.get(), signature);
    if (signature.size() != copied)
    {
        return {};
    }
    return signature;
}

bool java_verify_signature(std::span<const std::byte> hash, std::span<const std::byte> public_key,
                           std::span<const std::byte> signature)
{
    mpss::impl::os::JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::GetLogger()->error("Could not get JNI environment.");
        return false;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = mpss::impl::os::JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::GetLogger()->error("Could not get KeyManagement Java class.");
        return false;
    }

    jmethodID method = env->GetStaticMethodID(key_management, "VerifySignature", "([B[B[B)Ljava/lang/Boolean;");
    if (mpss::impl::os::utils::check_and_clear_exception(env, "resolving KeyManagement.VerifySignature"))
    {
        return false;
    }
    if (nullptr == method)
    {
        mpss::GetLogger()->error("Could not get KeyManagement.VerifySignature Java method.");
        return false;
    }

    jni_bytearray java_hash(env, mpss::impl::os::utils::to_jbyte_array(env, hash));
    jni_bytearray java_signature(env, mpss::impl::os::utils::to_jbyte_array(env, signature));
    jni_bytearray java_public_key(env, mpss::impl::os::utils::to_jbyte_array(env, public_key));
    if (java_hash.is_null() || java_signature.is_null() || java_public_key.is_null())
    {
        mpss::GetLogger()->error("Could not convert standalone-verification inputs to Java.");
        return false;
    }

    jni_object result(env, env->CallStaticObjectMethod(key_management, method, java_hash.get(), java_signature.get(),
                                                       java_public_key.get()));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "calling KeyManagement.VerifySignature"))
    {
        return false;
    }
    if (result.is_null())
    {
        mpss::impl::os::utils::report_java_error(env, "KeyManagement.VerifySignature");
        mpss::GetLogger()->error("{}", mpss::get_error());
        return false;
    }

    const std::optional<bool> verified = mpss::impl::os::utils::unbox_boolean(env, result.get());
    return verified.value_or(false);
}

std::optional<bool> java_key_operation(std::string_view operation, std::string_view key_name)
{
    mpss::impl::os::JNIEnvGuard guard;
    if (!guard.valid())
    {
        mpss::utils::set_error("Could not get JNI environment.");
        return std::nullopt;
    }
    JNIEnv *const env = guard.env();

    jclass key_management = mpss::impl::os::JNIHelper::key_management_class();
    if (nullptr == key_management)
    {
        mpss::utils::set_error("Could not get KeyManagement Java class.");
        return std::nullopt;
    }

    const std::string operation_string{operation};
    jmethodID method =
        env->GetStaticMethodID(key_management, operation_string.c_str(), "(Ljava/lang/String;)Ljava/lang/Boolean;");
    if (mpss::impl::os::utils::check_and_clear_exception(env, "resolving KeyManagement operation"))
    {
        return std::nullopt;
    }
    if (nullptr == method)
    {
        mpss::utils::set_error("Could not get KeyManagement Java method.");
        return std::nullopt;
    }

    const std::string key_name_string{key_name};
    jni_string java_key_name(env, env->NewStringUTF(key_name_string.c_str()));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "converting an Android key name to a Java string"))
    {
        return std::nullopt;
    }
    if (java_key_name.is_null())
    {
        mpss::utils::set_error("Could not convert key name to Java String.");
        return std::nullopt;
    }

    jni_object result(env, env->CallStaticObjectMethod(key_management, method, java_key_name.get()));
    if (mpss::impl::os::utils::check_and_clear_exception(env, "calling KeyManagement operation"))
    {
        return std::nullopt;
    }
    if (result.is_null())
    {
        const std::string operation_name = "KeyManagement." + operation_string;
        mpss::impl::os::utils::report_java_error(env, operation_name);
        return std::nullopt;
    }

    return mpss::impl::os::utils::unbox_boolean(env, result.get());
}

} // namespace

// Scenario: hardware isolation is requested for StrongBox-supported and unsupported algorithms.
// Expected behavior: normal Android Keystore fallback is never eligible.
TEST(AndroidIsolationPolicyTest, HardwareRequestsNeverUseNormalKeystoreFallback)
{
    using enum mpss::Algorithm;
    using enum mpss::IsolationLevel;
    using enum mpss::impl::os::AndroidCreateOutcome;

    EXPECT_TRUE(mpss::impl::os::android_strongbox_supports(ecdsa_secp256r1_sha256));
    EXPECT_FALSE(mpss::impl::os::android_should_try_normal_keystore(hardware, unavailable));
    EXPECT_FALSE(mpss::impl::os::android_strongbox_supports(ecdsa_secp384r1_sha384));
    EXPECT_FALSE(mpss::impl::os::android_should_try_normal_keystore(hardware, not_attempted));
}

// Scenario: Android reports StrongBox, Trusted Environment, and Software security levels for mixed isolation.
// Expected behavior: mixed accepts StrongBox and TEE evidence but rejects software evidence.
TEST(AndroidIsolationPolicyTest, MixedAcceptsStrongBoxAndTeeButRejectsSoftware)
{
    using enum mpss::IsolationLevel;

    const std::optional<mpss::KeyInfo> strongbox = mpss::impl::os::android_key_info_from_security_level(4);
    const std::optional<mpss::KeyInfo> tee = mpss::impl::os::android_key_info_from_security_level(3);
    const std::optional<mpss::KeyInfo> software_key_info =
        mpss::impl::os::android_key_info_from_security_level(1);

    ASSERT_TRUE(strongbox.has_value());
    ASSERT_TRUE(tee.has_value());
    ASSERT_TRUE(software_key_info.has_value());
    EXPECT_TRUE(mpss::meets_minimum_isolation(strongbox->isolation_level, mixed));
    EXPECT_TRUE(mpss::meets_minimum_isolation(tee->isolation_level, mixed));
    EXPECT_FALSE(mpss::meets_minimum_isolation(software_key_info->isolation_level, mixed));
}

// Scenario: software isolation is requested and the StrongBox attempt is unavailable.
// Expected behavior: StrongBox remains the first candidate and normal Android Keystore fallback stays eligible.
TEST(AndroidIsolationPolicyTest, SoftwarePreservesStrongestFirstFallback)
{
    using enum mpss::Algorithm;
    using enum mpss::IsolationLevel;
    using enum mpss::impl::os::AndroidCreateOutcome;

    EXPECT_TRUE(mpss::impl::os::android_strongbox_supports(ecdsa_secp256r1_sha256));
    EXPECT_TRUE(mpss::impl::os::android_should_try_normal_keystore(software, unavailable));
}

// Scenario: StrongBox is unavailable, succeeds with underqualified evidence, or fails operationally.
// Expected behavior: only unavailability permits a qualifying normal-Keystore fallback; success and errors abort it.
TEST(AndroidIsolationPolicyTest, StrongBoxFallbackRequiresUnavailableOutcome)
{
    using enum mpss::IsolationLevel;
    using enum mpss::impl::os::AndroidCreateOutcome;

    EXPECT_TRUE(mpss::impl::os::android_should_try_normal_keystore(mixed, unavailable));
    EXPECT_FALSE(mpss::impl::os::android_should_try_normal_keystore(mixed, created));
    EXPECT_FALSE(mpss::impl::os::android_should_try_normal_keystore(mixed, operational_error));
    EXPECT_FALSE(mpss::impl::os::android_should_try_normal_keystore(hardware, unavailable));
}

// Scenario: Android reports its two compatibility security levels on older or indeterminate platforms.
// Expected behavior: Unknown Secure maps to mixed isolation and Unknown maps to software isolation.
TEST(AndroidIsolationPolicyTest, UnknownSecurityLevelsMapExactly)
{
    using enum mpss::IsolationLevel;

    const std::optional<mpss::KeyInfo> unknown_secure = mpss::impl::os::android_key_info_from_security_level(2);
    const std::optional<mpss::KeyInfo> unknown = mpss::impl::os::android_key_info_from_security_level(0);

    ASSERT_TRUE(unknown_secure.has_value());
    ASSERT_TRUE(unknown.has_value());
    EXPECT_EQ(mixed, unknown_secure->isolation_level);
    EXPECT_STREQ("Unknown Secure", unknown_secure->storage_description);
    EXPECT_EQ(software, unknown->isolation_level);
    EXPECT_STREQ("Unknown", unknown->storage_description);
}

// Scenario: Android security evidence cannot be queried or has an unrecognized platform value.
// Expected behavior: no isolation properties are produced, so creation and open fail closed.
TEST(AndroidIsolationPolicyTest, SecurityLevelQueryFailureFailsClosed)
{
    EXPECT_FALSE(mpss::impl::os::android_key_info_from_security_level(-1).has_value());
    EXPECT_FALSE(mpss::impl::os::android_key_info_from_security_level(5).has_value());
}

// Scenario: normal Android Keystore produces a software P-384 key while mixed isolation is required.
// Expected behavior: the underqualified newly created key is deleted and never returned.
TEST(AndroidIsolationPolicyTest, UnderqualifiedCreatedKeyIsDeleted)
{
    using enum mpss::Algorithm;
    using enum mpss::IsolationLevel;

    if (!mpss::is_algorithm_available(ecdsa_secp384r1_sha384, software))
    {
        GTEST_SKIP() << "P-384 is not supported by the Android backend.";
    }

    const std::string probe_name = "test_android_underqualified_create_probe";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(probe_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }
    std::unique_ptr<mpss::KeyPair> probe =
        mpss::KeyPair::Create(probe_name, ecdsa_secp384r1_sha384, mpss::KeyPolicy::none, software);
    ASSERT_NE(nullptr, probe) << mpss::get_error();
    if (software != probe->key_info().isolation_level)
    {
        ASSERT_TRUE(probe->delete_key());
        GTEST_SKIP() << "Normal Android Keystore is isolated above software on this device.";
    }
    ASSERT_TRUE(probe->delete_key());

    const std::string key_name = "test_android_underqualified_create";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }
    SCOPE_GUARD({
        if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
        {
            cleanup->delete_key();
        }
    });

    EXPECT_EQ(nullptr,
              mpss::KeyPair::Create(key_name, ecdsa_secp384r1_sha384, mpss::KeyPolicy::none, mixed));
    EXPECT_NE(std::string::npos, mpss::get_error().find("below requested minimum"));

    const std::optional<bool> persisted = java_key_operation("OpenKey", key_name);
    ASSERT_TRUE(persisted.has_value()) << mpss::get_error();
    EXPECT_FALSE(*persisted);
}

// Scenario: an existing normal-Keystore P-384 key is opened with a hardware minimum and then reopened.
// Expected behavior: the rejected open releases only its runtime handle and leaves the persisted key intact.
TEST(AndroidIsolationPolicyTest, UnderqualifiedExistingKeyRemainsPersisted)
{
    using enum mpss::Algorithm;
    using enum mpss::IsolationLevel;

    if (!mpss::is_algorithm_available(ecdsa_secp384r1_sha384, software))
    {
        GTEST_SKIP() << "P-384 is not supported by the Android backend.";
    }

    const std::string key_name = "test_android_underqualified_open";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }
    SCOPE_GUARD({
        if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
        {
            cleanup->delete_key();
        }
    });

    std::unique_ptr<mpss::KeyPair> created =
        mpss::KeyPair::Create(key_name, ecdsa_secp384r1_sha384, mpss::KeyPolicy::none, software);
    ASSERT_NE(nullptr, created) << mpss::get_error();
    created.reset();

    EXPECT_EQ(nullptr, mpss::KeyPair::Open(key_name, hardware));
    EXPECT_NE(std::string::npos, mpss::get_error().find("minimum isolation"));

    std::unique_ptr<mpss::KeyPair> reopened = mpss::KeyPair::Open(key_name, software);
    ASSERT_NE(nullptr, reopened) << mpss::get_error();
    ASSERT_TRUE(reopened->delete_key());
}

// Scenario: Android availability and direct creation request the same hardware minimum for P-384.
// Expected behavior: both reject the algorithm because hardware creation cannot use normal Keystore fallback.
TEST(AndroidIsolationPolicyTest, AvailabilityAndCreationApplyTheSameMinimum)
{
    using enum mpss::Algorithm;
    using enum mpss::IsolationLevel;

    EXPECT_FALSE(mpss::is_algorithm_available(ecdsa_secp384r1_sha384, hardware));

    const std::string key_name = "test_android_hardware_minimum";
    EXPECT_EQ(nullptr,
              mpss::KeyPair::Create(key_name, ecdsa_secp384r1_sha384, mpss::KeyPolicy::none, hardware));
    const std::optional<bool> persisted = java_key_operation("OpenKey", key_name);
    ASSERT_TRUE(persisted.has_value()) << mpss::get_error();
    EXPECT_FALSE(*persisted);
}

// Scenario: Android creates a key and reports one of the platform security-level descriptions.
// Expected behavior: each Android security-level description maps to the exact approved isolation level.
TEST(AndroidSecurityTest, MetadataMapsToExactIsolationLevel)
{
    using enum mpss::Algorithm;
    using enum mpss::IsolationLevel;

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Required algorithm is not supported by the Android backend.";
    }

    const std::string key_name = "test_android_isolation_metadata";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }
    SCOPE_GUARD({
        if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
        {
            cleanup->delete_key();
        }
    });

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, key);

    const std::string_view storage = key->key_info().storage_description;
    if ("StrongBox" == storage)
    {
        EXPECT_EQ(hardware, key->key_info().isolation_level);
    }
    else if ("Trusted Environment" == storage || "Unknown Secure" == storage)
    {
        EXPECT_EQ(mixed, key->key_info().isolation_level);
    }
    else if ("Software" == storage || "Unknown" == storage)
    {
        EXPECT_EQ(software, key->key_info().isolation_level);
    }
    else
    {
        FAIL() << "Unexpected Android storage description: " << storage;
    }
}

TEST(AndroidSecurityTest, StandaloneVerifyRejectsMismatchedAlgorithm)
{
    using enum mpss::Algorithm;

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256) || !mpss::is_algorithm_available(ecdsa_secp384r1_sha384))
    {
        GTEST_SKIP() << "Required algorithms are not supported by the Android backend.";
    }

    const std::string key_name = "test_android_algorithm_binding";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }

    SCOPE_GUARD({
        if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
        {
            cleanup->delete_key();
        }
    });

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(key_name, ecdsa_secp384r1_sha384);
    ASSERT_NE(nullptr, key);

    const std::vector<std::byte> hash(32, static_cast<std::byte>('a'));
    const std::vector<std::byte> signature = java_sign_hash(key_name, hash);
    ASSERT_FALSE(signature.empty());

    const std::size_t public_key_size = key->extract_key({});
    ASSERT_NE(0, public_key_size);
    std::vector<std::byte> public_key(public_key_size);
    ASSERT_EQ(public_key_size, key->extract_key(public_key));

    ASSERT_TRUE(java_verify_signature(hash, public_key, signature));
    ASSERT_FALSE(mpss::verify(hash, public_key, ecdsa_secp256r1_sha256, signature));
}

TEST(AndroidJNITest, KeyPairCanMoveBetweenNativeThreads)
{
    using enum mpss::Algorithm;

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Required algorithm is not supported by the Android backend.";
    }

    const std::string key_name = "test_android_native_thread_key";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }
    SCOPE_GUARD({
        if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
        {
            cleanup->delete_key();
        }
    });

    std::promise<std::unique_ptr<mpss::KeyPair>> key_promise;
    std::future<std::unique_ptr<mpss::KeyPair>> key_future = key_promise.get_future();
    std::string create_error;
    std::thread creator([&key_promise, &create_error, &key_name]() {
        std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
        if (nullptr == key)
        {
            create_error = mpss::get_error();
        }
        key_promise.set_value(std::move(key));
    });
    creator.join();

    std::unique_ptr<mpss::KeyPair> key = key_future.get();
    ASSERT_NE(nullptr, key) << create_error;

    const std::vector<std::byte> hash(32, static_cast<std::byte>('a'));
    bool succeeded = false;
    std::string use_error;
    std::thread user([key = std::move(key), &hash, &succeeded, &use_error]() mutable {
        std::vector<std::byte> signature(key->sign_hash(hash, {}));
        const std::size_t signature_size = key->sign_hash(hash, signature);
        if (0 == signature_size)
        {
            use_error = mpss::get_error();
            key.reset();
            return;
        }
        signature.resize(signature_size);

        std::vector<std::byte> public_key(key->extract_key({}));
        const std::size_t public_key_size = key->extract_key(public_key);
        if (0 == public_key_size)
        {
            use_error = mpss::get_error();
            key.reset();
            return;
        }
        public_key.resize(public_key_size);

        succeeded = key->verify(hash, signature) && mpss::verify(hash, public_key, ecdsa_secp256r1_sha256, signature);
        if (!succeeded)
        {
            use_error = mpss::get_error();
        }
        key.reset();
    });
    user.join();

    ASSERT_TRUE(succeeded) << use_error;
}

TEST(AndroidJNITest, ConcurrentNativeThreadsUseIndependentJNIState)
{
    using enum mpss::Algorithm;

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Required algorithm is not supported by the Android backend.";
    }

    const std::string key_name = "test_android_concurrent_jni";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }
    SCOPE_GUARD({
        if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
        {
            cleanup->delete_key();
        }
    });

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, key);

    const std::vector<std::byte> hash(32, static_cast<std::byte>('b'));
    std::vector<std::byte> signature(key->sign_hash(hash, {}));
    const std::size_t signature_size = key->sign_hash(hash, signature);
    ASSERT_NE(0, signature_size);
    signature.resize(signature_size);

    std::vector<std::byte> public_key(key->extract_key({}));
    const std::size_t public_key_size = key->extract_key(public_key);
    ASSERT_NE(0, public_key_size);
    public_key.resize(public_key_size);

    std::latch ready(2);
    std::latch start(1);
    std::array<bool, 2> succeeded{true, true};
    std::array<std::string, 2> errors;
    std::array<std::thread, 2> workers;
    for (std::size_t worker_index = 0; worker_index < workers.size(); ++worker_index)
    {
        workers[worker_index] = std::thread([&, worker_index]() {
            JavaVM *java_vm = nullptr;
            {
                mpss::impl::os::JNIEnvGuard overlap_guard;
                if (!overlap_guard.valid())
                {
                    succeeded[worker_index] = false;
                    errors[worker_index] = "Could not get JNI environment.";
                }
                else if (JNI_OK != overlap_guard->GetJavaVM(&java_vm))
                {
                    succeeded[worker_index] = false;
                    errors[worker_index] = "Could not get Java VM.";
                }

                ready.count_down();
                start.wait();
                if (succeeded[worker_index])
                {
                    for (std::size_t iteration = 0; iteration < 16; ++iteration)
                    {
                        if (!mpss::verify(hash, public_key, ecdsa_secp256r1_sha256, signature))
                        {
                            succeeded[worker_index] = false;
                            errors[worker_index] = mpss::get_error();
                            break;
                        }
                    }
                }

                JNIEnv *nested_env = nullptr;
                if (succeeded[worker_index] &&
                    JNI_OK != java_vm->GetEnv(reinterpret_cast<void **>(&nested_env), JNI_VERSION_1_6))
                {
                    succeeded[worker_index] = false;
                    errors[worker_index] = "Nested guard detached its native thread.";
                }
            }

            if (nullptr == java_vm)
            {
                return;
            }

            JNIEnv *detached_env = nullptr;
            if (JNI_EDETACHED != java_vm->GetEnv(reinterpret_cast<void **>(&detached_env), JNI_VERSION_1_6))
            {
                succeeded[worker_index] = false;
                errors[worker_index] = "Native thread remained attached after its outer guard was destroyed.";
            }
        });
    }

    ready.wait();
    start.count_down();
    for (std::thread &worker : workers)
    {
        worker.join();
    }

    ASSERT_TRUE(succeeded[0]) << errors[0];
    ASSERT_TRUE(succeeded[1]) << errors[1];
}

TEST(AndroidJNITest, ConcurrentKeyCacheAccessIsSafe)
{
    using enum mpss::Algorithm;

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Required algorithm is not supported by the Android backend.";
    }

    const std::array<std::string, 4> key_names{
        "test_android_concurrent_cache_0",
        "test_android_concurrent_cache_1",
        "test_android_concurrent_cache_2",
        "test_android_concurrent_cache_3",
    };
    for (const std::string &key_name : key_names)
    {
        if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
        {
            ASSERT_TRUE(existing->delete_key());
        }
    }
    SCOPE_GUARD({
        for (const std::string &key_name : key_names)
        {
            if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
            {
                cleanup->delete_key();
            }
        }
    });

    for (const std::string &key_name : key_names)
    {
        std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
        ASSERT_NE(nullptr, key) << mpss::get_error();
        key.reset();
    }

    std::latch ready(4);
    std::latch start(1);
    std::array<bool, 4> succeeded{true, true, true, true};
    std::array<std::string, 4> errors;
    std::array<std::thread, 4> workers;
    for (std::size_t worker_index = 0; worker_index < workers.size(); ++worker_index)
    {
        workers[worker_index] = std::thread([&, worker_index]() {
            ready.count_down();
            start.wait();

            for (std::size_t iteration = 0; iteration < 8; ++iteration)
            {
                std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Open(key_names[worker_index]);
                if (nullptr == key)
                {
                    succeeded[worker_index] = false;
                    errors[worker_index] = mpss::get_error();
                    return;
                }

                std::vector<std::byte> public_key(key->extract_key({}));
                const std::size_t public_key_size = key->extract_key(public_key);
                if (0 == public_key_size)
                {
                    succeeded[worker_index] = false;
                    errors[worker_index] = mpss::get_error();
                    return;
                }
            }
        });
    }

    ready.wait();
    start.count_down();
    for (std::thread &worker : workers)
    {
        worker.join();
    }

    for (std::size_t worker_index = 0; worker_index < workers.size(); ++worker_index)
    {
        ASSERT_TRUE(succeeded[worker_index]) << key_names[worker_index] << ": " << errors[worker_index];
    }
}

TEST(AndroidJNITest, ConcurrentOpenAndDeleteLeaveCacheConsistent)
{
    using enum mpss::Algorithm;

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Required algorithm is not supported by the Android backend.";
    }

    const std::string key_name = "test_android_concurrent_open_delete";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }
    SCOPE_GUARD({
        if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
        {
            cleanup->delete_key();
        }
    });

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, key) << mpss::get_error();
    key.reset();

    constexpr std::size_t opener_count = 8;
    std::latch ready(opener_count + 1);
    std::latch start(1);
    std::array<std::optional<bool>, opener_count> open_results;
    std::array<std::string, opener_count> open_errors;
    std::array<std::thread, opener_count> openers;
    for (std::size_t opener_index = 0; opener_index < openers.size(); ++opener_index)
    {
        openers[opener_index] = std::thread([&, opener_index]() {
            ready.count_down();
            start.wait();
            open_results[opener_index] = java_key_operation("OpenKey", key_name);
            if (!open_results[opener_index].has_value())
            {
                open_errors[opener_index] = mpss::get_error();
            }
        });
    }

    std::optional<bool> delete_result;
    std::string delete_error;
    std::thread deleter([&]() {
        ready.count_down();
        start.wait();
        delete_result = java_key_operation("DeleteKey", key_name);
        if (!delete_result.has_value())
        {
            delete_error = mpss::get_error();
        }
    });

    ready.wait();
    start.count_down();
    for (std::thread &opener : openers)
    {
        opener.join();
    }
    deleter.join();

    ASSERT_TRUE(delete_result.has_value()) << delete_error;
    ASSERT_TRUE(*delete_result);
    for (std::size_t opener_index = 0; opener_index < open_results.size(); ++opener_index)
    {
        ASSERT_TRUE(open_results[opener_index].has_value()) << open_errors[opener_index];
    }

    const std::optional<bool> final_open_result = java_key_operation("OpenKey", key_name);
    ASSERT_TRUE(final_open_result.has_value()) << mpss::get_error();
    ASSERT_FALSE(*final_open_result);

    std::unique_ptr<mpss::KeyPair> replacement = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, replacement) << mpss::get_error();
    ASSERT_TRUE(replacement->delete_key()) << mpss::get_error();
}

TEST(AndroidJNITest, PendingJavaExceptionIsCleared)
{
    mpss::impl::os::JNIEnvGuard guard;
    ASSERT_TRUE(guard.valid());
    JNIEnv *const env = guard.env();

    jclass missing_class = env->FindClass("com/microsoft/research/mpss/MissingForTest");
    ASSERT_TRUE(mpss::impl::os::utils::check_and_clear_exception(env, "finding a test-only missing class"));
    ASSERT_EQ(nullptr, missing_class);
    ASSERT_FALSE(env->ExceptionCheck());

    const std::string exception_error = mpss::get_error();
    EXPECT_NE(std::string::npos, exception_error.find("finding a test-only missing class"));
    EXPECT_NE(std::string::npos, exception_error.find("ClassNotFoundException"));

    jclass key_management = mpss::impl::os::JNIHelper::key_management_class();
    ASSERT_NE(nullptr, key_management);
    jmethodID take_error = env->GetStaticMethodID(key_management, "TakeError", "()Ljava/lang/String;");
    ASSERT_FALSE(mpss::impl::os::utils::check_and_clear_exception(env, "resolving KeyManagement.TakeError"));
    ASSERT_NE(nullptr, take_error);
}

TEST(AndroidJNITest, JavaErrorIsContextualAndConsumed)
{
    const std::string key_name = "test_android_missing_error_detail";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }

    mpss::impl::os::JNIEnvGuard guard;
    ASSERT_TRUE(guard.valid());
    JNIEnv *const env = guard.env();

    ASSERT_EQ(nullptr, mpss::KeyPair::Open(key_name));
    mpss::impl::os::utils::report_java_error(env, "missing-key open probe");
    const std::string open_probe_error = mpss::get_error();
    EXPECT_NE(std::string::npos, open_probe_error.find("missing-key open probe failed without Java error detail."));
    EXPECT_EQ(std::string::npos, open_probe_error.find(key_name));

    jclass key_management = mpss::impl::os::JNIHelper::key_management_class();
    ASSERT_NE(nullptr, key_management);
    jmethodID get_security_level =
        env->GetStaticMethodID(key_management, "GetKeySecurityLevel", "(Ljava/lang/String;)I");
    ASSERT_FALSE(mpss::impl::os::utils::check_and_clear_exception(env, "resolving KeyManagement.GetKeySecurityLevel"));
    ASSERT_NE(nullptr, get_security_level);

    jni_string java_key_name(env, env->NewStringUTF(key_name.c_str()));
    ASSERT_FALSE(
        mpss::impl::os::utils::check_and_clear_exception(env, "converting an Android key name to a Java string"));
    ASSERT_FALSE(java_key_name.is_null());

    const jint security_level = env->CallStaticIntMethod(key_management, get_security_level, java_key_name.get());
    ASSERT_FALSE(mpss::impl::os::utils::check_and_clear_exception(env, "calling KeyManagement.GetKeySecurityLevel"));
    ASSERT_EQ(-1, security_level);

    mpss::impl::os::utils::report_java_error(env, "KeyManagement.GetKeySecurityLevel");
    const std::string first_error = mpss::get_error();
    EXPECT_NE(std::string::npos, first_error.find("KeyManagement.GetKeySecurityLevel failed:"));
    EXPECT_NE(std::string::npos, first_error.find("Could not get key: " + key_name));

    mpss::impl::os::utils::report_java_error(env, "second operation");
    const std::string second_error = mpss::get_error();
    EXPECT_NE(std::string::npos, second_error.find("second operation failed without Java error detail."));
    EXPECT_EQ(std::string::npos, second_error.find(key_name));
}

TEST(AndroidJNITest, BooleanUnboxingReusesCachedMetadata)
{
    mpss::impl::os::JNIEnvGuard guard;
    ASSERT_TRUE(guard.valid());
    JNIEnv *const env = guard.env();

    jclass boolean_class = mpss::impl::os::JNIHelper::boolean_class();
    ASSERT_NE(nullptr, boolean_class);
    jfieldID true_field = env->GetStaticFieldID(boolean_class, "TRUE", "Ljava/lang/Boolean;");
    ASSERT_FALSE(mpss::impl::os::utils::check_and_clear_exception(env, "resolving Boolean.TRUE"));
    ASSERT_NE(nullptr, true_field);

    jni_object true_value(env, env->GetStaticObjectField(boolean_class, true_field));
    ASSERT_FALSE(mpss::impl::os::utils::check_and_clear_exception(env, "getting Boolean.TRUE"));
    ASSERT_FALSE(true_value.is_null());

    for (std::size_t iteration = 0; iteration < 1024; ++iteration)
    {
        const std::optional<bool> value = mpss::impl::os::utils::unbox_boolean(env, true_value.get());
        ASSERT_TRUE(value.value_or(false));
    }
}

TEST(AndroidJNITest, StandaloneVerifyRecoversAfterMalformedPublicKey)
{
    using enum mpss::Algorithm;

    if (!mpss::is_algorithm_available(ecdsa_secp256r1_sha256))
    {
        GTEST_SKIP() << "Required algorithm is not supported by the Android backend.";
    }

    const std::string key_name = "test_android_java_exception";
    if (std::unique_ptr<mpss::KeyPair> existing = mpss::KeyPair::Open(key_name); nullptr != existing)
    {
        ASSERT_TRUE(existing->delete_key());
    }
    SCOPE_GUARD({
        if (std::unique_ptr<mpss::KeyPair> cleanup = mpss::KeyPair::Open(key_name); nullptr != cleanup)
        {
            cleanup->delete_key();
        }
    });

    std::unique_ptr<mpss::KeyPair> key = mpss::KeyPair::Create(key_name, ecdsa_secp256r1_sha256);
    ASSERT_NE(nullptr, key);

    const std::vector<std::byte> hash(32, static_cast<std::byte>('c'));
    std::vector<std::byte> signature(key->sign_hash(hash, {}));
    const std::size_t signature_size = key->sign_hash(hash, signature);
    ASSERT_NE(0, signature_size);
    signature.resize(signature_size);

    std::vector<std::byte> public_key(key->extract_key({}));
    const std::size_t public_key_size = key->extract_key(public_key);
    ASSERT_NE(0, public_key_size);
    public_key.resize(public_key_size);

    std::vector<std::byte> different_hash = hash;
    different_hash.front() ^= std::byte{1};
    ASSERT_FALSE(mpss::verify(different_hash, public_key, ecdsa_secp256r1_sha256, signature));

    mpss::impl::os::JNIEnvGuard guard;
    ASSERT_TRUE(guard.valid());
    mpss::impl::os::utils::report_java_error(guard.env(), "invalid-signature probe");
    EXPECT_NE(std::string::npos, mpss::get_error().find("invalid-signature probe failed without Java error detail."));

    std::vector<std::byte> malformed_public_key = public_key;
    malformed_public_key.front() = std::byte{0};
    ASSERT_FALSE(mpss::verify(hash, malformed_public_key, ecdsa_secp256r1_sha256, signature));
    const std::string verify_error = mpss::get_error();
    EXPECT_NE(std::string::npos, verify_error.find("KeyManagement.VerifySignature failed:"));
    EXPECT_NE(std::string::npos, verify_error.find("Invalid"));
    ASSERT_TRUE(mpss::verify(hash, public_key, ecdsa_secp256r1_sha256, signature));
}

} // namespace mpss::tests
