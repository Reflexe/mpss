// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifdef __ANDROID__
#include "mpss/impl/android/JNIHelper.h"
#endif
#include "mpss/log.h"
#include "tests/compat_env.h"
#include <array>
#include <cstdlib>
#ifdef __ANDROID__
#include <format>
#endif
#include <string>
#include <utility>
#ifdef __ANDROID__
#include <android/log.h>
#include <jni.h>
#endif
#include <gtest/gtest.h>

#ifdef MPSS_BACKEND_YUBIKEY
#include "mpss/impl/yubikey/yk_piv.h"
#endif

namespace
{

#ifdef __ANDROID__
constexpr char mpss_logcat_tag[] = "MPSS";
constexpr char test_logcat_tag[] = "MPSS_TESTS";

void log_to_logcat(android_LogPriority priority, const char *tag, const std::string &message)
{
    __android_log_write(priority, tag, message.c_str());
}

std::shared_ptr<mpss::Logger> new_logcat_logger()
{
    using enum mpss::LogLevel;

    std::array<mpss::log_handler_t, mpss::log_level_count> log_handlers{};
    log_handlers[static_cast<std::size_t>(trace)] = [](const std::string &message) {
        log_to_logcat(ANDROID_LOG_VERBOSE, mpss_logcat_tag, message);
    };
    log_handlers[static_cast<std::size_t>(debug)] = [](const std::string &message) {
        log_to_logcat(ANDROID_LOG_DEBUG, mpss_logcat_tag, message);
    };
    log_handlers[static_cast<std::size_t>(info)] = [](const std::string &message) {
        log_to_logcat(ANDROID_LOG_INFO, mpss_logcat_tag, message);
    };
    log_handlers[static_cast<std::size_t>(warning)] = [](const std::string &message) {
        log_to_logcat(ANDROID_LOG_WARN, mpss_logcat_tag, message);
    };
    log_handlers[static_cast<std::size_t>(error)] = [](const std::string &message) {
        log_to_logcat(ANDROID_LOG_ERROR, mpss_logcat_tag, message);
    };

    std::array<mpss::flush_handler_t, mpss::log_level_count> flush_handlers{};
    std::array<mpss::close_handler_t, mpss::log_level_count> close_handlers{};
    return mpss::Logger::Create(std::move(log_handlers), std::move(flush_handlers), std::move(close_handlers));
}

class LogcatEventListener : public ::testing::EmptyTestEventListener
{
  public:
    void OnTestStart(const ::testing::TestInfo &test_info) override
    {
        log_to_logcat(ANDROID_LOG_INFO, test_logcat_tag,
                      std::format("[ RUN      ] {}.{}", test_info.test_suite_name(), test_info.name()));
    }

    void OnTestPartResult(const ::testing::TestPartResult &result) override
    {
        if (!result.failed() && !result.skipped())
        {
            return;
        }

        const char *file_name = result.file_name();
        log_to_logcat(result.failed() ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, test_logcat_tag,
                      std::format("{}:{}: {}", nullptr == file_name ? "<unknown>" : file_name, result.line_number(),
                                  result.summary()));
    }

    void OnTestEnd(const ::testing::TestInfo &test_info) override
    {
        const ::testing::TestResult *result = test_info.result();
        const bool skipped = result->Skipped();
        const bool passed = result->Passed();
        const char *status = skipped ? "SKIPPED" : (passed ? "PASSED" : "FAILED");
        log_to_logcat(passed || skipped ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, test_logcat_tag,
                      std::format("[ {} ] {}.{} ({} ms)", status, test_info.test_suite_name(), test_info.name(),
                                  result->elapsed_time()));
    }

    void OnTestProgramEnd(const ::testing::UnitTest &unit_test) override
    {
        log_to_logcat(0 == unit_test.failed_test_count() ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, test_logcat_tag,
                      std::format("{} tests: {} passed, {} skipped, {} failed", unit_test.test_to_run_count(),
                                  unit_test.successful_test_count(), unit_test.skipped_test_count(),
                                  unit_test.failed_test_count()));
    }
};
#endif

/**
 * @brief Global test environment that auto-selects a YubiKey when multiple are present.
 *
 * When multiple YubiKeys are connected and MPSS_YUBIKEY_SERIAL is not set, this picks
 * the first available device so that the multi-device guard does not block key creation.
 * The original env var state is restored after all tests complete.
 */
class YubiKeyEnvironment : public ::testing::Environment
{
  public:
    void SetUp() override
    {
#ifdef MPSS_BACKEND_YUBIKEY
        const char *existing = std::getenv("MPSS_YUBIKEY_SERIAL"); // NOLINT(concurrency-mt-unsafe)
        if (nullptr != existing)
        {
            saved_serial_env_ = existing;
            return;
        }

        const auto serials = mpss::impl::yubikey::YubiKeyPIV::available_serials();
        if (serials.size() > 1)
        {
            auto_selected_ = true;
            const std::string serial_str = std::to_string(serials.front());
            setenv("MPSS_YUBIKEY_SERIAL", serial_str.c_str(), 1); // NOLINT(concurrency-mt-unsafe)
            mpss::GetLogger()->info("Multiple YubiKeys detected; auto-selected serial {} for tests.", serials.front());
        }
#endif
    }

    void TearDown() override
    {
#ifdef MPSS_BACKEND_YUBIKEY
        if (auto_selected_)
        {
            unsetenv("MPSS_YUBIKEY_SERIAL"); // NOLINT(concurrency-mt-unsafe)
        }
        else if (!saved_serial_env_.empty())
        {
            setenv("MPSS_YUBIKEY_SERIAL", saved_serial_env_.c_str(), 1); // NOLINT(concurrency-mt-unsafe)
        }
#endif
    }

  private:
    std::string saved_serial_env_;
    bool auto_selected_{false};
};

int run_all_tests(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
#ifdef __ANDROID__
    mpss::GetOrSetLogger(new_logcat_logger());
#endif
    mpss::GetLogger()->set_level(mpss::LogLevel::trace);
    ::testing::AddGlobalTestEnvironment(new YubiKeyEnvironment); // NOLINT(*-owning-memory)
#ifdef __ANDROID__
    ::testing::UnitTest::GetInstance()->listeners().Append(new LogcatEventListener); // NOLINT(*-owning-memory)
#endif
    const int result = RUN_ALL_TESTS();
    return 0 == ::testing::UnitTest::GetInstance()->test_to_run_count() ? 1 : result;
}

} // namespace

#ifdef __ANDROID__
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM * /*vm*/, void * /*reserved*/)
{
    return mpss::impl::os::JNIHelper::Initialized() ? JNI_VERSION_1_6 : JNI_ERR;
}

extern "C" JNIEXPORT jint JNICALL Java_com_microsoft_research_mpss_tests_TestRunner_runAllTests(JNIEnv * /*env*/,
                                                                                                jclass /*test_runner*/)
{
    char executable_name[] = "mpss_tests";
    char *argv[] = {executable_name, nullptr};
    return run_all_tests(1, argv);
}
#else
int main(int argc, char *argv[])
{
    return run_all_tests(argc, argv);
}
#endif
