#pragma once

#include <exception>
#include <string>
#include <utility>

// Base exception class for SpankOlm
class SpankOlmException : public std::exception
{
public:
    explicit SpankOlmException(std::string message) : message_(std::move(message))
    {
    }

    [[nodiscard]] const char* what() const noexcept override
    {
        return message_.c_str();
    }

private:
    std::string message_;
};

// Specific exception for key generation errors
class SpankOlmErrorKeyGeneration final : public SpankOlmException
{
public:
    SpankOlmErrorKeyGeneration() : SpankOlmException("Error generating key pair.")
    {
    }
};

// Specific exception for unknown pickle version errors
class SpankOlmErrorUnknownPickleVersion final : public SpankOlmException
{
public:
    SpankOlmErrorUnknownPickleVersion() : SpankOlmException("Unknown pickle version.")
    {
    }
};

// Specific exception for not finding the version in the pickle
class SpankOlmErrorVersionNotFound final : public SpankOlmException
{
public:
    SpankOlmErrorVersionNotFound() : SpankOlmException("Version not found in pickle.")
    {
    }
};

// Specific exception for a bad legacy account pickle
class SpankOlmErrorBadLegacyAccountPickle final : public SpankOlmException
{
public:
    SpankOlmErrorBadLegacyAccountPickle() : SpankOlmException("Bad legacy account pickle.")
    {
    }
};

// Specific exception for a corrupted account pickle
class SpankOlmErrorCorruptedAccountPickle final : public SpankOlmException
{
public:
    SpankOlmErrorCorruptedAccountPickle() : SpankOlmException("Corrupted account pickle.")
    {
    }
};
