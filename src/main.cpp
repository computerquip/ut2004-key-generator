#include <array>
#include <cinttypes>
#include <codecvt>
#include <cstdint>
#include <format>
#include <locale>
#include <print>
#include <string_view>
#include <string>
#include <vector>

#include "wil/result.h"
#include "wil/resource.h"

std::string_view GMagic = "appDebugfNoInit";
std::string_view GCDKeyBaseMap = "ABCDEFGHJLKMNPQRTUVWXYZ2346789";
unsigned int GCDKeyBase = (unsigned int)GCDKeyBaseMap.size();

using MD5 = std::array<unsigned char, 16>;

std::vector<unsigned char> GenerateRandom(size_t NumBytes)
{
    std::vector<unsigned char> Result;

    Result.resize(NumBytes);

    THROW_IF_NTSTATUS_FAILED(
        ::BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, Result.data(), NumBytes, 0));

    return Result;
}

MD5 DigestMD5(unsigned char *Data, size_t Size)
{
    DWORD cbHashObject{};
    DWORD cbDummy{};
    MD5 Digest{};

    THROW_IF_NTSTATUS_FAILED(::BCryptGetProperty(
        BCRYPT_MD5_ALG_HANDLE,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&cbHashObject,
        sizeof(cbHashObject),
        &cbDummy,
        0));

    std::vector<unsigned char> HashObject(cbHashObject);
    wil::unique_bcrypt_hash Hash{};

    THROW_IF_NTSTATUS_FAILED(::BCryptCreateHash(
        BCRYPT_MD5_ALG_HANDLE,
        Hash.addressof(),
        HashObject.data(),
        HashObject.size(),
        NULL,
        0,
        0));

    THROW_IF_NTSTATUS_FAILED(::BCryptHashData(Hash.get(), Data, Size, 0));

    THROW_IF_NTSTATUS_FAILED(::BCryptFinishHash(Hash.get(), Digest.data(), Digest.size(), 0));

    return Digest;
}

std::string ulltoa(uint64_t Num, unsigned int Base = 10)
{
    char Buffer[100]{};

    return _ui64toa(Num, Buffer, Base);
}

char ValueToCDKeyMap(char C)
{
    if (C >= '0' && C <='9') {
        return GCDKeyBaseMap[C - '0'];
    }

    if (C >= 'A' && C <='Z') {
        return GCDKeyBaseMap[C - 'A' + 10];
    }

    if (C >= 'a' && C <='z') {
        return GCDKeyBaseMap[C - 'a' + 10];
    }

    return 0;
}

std::string ValuesToCDKeyMap(std::string_view Values)
{
    std::string Result;

    for (char Value : Values) {
        Result.append(1, ValueToCDKeyMap(Value));
    }

    return Result;
}

std::string GenerateCDKey(uint64_t Seed, std::string_view Magic)
{
    std::string Key = ValuesToCDKeyMap(ulltoa(Seed, GCDKeyBase));

    if (Key.size() < 14) {
        Key.insert(0, 14 - Key.size(), GCDKeyBaseMap[0]);
    }

    std::string Check = std::format("{}{}", *(int64_t*)&Seed, Magic);
    MD5 Digest = DigestMD5((unsigned char*)Check.data(), Check.size());
    uint64_t QDigest = *(uint64_t*)Digest.data();
    std::string CheckOutput = ValuesToCDKeyMap(ulltoa(QDigest, GCDKeyBase));

    CheckOutput.resize(6);

    if(CheckOutput.size() < 6) {
        CheckOutput.insert(0, 6 - CheckOutput.size(), GCDKeyBaseMap[0]);
    }

    Key.append(CheckOutput);

    std::string_view KeyView = Key;

    return std::format(
        "{}-{}-{}-{}",
        KeyView.substr(10, 5),
        KeyView.substr(5, 5),
        KeyView.substr(0, 5),
        KeyView.substr(15, 5));
}

int main()
{
    std::vector<unsigned char> Bytes = GenerateRandom(8);
    uint64_t Seed = *(uint64_t*)Bytes.data();

    try {
        std::string Key = GenerateCDKey(Seed, GMagic);
        std::print(stderr, "Seed: {}\n", Seed);
        std::print(stdout, "{}", Key);

        return 0;
    } catch (...) {
        LOG_CAUGHT_EXCEPTION();
    }

    return 1;
}
