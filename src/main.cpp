#include <array>
#include <cinttypes>
#include <codecvt>
#include <cstdint>
#include <cstdio>
#include <locale>
#include <string_view>
#include <string>
#include <vector>

#if _WIN32
# include <wil/result.h>
# include <wil/resource.h>
#endif

namespace
{

constexpr const char* GMagic = "appDebugfNoInit";
constexpr std::string_view GCDKeyBaseMap = "ABCDEFGHJLKMNPQRTUVWXYZ2346789";
constexpr unsigned int GCDKeyBase = (unsigned int)GCDKeyBaseMap.size();

using MD5 = std::array<unsigned char, 16>;

#if _WIN32

void GenerateRandom(unsigned char* Buffer, size_t NumBytes)
{
	THROW_IF_NTSTATUS_FAILED(::BCryptGenRandom(
		NULL,
		Buffer,
		NumBytes,
		BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

MD5 DigestMD5(unsigned char* Data, size_t Size)
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

#endif

/* Based on the ui64toa implementation in WINE
 * https://github.com/wine-mirror/wine/blob/master/LICENSE */
std::string ui64toa(uint64_t value, int radix)
{
	char buffer[65], * pos;

	pos = &buffer[64];
	*pos = '\0';

	do {
		int digit = value % radix;
		value /= radix;

		if (digit < 10) {
			*--pos = '0' + digit;
		}
		else {
			*--pos = 'a' + digit - 10;
		}
	} while (value != 0);

	return pos;
}

uint64_t BufferToULL(const unsigned char* Source)
{
	uint64_t Result{};

	memcpy(&Result, Source, 8);

	return Result;
}

std::string Scramble(std::string_view View)
{
	std::string Result;

	for (const char C : View) {
		if (C >= '0' && C <= '9') {
			Result.push_back(GCDKeyBaseMap[C - '0']);
		}

		if (C >= 'A' && C <= 'Z') {
			Result.push_back(GCDKeyBaseMap[C - 'A' + 10]);
		}

		if (C >= 'a' && C <= 'z') {
			Result.push_back(GCDKeyBaseMap[C - 'a' + 10]);
		}
	}

	return Result;
}

void EnsureLength(std::string& Str, size_t WantedSize, char Pad)
{
	if (Str.size() < WantedSize) {
		Str.insert(0, WantedSize - Str.size(), Pad);

	}

	Str.resize(WantedSize);
}

template<typename ... ArgsT>
std::string Format(const std::string& FormatStr, ArgsT ... Args)
{
	std::string Result;
	int Length = std::snprintf(nullptr, 0, FormatStr.c_str(), Args ...);

	/* snprintf can't realistically fail here, don't check for errors. */
	Result.resize(Length);
	std::snprintf(Result.data(), Result.size() + 1, FormatStr.c_str(), Args ...);

	return Result;
}

std::string GenerateCDKey(uint64_t Seed, const char* Magic)
{
	std::string SeedStr = ui64toa(Seed, GCDKeyBase);
	std::string Key = Scramble(ui64toa(Seed, GCDKeyBase));

	EnsureLength(Key, 14, GCDKeyBaseMap[0]);

	std::string Check = Format("%" PRIi64 "%s", Seed, Magic);
	MD5 Digest = DigestMD5((unsigned char*)Check.data(), Check.size());
	uint64_t QDigest = BufferToULL(Digest.data());
	std::string CheckOutput = Scramble(ui64toa(QDigest, GCDKeyBase));

	EnsureLength(CheckOutput, 6, GCDKeyBaseMap[0]);

	Key.append(CheckOutput);

	return Format("%.*s-%.*s-%.*s-%.*s",
		5, Key.data() + 10,
		5, Key.data() + 5,
		5, Key.data() + 0,
		5, Key.data() + 15);
}

} /* <anonymous> namespace */

int main() try
{
	uint64_t Seed{};

	GenerateRandom((unsigned char*)&Seed, sizeof(Seed));

	std::string Key = GenerateCDKey(Seed, GMagic);
	fprintf(stdout, "%s", Key.c_str());

	return 0;
}
catch (const std::exception& e)
{
	std::string what = e.what();

	fprintf(stderr, "%s", what.c_str());

	return 1;
}
