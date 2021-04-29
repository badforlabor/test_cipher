#include <iostream>
#include <vector>
#include "cryptopp/aes.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/base64.h"
#include "cryptopp/rsa.h"
#include "cryptopp/pem.h"

using namespace std;
using namespace CryptoPP;

std::vector<byte> GenKey(const std::string& Key, size_t Size, char Pad)
{
	std::vector<byte> Ret;
	Ret.reserve(Size);

	for (auto i = 0; i < Key.size(); i++)
	{
		Ret.push_back(Key[i]);
	}
	while (Ret.size() < Size)
	{
		Ret.push_back(Pad);
	}
	while (Ret.size() > Size)
	{
		Ret.pop_back();
	}
	return Ret;
}

std::string ToBase64(const std::string cipher)
{
	Base64Encoder encoder;
	encoder.Put((const byte*)&cipher[0], cipher.size());
	encoder.MessageEnd();

	string encoded;
	word64 size = encoder.MaxRetrievable();
	if (size)
	{
		encoded.resize(size);
		encoder.Get((byte*)&encoded[0], encoded.size());
	}

	return encoded;
}

std::string FromBase64(const std::string cipher)
{
	Base64Decoder encoder;
	encoder.Put((const byte*)&cipher[0], cipher.size());
	encoder.MessageEnd();

	string encoded;
	word64 size = encoder.MaxRetrievable();
	if (size)
	{
		encoded.resize(size);
		encoder.Get((byte*)&encoded[0], encoded.size());
	}

	return encoded;
}