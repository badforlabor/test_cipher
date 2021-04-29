#pragma once

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

extern std::vector<byte> GenKey(const std::string& Key, size_t Size, char Pad);
extern std::string FromBase64(const std::string cipher);
extern std::string ToBase64(const std::string cipher);
