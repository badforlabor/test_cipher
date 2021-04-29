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

#include "util.h"

using namespace std;
using namespace CryptoPP;

void TestAES_ECB()
{
	AutoSeededRandomPool prng;

	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	auto keyValue = GenKey("123456", 32, '0');
	key.Assign(&keyValue[0], 32);

	string plain = "ECB Mode Test";
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	try
	{
		cout << "plain text: " << plain << endl;

		ECB_Mode< AES >::Encryption e;
		e.SetKey(key, key.size());

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource ss1(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch (CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	cout << "cipher text(base64): " << ToBase64(cipher) << endl;

	/*********************************\
	\*********************************/

	try
	{
		ECB_Mode< AES >::Decryption d;
		// ECB Mode does not use an IV
		d.SetKey(key, key.size());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource ss3(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch (CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}