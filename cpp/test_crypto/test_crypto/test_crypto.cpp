// test_crypto.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include "cryptopp/aes.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include "cryptopp/base64.h"

using namespace std;
using namespace CryptoPP;


void TestAES()
{
	// https://www.cryptopp.com/wiki/Advanced_Encryption_Standard

	AutoSeededRandomPool prng;
	HexEncoder encoder(new FileSink(std::cout));

	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	SecByteBlock iv(AES::BLOCKSIZE);

	prng.GenerateBlock(key, key.size());
	prng.GenerateBlock(iv, iv.size());

	unsigned char keyValue[16] = { '1', '2', '3', '4', '5', '6' };
	key.Assign(keyValue, 16);
	iv.Assign(keyValue, 16);

	std::string plain = "CBC Mode Test";
	std::string cipher, recovered;
	
	std::cout << "plain text: " << plain << std::endl;

	{
		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		StringSource s(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource
	}

	std::cout << "key: ";
	encoder.Put(key, key.size());
	encoder.MessageEnd();
	std::cout << std::endl;

	std::cout << "iv: ";
	encoder.Put(iv, iv.size());
	encoder.MessageEnd();
	std::cout << std::endl;

	std::cout << "cipher text: ";
	encoder.Put((const byte*)&cipher[0], cipher.size());
	encoder.MessageEnd();
	std::cout << std::endl;

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

		std::cout << "cipher text(base64):" << encoded << std::endl;
	}

	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		StringSource s(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		std::cout << "recovered text: " << recovered << std::endl;
	}
}

int main()
{

    std::cout << "Hello World!\n";

	cout << "key length: " << AES::DEFAULT_KEYLENGTH << endl;
	cout << "key length (min): " << AES::MIN_KEYLENGTH << endl;
	cout << "key length (max): " << AES::MAX_KEYLENGTH << endl;
	cout << "block size: " << AES::BLOCKSIZE << endl;

	TestAES();

	cout << "end..." << endl;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
