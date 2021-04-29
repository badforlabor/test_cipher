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
#include "cryptopp/rsa.h"
#include "cryptopp/pem.h"

using namespace std;
using namespace CryptoPP;

#include "util.h"



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
		string encoded = ToBase64(cipher);

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
template <typename Key>
const Key loadKey(const std::string& filename)
{
	Key key;
	CryptoPP::ByteQueue queue;
	CryptoPP::FileSource file(filename.c_str(), true);
	file.TransferTo(queue);
	queue.MessageEnd();

	key.Load(queue);
	return key;
}
template <typename Key>
const Key loadRawKey(const std::string& str)
{
	Key key;
	CryptoPP::ByteQueue queue;
	queue.Put((const byte*)&str[0], str.size());
	queue.MessageEnd();

	key.Load(queue);
	return key;
}

void loadPem()
{
	FileSource fs1("rsa-pub.pem", true);
	RSA::PublicKey k1;
	PEM_Load(fs1, k1);
}

void TestRSA()
{
	std::string privateKeyName, publicKeyName, plainText;

	privateKeyName = "key8.pem";
	publicKeyName = "key8.pub";
	plainText = "RSA Test.";

	AutoSeededRandomPool prng;

	RSA::PrivateKey privateKey;
	RSA::PublicKey publicKey;
	{
		FileSource fs1(publicKeyName.c_str(), true);
		PEM_Load(fs1, publicKey);
	}
	{
		FileSource fs1(privateKeyName.c_str(), true);
		PEM_Load(fs1, privateKey);
	}
	
	std::string encrypted, decrypted;
	RSAES_PKCS1v15_Encryptor e(publicKey);

	StringSource(plainText, true,
		new PK_EncryptorFilter(prng, e,
			new StringSink(encrypted)));

	RSAES_PKCS1v15_Decryptor d(privateKey);

	StringSource(encrypted, true,
		new PK_DecryptorFilter(prng, d,
			new StringSink(decrypted)));

	std::cout << plainText << " ---> " << ToBase64(encrypted) << " <--- " << decrypted << std::endl;

	// 解谜go中的
	{
		auto base64 = "cPfoLi14lnpikk9irvyeAdXUka/NzOmikABAaY1WGi+Uopi48V2PKvKVx1N4NbOBuxphmtZumIIF/6M4OiTX901gI08JkRQqDCc4umM52dRF4I7xvc+v/z+Kx1ozptSJ0CwrLNQZoWYLEbVOKwl5wpJxYKYZXdYVWEpVP+tTkBO0UNjhfYY3lzMSMwkE1KP5			hFU9yDTavy4x3FliL4nYOk59znwTVNbj1Gy + AQf9eik5WbJfWEIGOCM + UJwHBis7z5SVhBoj5kPS90Su4nUnjYsaEjT4GMo1fCT5HFv9 + Xdzmvc3mdxi1jZbj7KyvV18XuryPzj7F2KvV + B / koekXg ==";
		auto encrypted2 = FromBase64(base64);

		std::string decrypted2;
		StringSource(encrypted2, true,
			new PK_DecryptorFilter(prng, d,
				new StringSink(decrypted2)));
		std::cout << decrypted2 << std::endl;
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

	extern void TestAES_ECB();
	TestAES_ECB();

	TestRSA();

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
