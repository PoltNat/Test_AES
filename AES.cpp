
#include "Debug\cryptopp600\aes.h"
#include "Debug\cryptopp600\cryptlib.h"
#include "Debug\cryptopp600\filters.h"
#include "Debug\cryptopp600\osrng.h"
#include "Debug\cryptopp600\hex.h"
#include "Debug\cryptopp600\modes.h"
#include <stdio.h>
#include <iostream>
#include <string>
#include <iomanip>
#include <string.h>
#include <time.h>

using namespace std;
using namespace CryptoPP;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::StringSink;
using CryptoPP::StreamTransformation;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AES;
using CryptoPP::ECB_Mode;
//1.Initialization of key data
void InitKey(byte* key, size_t size) {
	srand(time(NULL));
	for (size_t i = 0; i < size; ++i) {
		key[i] = rand();
	}
}
void main()
{
	//Initialize common key and IV with appropriate values CryptoPP::AES::DEFAULT_KEYLENGTH
	byte key[CryptoPP::AES::MAX_KEYLENGTH];
	byte iv[CryptoPP::AES::BLOCKSIZE];

	// Initialize common key and IV with appropriate values
	InitKey(key, sizeof(key));
	InitKey(iv, sizeof(iv));

	FILE* f;
	f = fopen("pass.txt", "w");
	char str[(sizeof key) + 1];
	memcpy(str, key, sizeof key);
	//str[sizeof byteArray] = 0;
	fputs(str, f);
	fclose(f);


	string plainText = "123jhjkvgvgvkghvghc4";
	cout << "Plain Text : " << plainText << endl;
	//Create an encrypted object
	CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
	enc.SetKeyWithIV(key, sizeof(key), iv);
	string encText;
	CryptoPP::StreamTransformationFilter encFilter(enc, new CryptoPP::StringSink(encText));
	
	// encryption
	encFilter.Put(reinterpret_cast<const byte*>(plainText.c_str()), plainText.size());
	encFilter.MessageEnd();
	
	cout << "Encrypted Text : " << encText << endl;
	CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
	dec.SetKeyWithIV(key, sizeof(key), iv);

	//Creation of conversion filter for decryption
	string decText;
	CryptoPP::StreamTransformationFilter decFilter(dec, new CryptoPP::StringSink(decText));
	decFilter.Put(reinterpret_cast<const byte*>(encText.c_str()), encText.size());
	decFilter.MessageEnd();

	cout << "Decrypted Text : " << decText << endl;

	system("PAUSE");
}