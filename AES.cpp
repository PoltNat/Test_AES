
#include "Debug\cryptopp600\aes.h"
#include "Debug\cryptopp600\cryptlib.h"
#include "Debug\cryptopp600\filters.h"
#include "Debug\cryptopp600\osrng.h"
#include "Debug\cryptopp600\hex.h"
#include "Debug\cryptopp600\modes.h"
#include "Debug\cryptopp600\files.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
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

void PrintKey();
void WriteKey();
void EnProg();
void DecProg();


int main(void)
{
	char start_int;
	int count = 0;
	while (count <= 3)
	{
		std::cout << "Hi, you are in a test program \n";
		std::cout << "1 - Generate a new key and print console \n";
		std::cout << "2 - Generate a new key and write to a file \n";
		std::cout << "3 - Generate a new key, encrypt the file and write to the file \n";
		std::cout << "4 - Read key, decrypt the file and print \n";
		std::cout << "5 - Exit \n";
		std::cout << "Enter your selection ";
		std::cin >> start_int;

		if (start_int == '1') {PrintKey();}
		if (start_int == '2') {WriteKey();}
		if (start_int == '3') {EnProg();}
		if (start_int == '4') {DecProg();}
		if (start_int == '5') {return 0;}
		count++;
	}
	system("PAUSE");
}

void PrintKey()
{
	//Initialize common key and IV with appropriate values CryptoPP::AES::DEFAULT_KEYLENGTH
	byte key[CryptoPP::AES::MAX_KEYLENGTH];
	byte iv[CryptoPP::AES::BLOCKSIZE];

	// Initialize common key and IV with appropriate values
	InitKey(key, sizeof(key));
	InitKey(iv, sizeof(iv));
	std::cout <<"key "<< key << endl << "iv " << iv << endl;
	system("PAUSE");
}

void WriteKey()
{
	//Initialize common key and IV with appropriate values CryptoPP::AES::DEFAULT_KEYLENGTH
	byte key[CryptoPP::AES::MAX_KEYLENGTH];
	byte iv[CryptoPP::AES::BLOCKSIZE];

	// Initialize common key and IV with appropriate values
	InitKey(key, sizeof(key));
	InitKey(iv, sizeof(iv));

	ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));
	ArraySource as1(iv, sizeof(iv), true, new FileSink("iv.bin"));
	std::cout << key<<"\n";
	system("PAUSE");
}

void EnProg()
{
	//Initialize common key and IV with appropriate values CryptoPP::AES::DEFAULT_KEYLENGTH
	byte key[CryptoPP::AES::MAX_KEYLENGTH];
	byte iv[CryptoPP::AES::BLOCKSIZE];

	// Initialize common key and IV with appropriate values
	InitKey(key, sizeof(key));
	InitKey(iv, sizeof(iv));

	ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));
	ArraySource as1(iv, sizeof(iv), true, new FileSink("iv.bin"));

	std::cout << "Input your text\n";
	string plainText = "";
	std::cin >> plainText;
	std::cout << "Plain Text :" << plainText << endl << "key :" <<key<<endl << "iv :" << iv << endl;
	//Create an encrypted object
	CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
	enc.SetKeyWithIV(key, sizeof(key), iv);
	string encText;
	CryptoPP::StreamTransformationFilter encFilter(enc, new CryptoPP::StringSink(encText));

	// encryption
	encFilter.Put(reinterpret_cast<const byte*>(plainText.c_str()), plainText.size());
	encFilter.MessageEnd();

	std::cout << "Encrypted Text : " << encText << endl;

	std::ofstream out("EnText.txt");
	out << encText;
	out.close();
}


void DecProg() {

	string read_text = "";
	std::ifstream file("EnText.txt");
	std::string line;
		while (std::getline(file, line))
		{
			read_text += line;
		}
	byte key[CryptoPP::AES::MAX_KEYLENGTH];
	FileSource fs("key.bin", true, new ArraySink(key, sizeof(key)));
	byte iv[CryptoPP::AES::BLOCKSIZE];
	FileSource fs1("iv.bin", true, new ArraySink(iv, sizeof(iv)));
	std::cout << "ex ->" << read_text <<endl<<"keys :"<< key<<endl << "iv :" << iv << endl;
	CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
	dec.SetKeyWithIV(key, sizeof(key), iv);
	//Creation of conversion filter for decryption
	string decText;
	CryptoPP::StreamTransformationFilter decFilter(dec, new CryptoPP::StringSink(decText));
	decFilter.Put(reinterpret_cast<const byte*>(read_text.c_str()), read_text.size());
	decFilter.MessageEnd();
	cout << "Decrypted Text : " << decText << endl;
	system("PAUSE");
}
