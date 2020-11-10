
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


void InitKey(byte*, size_t);
int checkFile(char*);
void PrintKey(void);
void WriteKey(void);
void EnProg(void);
void DecProg(void);

char str1[] = "key.bin";
char str2[] = "iv.bin";

int main(void)
{
	char start_int;
	int count = 0;
	while (count <= 3)
	{
		std::cout << "Hi, you are in a test program \n";
		std::cout << "1 - Generate a new key \n";
		std::cout << "2 - Generate a new, block sive key and write to a file \n";
		std::cout << "3 - Encrypt the file and write to the file \n";
		std::cout << "4 - Read key, decrypt the file and print \n";
		std::cout << "5 - Exit \n";
		std::cout << "Enter your selection ";
		std::cin >> start_int;
		std::cout << endl;
		if (start_int == '1') {PrintKey();}
		if (start_int == '2') {WriteKey();}
		if (start_int == '3') {EnProg();}
		if (start_int == '4') {DecProg();}
		if (start_int == '5') {return 0;}
		count++;
	}
	system("PAUSE");
}

void PrintKey(void)
{
	byte key[CryptoPP::AES::MAX_KEYLENGTH];
	InitKey(key, sizeof(key));
	char start_int;
	std::cout << "The new key was generated you want to display on the screen(1) or save to a file(2)" << endl;
	std::cout << "Enter your selection ";
	std::cin >> start_int;
	std::cout << endl;
	if (start_int == '1')
	{
		std::cout << "New key " << key << endl;
	}
	if (start_int == '2')
	{
		ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));
	}
	else
	{
		std::cout << "you have entered a non-existent value";
	}
	start_int = ' ';
	std::cout << "Do you want to generate a block length\n 1-yes \n 2-no\n";
	std::cin >> start_int;
	std::cout << endl;
	if (start_int == '1')
	{
		byte iv[CryptoPP::AES::BLOCKSIZE];
		InitKey(iv, sizeof(iv));
		std::cout << "The new block size was generated, you want to display on the screen(1) or save to a file(2)";
		start_int = ' ';
		std::cin >> start_int;
		if (start_int == '1')
		{
			std::cout << "New block size " << iv << endl;
		}
		if (start_int == '2')
		{
			ArraySource as1(iv, sizeof(iv), true, new FileSink("iv.bin"));
		}
		
	}
	if (start_int == '2')
	{
		system("PAUSE");
	}
	else
	{
		std::cout << "you have entered a non-existent value";
	}
	std::cout << endl<<endl;
}

void WriteKey(void)
{
	byte key[CryptoPP::AES::MAX_KEYLENGTH];
	byte iv[CryptoPP::AES::BLOCKSIZE];
	InitKey(key, sizeof(key));
	InitKey(iv, sizeof(iv));
	ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));
	ArraySource as1(iv, sizeof(iv), true, new FileSink("iv.bin"));
	system("PAUSE");
	std::cout << endl << endl;
}

void EnProg(void)
{
	byte key[CryptoPP::AES::MAX_KEYLENGTH];
	byte iv[CryptoPP::AES::BLOCKSIZE];
	std::cout << "Do you have a generated key\n 1-yes(you must have file key.bin)\n 2-no\n";
	char start_int = ' ';
	std::cin >> start_int;
	std::cout << endl;
	if (start_int == '1')
	{
		if (checkFile(str1) != 1)
		{
			FileSource fs("key.bin", true, new ArraySink(key, sizeof(key)));
			std::cout << "Key - OK" << endl;
			if (checkFile(str2) != 1)
			{
				FileSource fs1("iv.bin", true, new ArraySink(iv, sizeof(iv)));
				std::cout << "IV - OK" << endl;
			}
			else
			{
				InitKey(iv, sizeof(iv));
				ArraySource as1(iv, sizeof(iv), true, new FileSink("iv.bin"));
			}
		}
		else
		{
			std::cout << "Gen new key and block size" << endl;
			InitKey(key, sizeof(key));
			InitKey(iv, sizeof(iv));

			ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));
			ArraySource as1(iv, sizeof(iv), true, new FileSink("iv.bin"));

		}
	}
	if (start_int == '2')
	{
		std::cout << "Gen new key and block size" << endl;
		InitKey(key, sizeof(key));
		InitKey(iv, sizeof(iv));

		ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));
		ArraySource as1(iv, sizeof(iv), true, new FileSink("iv.bin"));

	}
	std::cout << "Input your text\n";
	string plainText = "";
	std::cin >> plainText;
	std::cout << endl;
	std::cout << "Plain Text :" << plainText << endl << "key :" <<key<<endl << "iv :" << iv << endl;
	CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
	enc.SetKeyWithIV(key, sizeof(key), iv);
	string encText;
	CryptoPP::StreamTransformationFilter encFilter(enc, new CryptoPP::StringSink(encText));
	encFilter.Put(reinterpret_cast<const byte*>(plainText.c_str()), plainText.size());
	encFilter.MessageEnd();
	std::cout << "Encrypted Text : " << encText << endl;
	std::ofstream out("EnText.txt");
	out << encText;
	out.close();
	std::cout << endl << endl;
}


void DecProg(void) {

	byte key[CryptoPP::AES::MAX_KEYLENGTH];
	byte iv[CryptoPP::AES::BLOCKSIZE];
	if ((checkFile(str1) != 1)&&(checkFile(str2) != 1)) {
		FileSource fs("key.bin", true, new ArraySink(key, sizeof(key)));
		FileSource fs1("iv.bin", true, new ArraySink(iv, sizeof(iv)));
		string read_text = "";
		std::ifstream file("EnText.txt");
		std::string line;
		while (std::getline(file, line))
		{
			read_text += line;
		}

		std::cout << "ex ->" << read_text << endl << "keys :" << key << endl << "iv :" << iv << endl;
		CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
		dec.SetKeyWithIV(key, sizeof(key), iv);
		string decText;
		CryptoPP::StreamTransformationFilter decFilter(dec, new CryptoPP::StringSink(decText));
		decFilter.Put(reinterpret_cast<const byte*>(read_text.c_str()), read_text.size());
		decFilter.MessageEnd();
		cout << "Decrypted Text : " << decText << endl;
		system("PAUSE");
	}
	else
	{
		std::cout << "You dont have key or block size" << endl;
	}
	std::cout << endl << endl;
}

void InitKey(byte* key, size_t size) {
	srand(time(NULL));
	for (size_t i = 0; i < size; ++i) {
		key[i] = rand();
	}
}


int checkFile(char* file_name) {
	ifstream file;
	file.open(file_name);
	if (!file)
		return 1;
	else
		return 0;
}
