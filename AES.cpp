
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
bool checkFile(char*);
void Print_and_Write_Key(void);
void WriteKey(void);
void EnProg(void);
void DecProg(void);

char keyFileName[] = "key.bin";
char blockLengthFileName[] = "iv.bin";

int main(void)
{
	char start_menu;
	int count = 0;
	while (count <= 3)
	{
		cout << "Hi, you are in a test program \n";
		cout << "1 - Generate a new key \n";
		cout << "2 - Generate a new, block sive key and write to a file \n";
		cout << "3 - Encrypt the file and write to the file \n";
		cout << "4 - Read key, decrypt the file and print \n";
		cout << "5 - Exit \n";
		cout << "Enter your selection ";
		cin >> start_menu;
		cout << endl;

		switch (start_menu)
		{
			case '1': {Print_and_Write_Key(); continue;  }
			case '2': {WriteKey(); continue;  }
			case '3': {EnProg();   continue;  }
			case '4': {DecProg();  continue;  }
			case '5': {return 0; }
		}
		count++;
	}
	system("PAUSE");
}

void Print_and_Write_Key(void)
{
	byte key[CryptoPP::AES::MAX_KEYLENGTH];
	InitKey(key, sizeof(key));
	char user_selection;
	cout << "The new key was generated you want to display on the screen(1) or save to a file(2)" << endl;
	cout << "Enter your selection ";
	cin >> user_selection;
	cout << endl;
	if (user_selection == '1')
	{
		cout << "New key " << key << endl;
	}
	else if (user_selection == '2')
		{
			ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));
		}
	else
	{
		cout << "you have entered a non-existent value";
	}
	cout << "Do you want to generate a block length\n 1-yes \n 2-no\n";
	cin >> user_selection;
	cout << endl;
	if (user_selection == '1')
	{
		byte blockLength[CryptoPP::AES::BLOCKSIZE];
		InitKey(blockLength, sizeof(blockLength));
		cout << "The new block size was generated, you want to display on the screen(1) or save to a file(2)" << endl;
		cin >> user_selection;
		if (user_selection == '1')
		{
			cout << "New block size " << blockLength << endl;
		}
		else
		{
			ArraySource as1(blockLength, sizeof(blockLength), true, new FileSink("iv.bin"));
		}
		
	}
	if (user_selection == '2')
	{
		system("PAUSE");
	}
	else
	{
		cout << "you have entered a non-existent value";
	}
	cout << endl<<endl;
}

void WriteKey(void)
{
	byte key[CryptoPP::AES::MAX_KEYLENGTH];
	byte blockLength[CryptoPP::AES::BLOCKSIZE];
	InitKey(key, sizeof(key));
	InitKey(blockLength, sizeof(blockLength));
	ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));
	ArraySource as1(blockLength, sizeof(blockLength), true, new FileSink("iv.bin"));
	system("PAUSE");
	cout << endl << endl;
}

void EnProg(void)
{
	byte key[CryptoPP::AES::MAX_KEYLENGTH];
	byte blockLength[CryptoPP::AES::BLOCKSIZE];
	cout << "Do you have a generated key\n 1-yes(you must have file key.bin and iv.bin)\n 2-no\n";
	char user_selection;
	cin >> user_selection;
	cout << endl;
	switch (user_selection){
		case '1':
		{
		
		
			if ((checkFile(keyFileName) != false)&&(checkFile(blockLengthFileName) != false))
			{
				FileSource fs("key.bin", true, new ArraySink(key, sizeof(key)));
				cout << "Key - OK" << endl;
				FileSource fs1("iv.bin", true, new ArraySink(blockLength, sizeof(blockLength)));
				cout << "IV - OK" << endl;
			}
			else
			{
				cout << "Gen new key and block size" << endl;
				InitKey(key, sizeof(key));
				InitKey(blockLength, sizeof(blockLength));

				ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));
				ArraySource as1(blockLength, sizeof(blockLength), true, new FileSink("iv.bin"));

			}
		}
		case '2':{
			cout << "Gen new key and block size" << endl;
			InitKey(key, sizeof(key));
			InitKey(blockLength, sizeof(blockLength));

			ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));
			ArraySource as1(blockLength, sizeof(blockLength), true, new FileSink("iv.bin"));
		}
	}

	cout << "Input your text\n";
	string plainText;
	cin >> plainText;
	cout << endl;
	cout << "Plain Text :" << plainText << endl << "key :" <<key<<endl << "blockLength :" << blockLength << endl;
	CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
	enc.SetKeyWithIV(key, sizeof(key), blockLength);
	string encText;
	CryptoPP::StreamTransformationFilter encFilter(enc, new CryptoPP::StringSink(encText));
	encFilter.Put(reinterpret_cast<const byte*>(plainText.c_str()), plainText.size());
	encFilter.MessageEnd();
	cout << "Encrypted Text : " << encText << endl;
	ofstream out("EnText.txt");
	out << encText;
	out.close();
	cout << endl << endl;
}


void DecProg(void) {

	byte key[CryptoPP::AES::MAX_KEYLENGTH];
	byte blockLength[CryptoPP::AES::BLOCKSIZE];
	if ((checkFile(keyFileName) != false)&&(checkFile(blockLengthFileName) != false)) {
		FileSource fs("key.bin", true, new ArraySink(key, sizeof(key)));
		FileSource fs1("iv.bin", true, new ArraySink(blockLength, sizeof(blockLength)));
		string encrypted_text;
		ifstream file("EnText.txt");
		string line;
		while (getline(file, line))
		{
			encrypted_text += line;
		}

		cout << "ex ->" << encrypted_text << endl << "keys :" << key << endl << "blockLength :" << blockLength << endl;
		CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
		dec.SetKeyWithIV(key, sizeof(key), blockLength);
		string decText;
		CryptoPP::StreamTransformationFilter decFilter(dec, new CryptoPP::StringSink(decText));
		decFilter.Put(reinterpret_cast<const byte*>(encrypted_text.c_str()), encrypted_text.size());
		decFilter.MessageEnd();
		cout << "Decrypted Text : " << decText << endl;
		system("PAUSE");
	}
	else
	{
		cout << "You dont have key or block size" << endl;
	}
	cout << endl << endl;
}

void InitKey(byte* key, size_t size) {
	srand(time(NULL));
	for (size_t i = 0; i < size; ++i) {
		key[i] = rand();
	}
}

bool checkFile(char* file_name) {
	ifstream file;
	file.open(file_name);
	if (!file)
		return false;
	else
		return true;
}
