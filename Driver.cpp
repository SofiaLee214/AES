
#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include <iostream>
using std::cerr;
using std::cout;

using std::endl;
using std::wcerr;
using std::wcout;
using std::wcin;
using std::cin;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

#include "cryptopp/filters.h"
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::ArraySink;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;


#include "include/cryptopp/aes.h"
using CryptoPP::AES;

#include "include/cryptopp/ccm.h"


#include "assert.h"
/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;


#include <io.h>
#include <fcntl.h>
// function connvert str to wstr
std::wstring string2wstring(const std::string &str)
{
	std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
	return converter.from_bytes(str);
}
// function convert wstr to str
std::string wstring2string(const std::wstring &wstr)
{
	std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
	return converter.to_bytes(wstr);
}



#include "ECB.cpp"
#include "CBC.cpp"
#include "CTR.cpp"
#include "CCM.cpp"
#include "OFB.cpp"
#include "CFB.cpp"
#include "GCM.cpp"
#include "XTS.cpp"

int main(int argc, char *argv[])
{
#ifdef __linux__
	setlocale(LC_ALL, "");
#elif __APPLE__
#if TARGET_OS_MAC
	setlocale(LC_ALL, "");
#else
#endif
#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif

    int mode_ende, mode_keyiv,modetext,modesup;
	//get mode 
 	wcout << endl<< "1.ECB \t2.CBC \t3.OFB \t4.CTR \t5.CFB \t6.XTS \t7.CCM \t8.GCM";
	wcout<<"\nEnter mode: "; // Choose mode 
	std::wcin.sync();
    std::wcin >> modesup;
	
    //Choose encryption or decryption
	wcout<<"1.Encrypt \n2.Decrypt";
	wcout<<endl<<"Enter a number: ";
	std::wcin>>mode_ende;
	std::wcin.sync();

   //Choose mode for key and iv  
	std::wcout << "\n1: Secret key and IV are randomly chosen\n2: Input Secret Key and IV from screen\n3: Input Secret Key and IV from file" << std::endl;
	std::wcout << "Mode: ";
	std::wcin.sync();

	std::wcin>>mode_keyiv;
	wstring key_cin, iv_cin,plain1, cipher1;
	string hkey, hiv, decode, bkey, biv, cipher2;
	string plain,cipher, encoded, recovered;


	byte key[AES::DEFAULT_KEYLENGTH];
	byte iv[AES::BLOCKSIZE];
	 if (modesup == 7)
		iv[12];
	 
	 else if ((modesup ==8) || (modesup ==6))
			key [AES::MAX_KEYLENGTH];
	
	

	switch (mode_keyiv)
	{
	case 1:
		{
			AutoSeededRandomPool prng;
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		break;
	
	case 2:
		{
			std::wcout << L"Input key: ";
			wcin.sync();
			std::wcin >> key_cin;
			std::wcout << L"Input iv: ";

			wcin.sync();
			std::wcin >> iv_cin;
			// Convert wstring to string
			hkey = wstring2string(key_cin);
			hiv = wstring2string(iv_cin);
			// Convert string to key (binary)
			StringSource(hkey, true,
						new HexDecoder(
							new StringSink(bkey)) // HexDecoder
			);									   // StringSource

			// Convert string key to byte key
			StringSource(bkey, true,
						new ArraySink(key, sizeof(key)) // ArraySink
			);											 // StringSource

			// Convert string to iv (binary)
			StringSource(hiv, true,
						new HexDecoder(
							new StringSink(biv)) // HexDecoder
			);									  // StringSource
			StringSource(biv, true,
						new ArraySink(iv, sizeof(iv)) // ArraySink
			);										   // StringSource
		}
			break;
		case 3:
		{
			string hkey, hiv, decode,bkey,biv;
			FileSource("key.txt", true, new StringSink(hkey));
			wcout << string2wstring(hkey) << endl;
			// Convert string to key (binary)
			StringSource(hkey, true,
				new HexDecoder(
					new StringSink(bkey)
				) // HexDecoder
			); // StringSource
			StringSource(bkey, true,
				new ArraySink(key, sizeof(key)) // ArraySink
		);											 // StringSource

		FileSource("iv.txt", true, new StringSink(hiv));
			wcout << string2wstring(hiv) << endl;

		// Convert string to iv (binary)
		StringSource(hiv, true,
					 new HexDecoder(
						 new StringSink(biv)) // HexDecoder
		);									  // StringSource
		StringSource(biv, true,
					 new ArraySink(iv, sizeof(iv)) // ArraySink
		);										   // StringSource


		}
	}
	encoded.clear();
	StringSource(key, sizeof(key), true,
				 new HexEncoder(
					 new StringSink(encoded)) // HexEncoder
	);										  // StringSource
	wcout << "key: " << string2wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
				 new HexEncoder(
					 new StringSink(encoded)) // HexEncoder
	);										  // StringSource
	wcout << "iv: " << string2wstring(encoded) << endl;


	wcout << endl<< "1.Input text from screen \n2. Load text from file \n Note: Only get cipher text in type Hex";
	wcout<<"\nEnter mode text: "; // Choose mode for plaintext
	std::wcin.sync();
    std::wcin >> modetext;
    switch (modetext)
    {
        case 1:
        {
            wcout << endl<< "Input text: ";
            std::wcin.sync();
            std::getline(std::wcin, plain1);
            plain = wstring2string(plain1);
        }
            break;
        case 2:
        {
            
			if ( mode_ende ==2)
			{
				FileSource("ciphertext.txt", true, new StringSink(plain));
            	//wcout << "Check text: " << string2wstring(plain) << endl;
			}
			else {
				FileSource("plaintext.txt", true, new StringSink(plain));
            	//wcout << "Check text: " << string2wstring(plain) << endl;
			}
        }
            break;
    }
	
	switch (mode_ende)
	{
	case 1:
		{

			switch (modesup)
			{
			case 1: //mode encrypt ECB
				mainECB(key,plain, cipher, mode_ende);
				break;
			case 2:  //mode encrypt CBC
				mainCBC (key,iv, plain, cipher, mode_ende);
				break;
			case 3:  //mode encrypt OFB
				mainOFB(key,iv, plain, cipher, mode_ende);
				break;
			case 4: //mode CTR
				mainCTR (key,iv, plain, cipher, mode_ende);
				break; 
			case 5:  //mode CFB
				mainCFB (key,iv, plain, cipher, mode_ende);
				break;
			case 6: //mode XTS
				mainXTS (key,iv, plain, cipher, mode_ende);
				break;
			case 7: //mode CCM
				mainCCM(key,iv,plain,cipher, mode_ende);
				break;
			case 8: // ENCRYPT mode GCM
				mainGCM(key,iv,plain,cipher, mode_ende);
				break;
			}
			
		
		}
		break;

	
	case 2:
	{
		// Convert wstring to string
		cipher2 = wstring2string(plain1);
		
		switch (modesup)
		{
			case 1:  //mode ECB
				mainECB(key,plain, cipher2, mode_ende);
				break;
			case 2:  // mode CBC
				mainCBC (key,iv, plain, cipher2, mode_ende);
				break;
			case 3:  //mode OFB
				mainOFB(key,iv, plain, cipher2, mode_ende);
				break;
			case 4: //mode CTR
				mainCTR (key,iv, plain, cipher2, mode_ende);
				break;
			case 5:  //mode CFB
				mainCFB (key,iv, plain, cipher2, mode_ende);
				break;
			case 6: //mode XTS
				mainXTS (key,iv, plain, cipher2, mode_ende);
				break;
			case 7:  //mode CCM
				mainCCM (key,iv,plain,cipher2, mode_ende);
				break;
			case 8: //mode GCM
				mainGCM (key,iv,plain,cipher2, mode_ende);
				break;

		}

	}
		break;
	}
	

	return 0;
}

