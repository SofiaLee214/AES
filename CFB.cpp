
#include "cryptopp/modes.h"
using CryptoPP::CFB_Mode;

void mainCFB(byte key[AES::DEFAULT_KEYLENGTH],byte iv[AES::BLOCKSIZE],string plain, string cipher, int mode_ende)
{
	string encoded, recovered;
	
	switch (mode_ende)
	{
		case 1:
		{

			try
			{
				CFB_Mode< AES >::Encryption e;
				e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv); //key, sixeof(key), iv

				// CFB mode must not use padding. Specifying
				//  a scheme will result in an exception
				StringSource(plain, true, 
					new StreamTransformationFilter(e,
						new StringSink(cipher)
					) // StreamTransformationFilter      
				); // StringSource
			}
			catch(const CryptoPP::Exception& e)
			{
				cerr << e.what() << endl;
				exit(1);
			}

			//print ciphertext
			encoded.clear();
			StringSource(cipher, true,
						new HexEncoder(
							new StringSink(encoded)) // HexEncoder
			);										  // StringSource
			wcout << "cipher text (hex): " << string2wstring(encoded) << endl;

			encoded.clear();
			StringSource(cipher, true,
						new Base64Encoder(
							new StringSink(encoded)) // HexEncoder
			);										  // StringSources
			wcout << "cipher text (Base64): " << string2wstring(encoded) << endl; 
		}
		break;
		case 2:
		{
			string cipher1;
			StringSource(plain, true,
					new HexDecoder(
						new StringSink(cipher1)) // HexDecoder
			);	
			try
			{
				CFB_Mode< AES >::Decryption d;
				d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv); //key, sixeof(key), iv

				// The StreamTransformationFilter removes
				//  padding as required.
				StringSource s(cipher1, true, 
					new StreamTransformationFilter(d,
						new StringSink(recovered)
					) // StreamTransformationFilter
				); // StringSource

			wcout << "recovered text: " << string2wstring(recovered) << endl;
			}
			catch(const CryptoPP::Exception& e)
			{
				cerr << e.what() << endl;
				exit(1);
			}

		}
		break;
	}

	
}

