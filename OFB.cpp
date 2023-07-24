
#include "cryptopp/modes.h"
using CryptoPP::OFB_Mode;

void mainOFB (byte key[AES::DEFAULT_KEYLENGTH],byte iv[AES::BLOCKSIZE],string plain, string cipher, int mode_ende)
{
	string encoded, recovered;
	wcout<<"plain: "<<string2wstring(plain)<<endl;
	encoded.clear();
	StringSource(key, AES::DEFAULT_KEYLENGTH, true,
				 new HexEncoder(
					 new StringSink(encoded)) // HexEncoder
	);										  // StringSource
	wcout << "key: " << string2wstring(encoded) << endl;  
	switch (mode_ende)
	{
		case 1:
		{

			try
			{
				cout << "plain text: " << plain << endl;

				OFB_Mode< AES >::Encryption e;
				e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);  //key, sixeof(key), iv

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
		
		//Decrypt

		try
		{
			OFB_Mode< AES >::Decryption d;
			d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);  //key, sixeof(key), iv

			// The StreamTransformationFilter removes
			//  padding as required.
			StringSource s(cipher, true, 
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

