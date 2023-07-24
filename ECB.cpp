
#include "cryptopp/modes.h"
using CryptoPP::ECB_Mode;

void mainECB( byte key[AES::DEFAULT_KEYLENGTH],string plain, string &cipher, int mode_ende)
{
	string encoded, recovered;
	//wcout<<"plain: "<<string2wstring(plain)<<endl;
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
				
				ECB_Mode< AES >::Encryption e;
				e.SetKey(key, AES::DEFAULT_KEYLENGTH);

				// The StreamTransformationFilter adds padding
				//  as required. ECB and CBC Mode must be padded
				//  to the block size of the cipher.
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
			encoded.clear();
			StringSource(cipher, true,
						new HexEncoder(
							new StringSink(encoded)) // HexEncoder
			);										  // StringSource
			wcout << "cipher text (hex): " << string2wstring(encoded) << endl;
/*
			encoded.clear();
			StringSource(cipher, true,
						new Base64Encoder(
							new StringSink(encoded)) // HexEncoder
			);										  // StringSources
			wcout << "cipher text (Base64): " << string2wstring(encoded) << endl; */
			

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
			ECB_Mode< AES >::Decryption d;
			d.SetKey(key, AES::DEFAULT_KEYLENGTH);

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

