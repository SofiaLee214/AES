
#include "cryptopp/ccm.h"
using CryptoPP::CTR_Mode;


void mainCTR(byte key[AES::DEFAULT_KEYLENGTH],byte iv[AES::BLOCKSIZE],string plain, string cipher, int mode_ende)

{
	string encoded, recovered;

	switch (mode_ende)
	{
	case 1:
		{
			try
			{
				
				CTR_Mode< AES >::Encryption e;
				e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

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
			CTR_Mode< AES >::Decryption d;
			d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

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

