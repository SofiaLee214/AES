#include "cryptopp/ccm.h"
using CryptoPP::CBC_Mode;


void mainCBC(byte key[AES::DEFAULT_KEYLENGTH],byte iv[AES::BLOCKSIZE],string plain, string cipher, int mode_ende)
{
	
	string encoded, recovered;
switch (mode_ende)
{
case 1:
{
	try
		{
			CBC_Mode< AES >::Encryption e;
			e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

			// The StreamTransformationFilter removes
			//  padding as required.
			StringSource s(plain, true, 
				new StreamTransformationFilter(e,
					new StringSink(cipher)
				) // StreamTransformationFilter
			); // StringSource

	#if 0
			StreamTransformationFilter filter(e);
			filter.Put((const byte*)plain.data(), plain.size());
			filter.MessageEnd();

			const size_t ret = filter.MaxRetrievable();
			cipher.resize(ret);
			filter.Get((byte*)cipher.data(), cipher.size());
	#endif
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
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher1, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif

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

