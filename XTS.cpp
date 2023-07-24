
#include "cryptopp/xts.h"
using CryptoPP::XTS_Mode;


void mainXTS(byte key[32],byte iv[16],string plain,string cipher, int mode_ende)
{
   
    std::string  encoded, recovered;
    switch (mode_ende)
    {
    case 1:
    {
            try
        {
            XTS_Mode< AES >::Encryption enc;
            enc.SetKeyWithIV( key, 32, iv );

    #if 0
            std::cout << "key length: " << enc.DefaultKeyLength() << std::endl;
            std::cout << "key length (min): " << enc.MinKeyLength() << std::endl;
            std::cout << "key length (max): " << enc.MaxKeyLength() << std::endl;
            std::cout << "block size: " << enc.BlockSize() << std::endl;
    #endif

            // The StreamTransformationFilter adds padding
            //  as requiredec. ECB and XTS Mode must be padded
            //  to the block size of the cipher.
            StringSource ss( plain, true, 
                new StreamTransformationFilter( enc,
                    new StringSink( cipher ),
                    StreamTransformationFilter::NO_PADDING
                ) // StreamTransformationFilter      
            ); // StringSource
        
        }
        catch( const CryptoPP::Exception& ex )
        {
            std::cerr << ex.what() << std::endl;
            exit(1);
        }

        /*********************************\
        \*********************************/

        // Pretty print cipher text
        encoded.clear();
        StringSource ss3( cipher, true,
            new HexEncoder(
                new StringSink( encoded )
            ) // HexEncoder
        ); // StringSource
        wcout << "cipher text: " << string2wstring(encoded)  << endl;
        

		encoded.clear();
		StringSource s3(cipher, true,
					new Base64Encoder(
						new StringSink(encoded)) // HexEncoder
			);										  // StringSources
		wcout << "\ncipher text (Base64): " << string2wstring(encoded) << endl; 
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
            XTS_Mode< AES >::Decryption dec;
            dec.SetKeyWithIV( key, 32, iv );

            // The StreamTransformationFilter removes
            //  padding as requiredec.
            StringSource ss( cipher1, true, 
                new StreamTransformationFilter( dec,
                    new StringSink( recovered ),
                    StreamTransformationFilter::NO_PADDING
                ) // StreamTransformationFilter
            ); // StringSource        
            wcout << "\nrecovered text: " << string2wstring(recovered) << endl;
        }
        catch( const CryptoPP::Exception& ex )
        {
            std::cerr << ex.what() << std::endl;
            exit(1);
        }
    
    }
        break;
    }

    
}
