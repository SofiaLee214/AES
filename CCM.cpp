
#include "cryptopp/ccm.h"
using CryptoPP::CCM;

#include "assert.h"

void mainCCM(byte key[AES::DEFAULT_KEYLENGTH],byte iv[12],string pdata, string cipher3, int mode_ende)
{
    
   /* // Generate random key and IV
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(iv, 12);*/

    wcout << L"Enter additional authenticated data (adata): ";
    wstring wadata;  string adata;
    std::wcin.sync();
    std::getline(std::wcin, wadata);
    adata = wstring2string(wadata);
    
    const int TAG_SIZE = 8;

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string radata, rpdata;

    switch (mode_ende)
    {
    case 1:
    {
        try
        {
            CCM<AES, TAG_SIZE>::Encryption e;
            e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, 12);
            e.SpecifyDataLengths(adata.size(), pdata.size(), 0);

            AuthenticatedEncryptionFilter ef(e, new StringSink(cipher)); // AuthenticatedEncryptionFilter

            // AuthenticatedEncryptionFilter::ChannelPut
            //  defines two channels: "" (empty) and "AAD"
            //   channel "" is encrypted and authenticated
            //   channel "AAD" is authenticated
            ef.ChannelPut("AAD", (const byte*)adata.data(), adata.size());
            ef.ChannelMessageEnd("AAD");

            // Authenticated data *must* be pushed before
            //  Confidential/Authenticated data
            ef.ChannelPut("", (const byte*)pdata.data(), pdata.size());
            ef.ChannelMessageEnd("");

            // Pretty print
            StringSource(cipher, true, new HexEncoder(new StringSink(encoded), true));

            wcout << "cipher text (enc + tag): " << endl << " " <<string2wstring(encoded)  << endl;
            wcout << endl;
        }
        catch (CryptoPP::BufferedTransformation::NoChannelSupport& e)
        {
            // The tag must go in to the default channel:
            //  "unknown: this object doesn't support multiple channels"
            cerr << "Caught NoChannelSupport..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
        }
        catch (CryptoPP::InvalidArgument& e)
        {
            cerr << "Caught InvalidArgument..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
        }

    }
        break;
    
    case 2:
    {
        string cipher2;
        StringSource(pdata, true,
                    new HexDecoder(
                        new StringSink(cipher2)) // HexDecoder
            );	
        
        try
        {
            // Break the cipher text out into it's
            //  components: Encrypted and MAC
            string enc = cipher2.substr( 0, cipher2.length()-TAG_SIZE );
            string tag = cipher2.substr( cipher2.length()-TAG_SIZE );

            // Sanity checks
            assert( cipher2.size() == enc.size() + tag.size() );
            assert( enc.size() == pdata.size() );
            assert( TAG_SIZE == tag.size() );

            // Not recovered - sent via clear channel
            radata = adata;

            CCM< AES, TAG_SIZE >::Decryption d;
            d.SetKeyWithIV( key, AES::DEFAULT_KEYLENGTH, iv, 12 );
            d.SpecifyDataLengths( radata.size(), enc.size(), 0 );

            // Object will not throw an exception
            //  during decryption\verification _if_
            //  verification fails.
            //AuthenticatedDecryptionFilter df( d, NULL,
            // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

            AuthenticatedDecryptionFilter df( d, NULL,
                //AuthenticatedDecryptionFilter::MAC_AT_BEGIN | 
                AuthenticatedDecryptionFilter::THROW_EXCEPTION );

            // The order of the following calls are important        
            df.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() );
            df.ChannelPut( "", (const byte*)enc.data(), enc.size() );
            df.ChannelPut( "", (const byte*)tag.data(), tag.size() );

            df.ChannelMessageEnd( "AAD" );
            df.ChannelMessageEnd( "" );

            

            // Remove data from channel
            string retrieved;
            size_t n = (size_t)-1;

            // Plain text recovered from enc.data()
            df.SetRetrievalChannel( "" );
            n = (size_t)df.MaxRetrievable();
            retrieved.resize( n );

            if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
            rpdata = retrieved;
            assert( rpdata == pdata );

            // Hmmm... No way to get the calculated MAC
            // tag out of the Decryptor/Verifier. At
            // least it is purported to be good.
            //df.SetRetrievalChannel( "AAD" );
            //n = (size_t)df.MaxRetrievable();
            //retrieved.resize( n );

            //if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
            //assert( retrieved == tag );

            // All is well - work with data
            wcout << "Decrypted and Verified data. Ready for use." << endl;
            wcout << endl;

            wcout << "recovered adata: " << string2wstring(radata)  << endl;
            wcout << "recovered pdata: " << string2wstring(rpdata)  << endl;
            wcout << endl;
        }
        catch( CryptoPP::InvalidArgument& e )
        {
            cerr << "Caught InvalidArgument..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
        }
        catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
        {
            cerr << "Caught HashVerificationFailed..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
        }

    }

        break;
    }
  
}
