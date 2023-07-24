
#include "cryptopp/gcm.h"
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;

#include "assert.h"

void mainGCM(byte key[32],byte iv[12],string pdata, string cipher3, int mode_ende)
{

    wcout << L"Enter additional authenticated data (adata): ";
    wstring wadata;  string adata;
    std::wcin.sync();
    std::getline(std::wcin, wadata);
    adata = wstring2string(wadata);

    const int TAG_SIZE = 16;

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
            GCM< AES >::Encryption e;
            e.SetKeyWithIV( key, 32, iv, 12 );
            // Not required for GCM mode (but required for CCM mode)
            // e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );

            AuthenticatedEncryptionFilter ef( e,
                new StringSink( cipher ), false, TAG_SIZE
            ); // AuthenticatedEncryptionFilter

            // AuthenticatedEncryptionFilter::ChannelPut
            //  defines two channels: "" (empty) and "AAD"
            //   channel "" is encrypted and authenticated
            //   channel "AAD" is authenticated
            ef.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() );
            ef.ChannelMessageEnd("AAD");

            // Authenticated data *must* be pushed before
            //  Confidential/Authenticated data. Otherwise
            //  we must catch the BadState exception
            ef.ChannelPut( "", (const byte*)pdata.data(), pdata.size() );
            ef.ChannelMessageEnd("");

            // Pretty print
            StringSource( cipher, true,
                new HexEncoder( new StringSink( encoded ), true) );

            wcout << "cipher text: " << endl << " " << string2wstring(encoded)  << endl;
            wcout << endl;

        }
        catch( CryptoPP::BufferedTransformation::NoChannelSupport& e )
        {
            // The tag must go in to the default channel:
            //  "unknown: this object doesn't support multiple channels"
            cerr << "Caught NoChannelSupport..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
        }
        catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
        {
            // Pushing PDATA before ADATA results in:
            //  "GMC/AES: Update was called before State_IVSet"
            cerr << "Caught BadState..." << endl;
            cerr << e.what() << endl;
            cerr << endl;
        }
        catch( CryptoPP::InvalidArgument& e )
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
            GCM< AES >::Decryption d;
            d.SetKeyWithIV( key, 32, iv, 12 );

            // Break the cipher text out into it's
            //  components: Encrypted Data and MAC Value
            string enc = cipher2.substr( 0, cipher2.length()-TAG_SIZE );
            string mac = cipher2.substr( cipher2.length()-TAG_SIZE );

            // Sanity checks
            assert( cipher2.size() == enc.size() + mac.size() );
            assert( enc.size() == pdata.size() );
            assert( TAG_SIZE == mac.size() );

            // Not recovered - sent via clear channel
            radata = adata;     

            // Object will not throw an exception
            //  during decryption\verification _if_
            //  verification fails.
            //AuthenticatedDecryptionFilter df( d, NULL,
            // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

            AuthenticatedDecryptionFilter df( d, NULL,
                AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );

            // The order of the following calls are important
            df.ChannelPut( "", (const byte*)mac.data(), mac.size() );
            df.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() ); 
            df.ChannelPut( "", (const byte*)enc.data(), enc.size() );               

            // If the object throws, it will most likely occur
            //  during ChannelMessageEnd()
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
        catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
        {
            // Pushing PDATA before ADATA results in:
            //  "GMC/AES: Update was called before State_IVSet"
            cerr << "Caught BadState..." << endl;
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
