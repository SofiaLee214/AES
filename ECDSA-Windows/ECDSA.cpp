// ECDSA.KeyGen.cpp : Defines the entry point for the console application.
//

#include <assert.h>

#include <iostream>
using std::cerr;
using std::cout;

using std::cin;
using std::endl;

#include <string>
using std::string;

#include "cryptopp/osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/sha.h"
using CryptoPP::SHA512;

#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/eccrypto.h"
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECDSA;
using CryptoPP::ECP;

#include "cryptopp/oids.h"
using CryptoPP::OID;
#include <chrono>
using namespace std::chrono;

bool GeneratePrivateKey(const OID &oid, ECDSA<ECP, SHA512>::PrivateKey &key);
bool GeneratePublicKey(const ECDSA<ECP, SHA512>::PrivateKey &privateKey, ECDSA<ECP, SHA512>::PublicKey &publicKey);

void SavePrivateKey(const string &filename, const ECDSA<ECP, SHA512>::PrivateKey &key);
void SavePublicKey(const string &filename, const ECDSA<ECP, SHA512>::PublicKey &key);
void LoadPrivateKey(const string &filename, ECDSA<ECP, SHA512>::PrivateKey &key);
void LoadPublicKey(const string &filename, ECDSA<ECP, SHA512>::PublicKey &key);

void PrintDomainParameters(const ECDSA<ECP, SHA512>::PrivateKey &key);
void PrintDomainParameters(const ECDSA<ECP, SHA512>::PublicKey &key);
void PrintDomainParameters(const DL_GroupParameters_EC<ECP> &params);
void PrintPrivateKey(const ECDSA<ECP, SHA512>::PrivateKey &key);
void PrintPublicKey(const ECDSA<ECP, SHA512>::PublicKey &key);

bool SignMessage(const ECDSA<ECP, SHA512>::PrivateKey &key, const string &message, string &signature);
bool VerifyMessage(const ECDSA<ECP, SHA512>::PublicKey &key, const string &message, const string &signature);

//////////////////////////////////////////
// In 2010, use SHA-256 and P-256 curve
//////////////////////////////////////////

int main(int argc, char *argv[])
{
    auto start = high_resolution_clock::now();
    // Scratch result
    string message;

    string messageFile;
    string signature;
    // Private and Public keys
    ECDSA<ECP, SHA512>::PrivateKey privateKey;
    ECDSA<ECP, SHA512>::PublicKey publicKey;
    int mode;
    cout << "Please choose mode: 1. Key generation; 2. Sign message; 3. Verify message" << endl;
    cin >> mode;
    switch (mode)
    {
    case 1:
        /////////////////////////////////////////////
        // Generate Keys
        GeneratePrivateKey(CryptoPP::ASN1::secp256k1(), privateKey);
        GeneratePublicKey(privateKey, publicKey);
        /////////////////////////////////////////////
        // Save key in PKCS#9 and X.509 format
        SavePrivateKey("ecc.private.pem", privateKey);
        SavePublicKey("ecc.public.pem", publicKey);

        /////////////////////////////////////////////
        break;
    case 2:
        LoadPrivateKey("ecc.private.pem", privateKey);
        // get message from file or input from screen
        cout << "Please input message: " << endl;
        cout << "1. From file\n 2. From screen" << endl;
        int modem;
        cin >> modem;
        switch (modem)
        {
        case 1:
        {
            cout << "Please input message: " << endl;
            cout << "1. Message 1 (39 bytes)\n2. Message 2 (445 bytes)\n3. Message 3 (1.19KB)\n4. Message 4 (3.25KB)\n5. Message 5 (79MB)\n6. Message 6 (316MB)" << endl;
            int modem1;
            cin >> modem1;
            switch (modem1)
            {
            case 1:
                messageFile = "message1.txt";
                break;
            case 2:
                messageFile = "message2.txt";
                break;
            case 3:
                messageFile = "message3.txt";
                break;
            case 4:
                messageFile = "message4.txt";
                break;
            case 5:
                messageFile = "message5.txt";
                break;
            case 6:
                messageFile = "message6.txt";
                break;
            }

            FileSource fs(messageFile.c_str(), false /*pumpAll*/);
            CryptoPP::StringSink ss(message);
            fs.Detach(new CryptoPP::Redirector(ss));
            fs.PumpAll();
            break;
        }
        case 2:
        {
            cout << "Please input message: " << endl;
            cin.ignore();
            getline(cin, message);
            messageFile = "inpmessage.txt";
            // Save message
            FileSink fs(messageFile.c_str());
            fs.Put((CryptoPP::byte *)message.data(), message.size());
            fs.MessageEnd();
            break;
        }
        }
        SignMessage(privateKey, message, signature);
        if (SignMessage(privateKey, message, signature))
        {
            cout << "Signature: " << signature << endl;
            // Save signature
            string file = messageFile.erase(10, 15);
            string signatureFile = file + ".signature.txt";
            FileSink fs(signatureFile.c_str());
            fs.Put((CryptoPP::byte *)signature.data(), signature.size());
            fs.MessageEnd();
            cout << "Message signed" << endl;
        }
        else
        {
            cout << "Message signing failed" << endl;
        }
        break;

    case 3:
        LoadPublicKey("ecc.public.pem", publicKey);
        // get message from file
        cout << "Please input message to verify: " << endl;
        cout << "1. Message 1 (39 bytes)\n2. Message 2 (445 bytes)\n3. Message 3 (1.19KB)\n4. Message 4 (3.25KB)\n5. Message 5 (79MB)\n6. Message 6 (316MB)\n7. Message input from screen" << endl;
        int modem1;
        cin >> modem1;
        switch (modem1)
        {
        case 1:
            messageFile = "message1.txt";
            break;
        case 2:
            messageFile = "message2.txt";
            break;
        case 3:
            messageFile = "message3.txt";
            break;
        case 4:
            messageFile = "message4.txt";
            break;
        case 5:
            messageFile = "message5.txt";
            break;
        case 6:
            messageFile = "message6.txt";
            break;
        case 7:
            messageFile = "inpmessage.txt";
            break;
        }
        FileSource fs1(messageFile.c_str(), false /*pumpAll*/);
        CryptoPP::StringSink ss1(message);
        fs1.Detach(new CryptoPP::Redirector(ss1));
        fs1.PumpAll();
        /////////////////////////////////////////////
        // Load signature
        string file = messageFile.erase(10, 15);
        string signatureFile = file + ".signature.txt";
        string signature;
        FileSource fs(signatureFile.c_str(), false /*pumpAll*/);
        CryptoPP::StringSink ss(signature);
        fs.Detach(new CryptoPP::Redirector(ss));
        fs.PumpAll();
        /////////////////////////////////////////////
        // Verify the signature
        if (VerifyMessage(publicKey, message, signature))
        {
            cout << "Signature on message is verified" << endl;
        }
        else
        {
            cout << "Message verification failed" << endl;
        }

        break;
    }
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(stop - start);
    cout << "Time taken by function: " << duration.count() << " milliseconds" << endl;
    system("pause");
    return 0;
}

bool GeneratePrivateKey(const OID &oid, ECDSA<ECP, SHA512>::PrivateKey &key)
{
    AutoSeededRandomPool prng;

    key.Initialize(prng, oid);
    assert(key.Validate(prng, 512));

    return key.Validate(prng, 512);
}

bool GeneratePublicKey(const ECDSA<ECP, SHA512>::PrivateKey &privateKey, ECDSA<ECP, SHA512>::PublicKey &publicKey)
{
    AutoSeededRandomPool prng;

    // Sanity check
    assert(privateKey.Validate(prng, 512));

    privateKey.MakePublicKey(publicKey);
    assert(publicKey.Validate(prng, 512));

    return publicKey.Validate(prng, 512);
}

void PrintDomainParameters(const ECDSA<ECP, SHA512>::PrivateKey &key)
{
    PrintDomainParameters(key.GetGroupParameters());
}

void PrintDomainParameters(const ECDSA<ECP, SHA512>::PublicKey &key)
{
    PrintDomainParameters(key.GetGroupParameters());
}

void PrintDomainParameters(const DL_GroupParameters_EC<ECP> &params)
{
    cout << endl;

    cout << "Modulus:" << endl;
    cout << " " << params.GetCurve().GetField().GetModulus() << endl;

    cout << "Coefficient A:" << endl;
    cout << " " << params.GetCurve().GetA() << endl;

    cout << "Coefficient B:" << endl;
    cout << " " << params.GetCurve().GetB() << endl;

    cout << "Base Point:" << endl;
    cout << " X: " << params.GetSubgroupGenerator().x << endl;
    cout << " Y: " << params.GetSubgroupGenerator().y << endl;

    cout << "Subgroup Order:" << endl;
    cout << " " << params.GetSubgroupOrder() << endl;

    cout << "Cofactor:" << endl;
    cout << " " << params.GetCofactor() << endl;
}

void PrintPrivateKey(const ECDSA<ECP, SHA512>::PrivateKey &key)
{
    cout << endl;
    cout << "Private Exponent:" << endl;
    cout << " " << key.GetPrivateExponent() << endl;
}

void PrintPublicKey(const ECDSA<ECP, SHA512>::PublicKey &key)
{
    cout << endl;
    cout << "Public Element:" << endl;
    cout << " X: " << key.GetPublicElement().x << endl;
    cout << " Y: " << key.GetPublicElement().y << endl;
}

void SavePrivateKey(const string &filename, const ECDSA<ECP, SHA512>::PrivateKey &key)
{
    key.Save(FileSink(filename.c_str(), true /*binary*/).Ref());
}

void SavePublicKey(const string &filename, const ECDSA<ECP, SHA512>::PublicKey &key)
{
    key.Save(FileSink(filename.c_str(), true /*binary*/).Ref());
}

void LoadPrivateKey(const string &filename, ECDSA<ECP, SHA512>::PrivateKey &key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

void LoadPublicKey(const string &filename, ECDSA<ECP, SHA512>::PublicKey &key)
{
    key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

bool SignMessage(const ECDSA<ECP, SHA512>::PrivateKey &key, const string &message, string &signature)
{
    AutoSeededRandomPool prng;

    signature.erase();

    StringSource(message, true,
                 new SignerFilter(prng,
                                  ECDSA<ECP, SHA512>::Signer(key),
                                  new StringSink(signature)) // SignerFilter
    );                                                       // StringSource

    return !signature.empty();
}

bool VerifyMessage(const ECDSA<ECP, SHA512>::PublicKey &key, const string &message, const string &signature)
{
    bool result = false;

    StringSource(signature + message, true,
                 new SignatureVerificationFilter(
                     ECDSA<ECP, SHA512>::Verifier(key),
                     new ArraySink((CryptoPP::byte *)&result, sizeof(result))) // SignatureVerificationFilter
    );

    return result;
}
