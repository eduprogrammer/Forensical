#include <Windows.h>
#include <wincrypt.h>

/*
	Copyright 2021. Eduardo Programador
	www.eduardoprogramador.com
	All rights reserved
	Contact him at:
	E-mail: consultoria@eduardoprogramador.com
	WhatsApp: +55 81 98860 0704
	Instagram: @eduardo_programador	
	
*/

/*
	Hash type algorithms
	that must fill the HASH_TYPE
	in the call of the cryptographic functions
	The Format is:
	HASH_(ALGORITHM).
	The algorithm may be one of the following ones:
	md2, md5, sha (sha1), sha256 and sha512.
*/

#define HASH_MD2 0
#define HASH_MD5 1
#define HASH_SHA 2
#define HASH_SHA256 3
#define HASH_SHA512 4

/*
	HMAC_TYPES
	The format is: HMAC_(CHECKSUM)
	The cheksum may be:
	md5, sha (sha1), sha256 and sha512.
*/
#define HMAC_MD5 0
#define HMAC_SHA 1
#define HMAC_SHA256 2
#define HMAC_SHA512 3

/*
	These ara the key types
	of the cryptography algorithms.
	The format is:
	KEY_(TYPE)_(SIZE)
*/

#define KEY_RANDOM 0
#define KEY_PASSPHRASE 1
#define KEY_RC2_40 2
#define KEY_RC4_40 3
#define KEY_DES_56 4
#define KEY_2DES_112 5
#define KEY_3DES_168 6
#define KEY_AES_128 7
#define KEY_AES_192 8
#define KEY_AES_256 9

/*
	Encryption modes.
	ECB: Electronic Codebook
	CBC: Cypher Block Chaining
	CFB: Cipher Feedback
	OFB: Output Feedback
*/
#define ECB 0
#define CBC 1
#define CFB 2
#define OFB 3

/*
	FORENSICAL_HASH or FORENSICAL_HMAC struct.
	szHashData: A pointer of a char that will hold the output of the hash.
	dwHashSize: The size of the hash that will based on the char pointer.
*/
typedef struct {

	char* szHashData;
	DWORD dwHashSize;

} FORENSICAL_HASH, FORENSICAL_HMAC;

/*
	FORENSICAL_KEY struct.
	pbKey: The cryptographic key in raw value.
	dwKeySize: The key size.
	algId: the ALG_ID object of the key
*/
typedef struct {

	BYTE* pbKey;
	DWORD dwKeySize;
	ALG_ID algId;

} FORENSICAL_KEY, * PFORENSICAL_KEY;

/*
	FORENSICAL_DATA struct.
	pbData: The raw value to be encrypted or decrypted.
	dwOutputLen: The size of the output encrypted or decrypted.
	dwSrcLen: The size of the input data encrypted or decrypted.
	isEncrypted: A boolean variable that affirms if the operation is encryption
		or decription.
*/
typedef struct FORENSICAL_DATA
{
	BYTE* pbData;
	DWORD dwOutputLen;
	DWORD dwSrcLen;
	BOOL bIsEncrypted;
} *PFORENSICAL_DATA;


/*
	This namespace contains some projects
	developed by Eduardo Programador.
*/
namespace EduardoProgramador
{	

	/*
		This class contains functions to 
		build cryptographic operations on string and in 
		raw data. 
	*/
	class Forensical
	{	

	public:
		/*
			The public constructor. It does not require
			any special argument
		*/
		__declspec(dllexport) Forensical();

		/*
			The Forensical class destructor also 
			does not require any special arguments.
		*/
		__declspec(dllexport) ~Forensical();

		/*
			Creates a new Forensical Key Object that will be handled by the
			FORENSICAL_KEY struct pointer.
			The first version is destinated to passphrase encryption

			Params:

			HASH_TYPE: The hash type
			passprase: the passphrase used to encrypt or decrypt the content
			KEY_TYPE: The type of the key.
			fKey: A pointer to a FORENSICAL_KEY struct that will get the generated key.

		*/
		__declspec(dllexport) BOOL ForensicalCreateKey(unsigned int HASH_TYPE, const char* passphrase, unsigned int KEY_TYPE, FORENSICAL_KEY* fKey);

		/*
			Creates a new Forensical Key object that will be handled by the
			FORENSICAL_KEY struct pointer.
			The second version doest not require a passphrase.

			Params:

			KEY_TYPE: A key type. You must choose an encryption algotithm key.
			fKey: A pointer to a FORENSICAL_KEY struct that will get the key.

		*/
		__declspec(dllexport) BOOL ForensicalCreateKey(unsigned int KEY_TYPE, FORENSICAL_KEY* fKey);

		/*
			Saves the key in raw format to a file in the local machice.
			Important: The key must be protected in a local safe place.

			Params:

			fKey: The forensical key to read from
			szPath: A char pointer that contains the path to save in.
		*/
		__declspec(dllexport) BOOL ForensicalWriteKeyToFile(FORENSICAL_KEY* fKey, const char* szPath);

		/*
			Reads the key saved in your local machine
			to start some encryption or decryption routine later.

			Params:

			fKey: A pointer to a Forensical Key struct to write the bytes to read from the key file.
			szPath: A char pointer that represents the file path of the key to read from
			KEY_TYPE: The key type. The user must to know the key he or she works with
		*/
		__declspec(dllexport) BOOL ForensicalGetKeyFromFile(FORENSICAL_KEY* fKey, const char* szPath, unsigned int KEY_TYPE);

		/*
			Encrypts a source string into an encrypted one.
			This function also works to encrypt casted data.

			Params:

			fKey: A FORENSICAL_KEY struct that contains the key.
			szDataSrc: A pointer to a char type that holds the string to be encrypted.
			fData: The struct of a pointer that will hold the result of the encryption
		*/
		__declspec(dllexport) BOOL ForensicalEncrypt(FORENSICAL_KEY* fKey, const char* szDataSrc, FORENSICAL_DATA* fData);

		/*
			Encrypts a binary file.
			The user must provide the source path and the output path of the encrypted file

			Params:

			fKey: A FORENSICAL_KEY struct that contains the key.
			szFileIn: The full path of the file to be encrypted.
			szFileOut: The encrypted file path to save to.
		*/
		__declspec(dllexport) BOOL ForensicalEncrypt(FORENSICAL_KEY* fKey, const char* szFileIn, const char* szFileOut);

		/*
			Decrypts an encrypted string.

			Params:

			fKey: A FORENSICAL_KEY struct that contains the key.
			szFileEncrypted: The full path of the file to be decrypted.
			szFileToDecrypted: The decrypted file path to save to.

		*/
		__declspec(dllexport) BOOL ForensicalDecrypt(FORENSICAL_KEY* fKey, const char* szFileEncrypted, const char* szFileToDecrypt);

		/*
			fKey: A FORENSICAL_KEY struct that contains the key.
			fDataInput: A FORENSICAL_DATA struct that contains some date to decrypted.
			fDataOutput: A FORENSICAL_DATA struct that will receive the decrypted data
		*/
		__declspec(dllexport) BOOL ForensicalDecrypt(FORENSICAL_KEY* fKey, FORENSICAL_DATA* fDataInput, FORENSICAL_DATA* fDataOutput);

		/*
			Calculates the checksum (MD5, SHA, etc.),
			of a given string.

			Params:

			HASH_TYPE: The type of the hash algorithm
			str: A char pointer that contains the raw data.
			fh: A FORENSICAL_HASH struct that will receive the calculated checksum and other data.
		*/	
		__declspec(dllexport) BOOL ForensicalGetHash(unsigned int HASH_TYPE, const char* str, FORENSICAL_HASH* fh);

		/*
			Calculates the checksum (MD5, SHA, etc.),
			of a given file.

			Params:

			HASH_TYPE: The type of the hash algorithm
			szFileIn: A pointer to a constant string represents the file path.
			fh: A FORENSICAL_HASH struct that will receive the calculated checksum and other data.
		*/

		__declspec(dllexport) BOOL ForensicalGetHashF(unsigned int HASH_TYPE, LPCSTR szFileIn, FORENSICAL_HASH* fh);


		/*
			Calculate the MAC (Message Authentication Code) of some data.

			Params:

			HMAC_TYPE: The type of the MAC algorithm
			fKey: The key that contains the simetric algorithm needed to calculate the HMAC
			str: A char pointer of the source string (or casted data)
			fHmac: A pointer to a FORENSICAL_HMAC struct that will receive the calculated MAC code.
		*/
		__declspec(dllexport) BOOL ForensicalGetMac(unsigned int HMAC_TYPE, FORENSICAL_KEY* fKey, const char* str, FORENSICAL_HMAC* fHmac);

		/*
			Encodes a string into Base64 format

			Params:

			srcStr: The original string to be converted
			out: A char pointer that will receive the encoded Base64 string
		*/
		__declspec(dllexport) BOOL ForensicalToBase64(const char* srcStr, char* out);

		/*
			Decodes a Base64 string into a normal string

			Params:

			src64: The base64 string to be converted
			out: A char pointer that will receive the decoded string
		*/
		__declspec(dllexport) BOOL ForensicalFromBase64(const char* src64, char* out);


	private:

	};	
}