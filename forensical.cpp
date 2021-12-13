#include "forensical.h"
#include <cstdio>
#include <cstdlib>
#include <wincrypt.h>

#pragma warning(disable: 4996)
#pragma comment(lib, "Crypt32.lib")

/*
	Copyright 2021. Eduardo Programador
	www.eduardoprogramador.com
	All rights reserved
	Contact him at:
	E-mail: consultoria@eduardoprogramador.com
	WhatsApp: +55 81 98860 0704
	Instagram: @eduardo_programador

	This is a C++ source file
	that contains the implementations of the functions declared
	in Forensical class.

*/

/*
	This namespace contains some projects
	developed by Eduardo Programador.
*/
namespace EduardoProgramador
{
	/* Implementations */

	Forensical::Forensical() {}
	
	Forensical::~Forensical() {}

	BOOL Forensical::ForensicalCreateKey(unsigned int HASH_TYPE, const char* passphrase, unsigned int KEY_TYPE, FORENSICAL_KEY* fKey)
	{
		HCRYPTPROV hProv;
		HCRYPTHASH hHash;
		HCRYPTKEY hKey, hPublicKey;
		DWORD dwHashSize = sizeof(DWORD), dwData = sizeof(DWORD), dwKeyLen = sizeof(DWORD);
		ALG_ID algId, algKey;
		BYTE* pbKey;

		switch (HASH_TYPE)
		{

		case HASH_MD5:
			algId = CALG_MD5;
			break;

		case HASH_SHA:
			algId = CALG_SHA1;
			break;

		case HASH_SHA256:
			algId = CALG_SHA_256;
			break;

		case HASH_SHA512:
			algId = CALG_SHA_512;
			break;

		default:
			return FALSE;
		}

		if (HASH_TYPE == HASH_SHA256 || HASH_TYPE == HASH_SHA512)
		{
			if (!CryptAcquireContext(&hProv, 0, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
				return FALSE;

		}
		else
		{
			if (!CryptAcquireContext(&hProv, 0, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
				return FALSE;
		}

		if (!CryptCreateHash(hProv, algId, 0, 0, &hHash))
			return FALSE;

		if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&dwHashSize, &dwData, 0))
			return FALSE;

		BYTE* pbPassphrase = (BYTE*)passphrase;
		if (!CryptHashData(hHash, pbPassphrase, strlen(passphrase), 0))
			return FALSE;



		switch (KEY_TYPE)
		{

		case KEY_RC2_40:
			algKey = CALG_RC2;
			dwKeyLen = 40;
			break;

		case KEY_RC4_40:
			algKey = CALG_RC4;
			dwKeyLen = 40;
			break;

		case KEY_DES_56:
			algKey = CALG_DES;
			dwKeyLen = 56;
			break;

		case KEY_2DES_112:
			algKey = CALG_3DES_112;
			dwKeyLen = 112;
			break;

		case KEY_3DES_168:
			algKey = CALG_3DES;
			dwKeyLen = 168;
			break;

		case KEY_AES_128:
			algKey = CALG_AES_128;
			dwKeyLen = 128;
			break;

		case KEY_AES_192:
			algKey = CALG_AES_192;
			dwKeyLen = 192;
			break;

		case KEY_AES_256:
			algKey = CALG_AES_256;
			dwKeyLen = 256;
			break;

		default:
			return FALSE;

		}

		if (!CryptDeriveKey(hProv, algKey, hHash, (dwKeyLen << 16) & 0xFFFF0000 | CRYPT_EXPORTABLE, &hKey))
			return FALSE;

		CryptDestroyHash(hHash);

		if (!CryptGenKey(hProv, AT_KEYEXCHANGE, (2048 << 16), &hPublicKey))
			return FALSE;

		dwKeyLen = sizeof(DWORD);
		dwData = sizeof(DWORD);

		if (!CryptExportKey(hKey, hPublicKey, SIMPLEBLOB, 0, 0, &dwData))
			return FALSE;

		pbKey = new BYTE[dwData];

		if (!CryptExportKey(hKey, hPublicKey, SIMPLEBLOB, 0, pbKey, &dwData))
			return FALSE;


		BYTE* pbKeyData = pbKey + sizeof(BLOBHEADER) + sizeof(ALG_ID);
		dwData -= (sizeof(BLOBHEADER) + sizeof(ALG_ID));

		if (!CryptDecrypt(hPublicKey, 0, TRUE, 0, pbKeyData, &dwData))
			return FALSE;

		CryptDestroyKey(hKey);
		CryptDestroyKey(hPublicKey);
		CryptReleaseContext(hProv, 0);

		fKey->dwKeySize = dwData;
		fKey->pbKey = pbKeyData;
		fKey->algId = algKey;

		return TRUE;

	}

	BOOL Forensical::ForensicalCreateKey(unsigned int KEY_TYPE, FORENSICAL_KEY* fKey)
	{
		HCRYPTPROV hProv;
		HCRYPTKEY hKey, hPublicKey;
		DWORD dwKeyLen, dwData = sizeof(DWORD);
		ALG_ID algId;

		switch (KEY_TYPE)
		{

		case KEY_RC2_40:
			algId = CALG_RC2;
			dwKeyLen = 40;
			break;

		case KEY_RC4_40:
			algId = CALG_RC4;
			dwKeyLen = 40;
			break;

		case KEY_DES_56:
			algId = CALG_DES;
			dwKeyLen = 56;
			break;

		case KEY_2DES_112:
			algId = CALG_3DES_112;
			dwKeyLen = 112;
			break;

		case KEY_3DES_168:
			algId = CALG_3DES;
			dwKeyLen = 168;
			break;

		case KEY_AES_128:
			algId = CALG_AES_128;
			dwKeyLen = 128;
			break;

		case KEY_AES_192:
			algId = CALG_AES_192;
			dwKeyLen = 192;
			break;

		case KEY_AES_256:
			algId = CALG_AES_256;
			dwKeyLen = 256;
			break;

		default:
			return FALSE;
		}

		if (KEY_TYPE == KEY_AES_128 || KEY_TYPE == KEY_AES_192 || KEY_TYPE == KEY_AES_256)
		{
			if (!CryptAcquireContext(&hProv, 0, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
				return FALSE;
		}
		else
		{
			if (!CryptAcquireContext(&hProv, 0, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
				return FALSE;
		}


		if (!CryptGenKey(hProv, algId, (dwKeyLen << 16) & 0xFFFF0000 | CRYPT_EXPORTABLE, &hKey))
			return FALSE;

		if (!CryptGenKey(hProv, AT_KEYEXCHANGE, (2048 << 16), &hPublicKey))
			return FALSE;


		if (!CryptExportKey(hKey, hPublicKey, SIMPLEBLOB, 0, 0, &dwData))
			return FALSE;


		BYTE* pbData = new BYTE[dwData];

		if (!CryptExportKey(hKey, hPublicKey, SIMPLEBLOB, 0, pbData, &dwData))
			return FALSE;


		BYTE* pbKey = (pbData + sizeof(BLOBHEADER) + sizeof(ALG_ID));
		dwData -= (sizeof(BLOBHEADER) + sizeof(ALG_ID));


		if (!CryptDecrypt(hPublicKey, 0, TRUE, 0, pbKey, &dwData))
			return FALSE;

		CryptDestroyKey(hKey);
		CryptDestroyKey(hPublicKey);
		CryptReleaseContext(hProv, 0);

		fKey->algId = algId;
		fKey->dwKeySize = dwData;
		fKey->pbKey = pbKey;

		return TRUE;

	}

	BOOL Forensical::ForensicalWriteKeyToFile(FORENSICAL_KEY* fKey, const char* szPath)
	{		
		HANDLE hFile;

		if ((hFile = CreateFile(szPath, GENERIC_WRITE, FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)) == NULL)
			return FALSE;

		if (!WriteFile(hFile, fKey->pbKey, fKey->dwKeySize, 0, 0))
			return FALSE;

		CloseHandle(hFile);

		return TRUE;

	}

	BOOL Forensical::ForensicalGetKeyFromFile(FORENSICAL_KEY* fKey, const char* szPath, unsigned int KEY_TYPE)
	{		
		HANDLE hFile;
		BYTE* pbFromFile;
	
		if ((hFile = CreateFile(szPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)) == NULL)
			return FALSE;

		DWORD dwToRead = 32;
		pbFromFile = new BYTE[dwToRead];
		DWORD dwKeySize = 0;
		if (!ReadFile(hFile, pbFromFile, dwToRead, &dwKeySize, 0))
			return FALSE;

		CloseHandle(hFile);		

		ALG_ID alg = 0;
		switch (KEY_TYPE)
		{

		case KEY_RC2_40:
			alg = CALG_RC2;
			break;

		case KEY_RC4_40:
			alg = CALG_RC4;
			break;

		case KEY_DES_56:
			alg = CALG_DES;
			break;

		case KEY_2DES_112:
			alg = CALG_3DES_112;
			break;

		case KEY_3DES_168:
			alg = CALG_3DES;
			break;

		case KEY_AES_128:
			alg = CALG_AES_128;
			break;

		case KEY_AES_192:
			alg = CALG_AES_192;
			break;

		case KEY_AES_256:
			alg = CALG_AES_256;
			break;

		default:
			break;
		}

		fKey->algId = alg;
		fKey->dwKeySize = dwKeySize;
		fKey->pbKey = pbFromFile;

		return TRUE;


	}

	BOOL Forensical::ForensicalEncrypt(FORENSICAL_KEY* fKey, const char* szDataSrc, FORENSICAL_DATA* fData)
	{		
		HCRYPTPROV hProv;
		HCRYPTKEY hKey, hPubKey;
	
		if (fKey->algId == CALG_AES_128 || fKey->algId == CALG_AES_192 || fKey->algId == CALG_AES_256)
		{
			if (!CryptAcquireContext(&hProv, 0, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
				return FALSE;
		}
		else
		{
			if (!CryptAcquireContext(&hProv, 0, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
				return FALSE;
		}
		
		if (!CryptGenKey(hProv, AT_KEYEXCHANGE, (2048 << 16), &hPubKey))
			return FALSE;

		DWORD dwDataLen = sizeof(DWORD);
		DWORD dwHeaderLen = sizeof(BLOBHEADER) + sizeof(ALG_ID);
		DWORD dwKeyLen = fKey->dwKeySize;
		if (!CryptEncrypt(hPubKey, 0, TRUE, 0, 0, &dwDataLen, dwDataLen))
			return FALSE;

		BYTE* pbKeyData = new BYTE[dwDataLen + dwHeaderLen];
		CopyMemory(pbKeyData + dwHeaderLen, fKey->pbKey, fKey->dwKeySize);
		if (!CryptEncrypt(hPubKey, 0, TRUE, 0, pbKeyData + dwHeaderLen, &dwKeyLen, dwDataLen))
			return FALSE;

		BLOBHEADER* pBlob = (BLOBHEADER*)pbKeyData;
		ALG_ID* pAlgId = (ALG_ID*)(pbKeyData + sizeof(BLOBHEADER));
		pBlob->aiKeyAlg = fKey->algId;
		pBlob->bType = SIMPLEBLOB;
		pBlob->bVersion = 2;
		pBlob->reserved = 0;
		DWORD dwAlgLen = sizeof(ALG_ID);

		if (!CryptGetKeyParam(hPubKey, KP_ALGID, (BYTE*)pAlgId, &dwAlgLen, 0))
			return FALSE;

		if (!CryptImportKey(hProv, pbKeyData, dwDataLen + dwHeaderLen, hPubKey, 0, &hKey))
			return FALSE;

		CryptDestroyKey(hPubKey);


		DWORD dwEncLen = strlen(szDataSrc);
		DWORD dwBufLen = sizeof(DWORD);

		if (!CryptEncrypt(hKey, 0, TRUE, 0, 0, &dwBufLen, dwBufLen))
			return FALSE;

		dwBufLen += dwEncLen;
		BYTE* pbDataSrc = new BYTE[dwEncLen];
		char* szDataSrc2 = new CHAR[dwEncLen];
		strcpy(szDataSrc2, szDataSrc);
		pbDataSrc = (BYTE*)szDataSrc2;

		DWORD dwOrigin = dwEncLen;

		if (!CryptEncrypt(hKey, 0, TRUE, 0, pbDataSrc, &dwEncLen, dwBufLen))
			return FALSE;

		fData->bIsEncrypted = TRUE;
		fData->dwOutputLen = dwEncLen;
		fData->dwSrcLen = dwOrigin;
		fData->pbData = pbDataSrc;

		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);

		return TRUE;

	}

	BOOL Forensical::ForensicalEncrypt(FORENSICAL_KEY* fKey, const char* szFileIn, const char* szFileOut)
	{
		
		HCRYPTPROV hProv;
		HCRYPTKEY hKey, hPubKey;
		HANDLE hFile;
		
		if ((hFile = CreateFile(szFileIn, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)) == NULL)
			return FALSE;

		DWORD dwFileSize = 0;
		LARGE_INTEGER li;
		ZeroMemory(&li, sizeof(LARGE_INTEGER));
		if (!GetFileSizeEx(hFile, &li))
			return FALSE;

		dwFileSize = li.QuadPart;
		BYTE* pbFile = new BYTE[dwFileSize];
		DWORD dwReadLen = 0;

		if (!ReadFile(hFile, pbFile, dwFileSize, &dwReadLen, 0))
			return FALSE;

		CloseHandle(hFile);


		if (fKey->algId == CALG_AES_128 || fKey->algId == CALG_AES_192 || fKey->algId == CALG_AES_256)
		{
			if (!CryptAcquireContext(&hProv, 0, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
				return FALSE;
		}
		else
		{
			if (!CryptAcquireContext(&hProv, 0, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
				return FALSE;
		}
		
		if (!CryptGenKey(hProv, AT_KEYEXCHANGE, (2048 << 16), &hPubKey))
			return FALSE;

		DWORD dwDataLen = sizeof(DWORD);
		DWORD dwHeaderLen = sizeof(BLOBHEADER) + sizeof(ALG_ID);
		DWORD dwKeyLen = fKey->dwKeySize;
		if (!CryptEncrypt(hPubKey, 0, TRUE, 0, 0, &dwDataLen, dwDataLen))
			return FALSE;

		BYTE* pbKeyData = new BYTE[dwDataLen + dwHeaderLen];
		CopyMemory(pbKeyData + dwHeaderLen, fKey->pbKey, fKey->dwKeySize);
		if (!CryptEncrypt(hPubKey, 0, TRUE, 0, pbKeyData + dwHeaderLen, &dwKeyLen, dwDataLen))
			return FALSE;

		BLOBHEADER* pBlob = (BLOBHEADER*)pbKeyData;
		ALG_ID* pAlgId = (ALG_ID*)(pbKeyData + sizeof(BLOBHEADER));
		pBlob->aiKeyAlg = fKey->algId;
		pBlob->bType = SIMPLEBLOB;
		pBlob->bVersion = 2;
		pBlob->reserved = 0;
		DWORD dwAlgLen = sizeof(ALG_ID);

		if (!CryptGetKeyParam(hPubKey, KP_ALGID, (BYTE*)pAlgId, &dwAlgLen, 0))
			return FALSE;

		if (!CryptImportKey(hProv, pbKeyData, dwDataLen + dwHeaderLen, hPubKey, 0, &hKey))
			return FALSE;

		CryptDestroyKey(hPubKey);


		DWORD dwEncLen = dwFileSize;
		DWORD dwBufLen = sizeof(DWORD);

		if (!CryptEncrypt(hKey, 0, TRUE, 0, 0, &dwBufLen, dwBufLen))
			return FALSE;

		dwBufLen += dwEncLen;
		BYTE* pbDataSrc = new BYTE[dwEncLen];
		pbDataSrc = pbFile;

		DWORD dwOrigin = dwEncLen;

		if (!CryptEncrypt(hKey, 0, TRUE, 0, pbDataSrc, &dwEncLen, dwBufLen))
			return FALSE;

		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);

		HANDLE hFileOut;
		if ((hFileOut = CreateFile(szFileOut, GENERIC_WRITE, FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)) == NULL)
			return FALSE;

		if (!WriteFile(hFileOut, pbDataSrc, dwEncLen, 0, 0))
			return FALSE;

		CloseHandle(hFileOut);

		return TRUE;

	}

	BOOL Forensical::ForensicalDecrypt(FORENSICAL_KEY* fKey, FORENSICAL_DATA* fDataInput, FORENSICAL_DATA* fDataOutput)
	{
		HCRYPTPROV hProv;
		HCRYPTKEY hKey, hPubKey;

		if (fKey->algId == CALG_AES_128 || fKey->algId == CALG_AES_192 || fKey->algId == CALG_AES_256)
		{
			if (!CryptAcquireContext(&hProv, 0, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
				return FALSE;
		}
		else
		{
			if (!CryptAcquireContext(&hProv, 0, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
				return FALSE;
		}

		if (!CryptGenKey(hProv, AT_KEYEXCHANGE, (2048 << 16), &hPubKey))
			return FALSE;

		DWORD dwDataLen = sizeof(DWORD);
		DWORD dwHeaderLen = sizeof(BLOBHEADER) + sizeof(ALG_ID);
		DWORD dwKeyLen = fKey->dwKeySize;
		if (!CryptEncrypt(hPubKey, 0, TRUE, 0, 0, &dwDataLen, dwDataLen))
			return FALSE;

		BYTE* pbKeyData = new BYTE[dwHeaderLen + dwDataLen];
		CopyMemory(pbKeyData + dwHeaderLen, fKey->pbKey, dwKeyLen);
		if (!CryptEncrypt(hPubKey, 0, TRUE, 0, pbKeyData + dwHeaderLen, &dwKeyLen, dwDataLen))
			return FALSE;

		BLOBHEADER* pBlob = (BLOBHEADER*)pbKeyData;
		ALG_ID* pAlgId = (ALG_ID*)(pbKeyData + sizeof(BLOBHEADER));
		pBlob->aiKeyAlg = fKey->algId;
		pBlob->bType = SIMPLEBLOB;
		pBlob->bVersion = 2;
		pBlob->reserved = 0;
		DWORD dwAlgLen = sizeof(ALG_ID);

		if (!CryptGetKeyParam(hPubKey, KP_ALGID, (BYTE*)pAlgId, &dwAlgLen, 0))
			return FALSE;

		if (!CryptImportKey(hProv, pbKeyData, dwDataLen + dwKeyLen, hPubKey, 0, &hKey))
			return FALSE;

		CryptDestroyKey(hPubKey);

		BYTE* pbToDecrypt = fDataInput->pbData;
		DWORD dwEncryptedLen = fDataInput->dwOutputLen;
		if (!CryptDecrypt(hKey, 0, TRUE, 0, pbToDecrypt, &dwEncryptedLen))
			return FALSE;

		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);

		char temp[50] = { 0 };
		char* szFinal = new CHAR[fDataInput->dwSrcLen];
		strcpy(szFinal, "");
		for (DWORD i = 0; i < fDataInput->dwSrcLen; i++)
		{
			sprintf(temp, "%c", pbToDecrypt[i]);
			strcat(szFinal, temp);
		}

		BYTE* pbFinal = (BYTE*)szFinal;

		fDataOutput->bIsEncrypted = FALSE;
		fDataOutput->dwOutputLen = fDataInput->dwSrcLen;
		fDataOutput->dwSrcLen = fDataInput->dwOutputLen;
		fDataOutput->pbData = pbFinal;

		return TRUE;

	}

	BOOL Forensical::ForensicalDecrypt(FORENSICAL_KEY* fKey, const char* szFileEncrypted, const char* szFileToDecrypt)
	{
		HCRYPTPROV hProv;
		HCRYPTKEY hKey, hPubKey;
		HANDLE hFile;

		if ((hFile = CreateFile(szFileEncrypted, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)) == NULL)
			return FALSE;

		LARGE_INTEGER li;
		DWORD dwFileSize = 0, dwReadLen = 0;
		memset(&li, 0, sizeof(LARGE_INTEGER));

		if (!GetFileSizeEx(hFile, &li))
			return FALSE;

		dwFileSize = li.QuadPart;
		DWORD dwSrcLen = dwFileSize;
		BYTE* pbFile = new BYTE[dwFileSize];
		if (!ReadFile(hFile, pbFile, dwFileSize, &dwReadLen, 0))
			return FALSE;

		CloseHandle(hFile);


		if (fKey->algId == CALG_AES_128 || fKey->algId == CALG_AES_192 || fKey->algId == CALG_AES_256)
		{
			if (!CryptAcquireContext(&hProv, 0, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
				return FALSE;
		}
		else
		{
			if (!CryptAcquireContext(&hProv, 0, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
				return FALSE;
		}

		if (!CryptGenKey(hProv, AT_KEYEXCHANGE, (2048 << 16), &hPubKey))
			return FALSE;

		DWORD dwDataLen = sizeof(DWORD);
		DWORD dwHeaderLen = sizeof(BLOBHEADER) + sizeof(ALG_ID);
		DWORD dwKeyLen = fKey->dwKeySize;
		if (!CryptEncrypt(hPubKey, 0, TRUE, 0, 0, &dwDataLen, dwDataLen))
			return FALSE;

		BYTE* pbKeyData = new BYTE[dwHeaderLen + dwDataLen];
		CopyMemory(pbKeyData + dwHeaderLen, fKey->pbKey, dwKeyLen);
		if (!CryptEncrypt(hPubKey, 0, TRUE, 0, pbKeyData + dwHeaderLen, &dwKeyLen, dwDataLen))
			return FALSE;

		BLOBHEADER* pBlob = (BLOBHEADER*)pbKeyData;
		ALG_ID* pAlgId = (ALG_ID*)(pbKeyData + sizeof(BLOBHEADER));
		pBlob->aiKeyAlg = fKey->algId;
		pBlob->bType = SIMPLEBLOB;
		pBlob->bVersion = 2;
		pBlob->reserved = 0;
		DWORD dwAlgLen = sizeof(ALG_ID);

		if (!CryptGetKeyParam(hPubKey, KP_ALGID, (BYTE*)pAlgId, &dwAlgLen, 0))
			return FALSE;

		if (!CryptImportKey(hProv, pbKeyData, dwDataLen + dwKeyLen, hPubKey, 0, &hKey))
			return FALSE;

		CryptDestroyKey(hPubKey);

		DWORD dwEncryptedLen = dwFileSize;
		if (!CryptDecrypt(hKey, 0, TRUE, 0, pbFile, &dwEncryptedLen))
			return FALSE;

		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);		


		HANDLE hFileOut;
		if ((hFileOut = CreateFile(szFileToDecrypt, GENERIC_WRITE, FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)) == NULL)
			return FALSE;

		if (!WriteFile(hFileOut, pbFile, dwEncryptedLen, 0, 0))
			return FALSE;

		return TRUE;

	}

	BOOL Forensical::ForensicalGetHash(unsigned int HASH_TYPE, const char* str, FORENSICAL_HASH* fh)
	{
		HCRYPTPROV hProv;
		HCRYPTHASH hHash;
		BYTE* pbStr, * pbHash;
		DWORD dwHashSize = sizeof(DWORD), dwData = sizeof(DWORD);
		ALG_ID algId;

		switch (HASH_TYPE)
		{
		case HASH_MD2:
			algId = CALG_MD2;
			break;

		case HASH_MD5:
			algId = CALG_MD5;
			break;

		case HASH_SHA:
			algId = CALG_SHA1;
			break;

		case HASH_SHA256:
			algId = CALG_SHA_256;
			break;

		case HASH_SHA512:
			algId = CALG_SHA_512;
			break;

		default:
			return FALSE;
			break;

		}

		if (HASH_TYPE == HASH_SHA256 || HASH_TYPE == HASH_SHA512)
		{

			if (!CryptAcquireContext(&hProv, 0, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
				return FALSE;

		}
		else
		{

			if (!CryptAcquireContext(&hProv, 0, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
				return FALSE;

		}

		if (!CryptCreateHash(hProv, algId, 0, 0, &hHash))
			return FALSE;

		if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&dwHashSize, &dwData, 0))
			return FALSE;


		pbHash = new BYTE[dwHashSize];
		if (!pbHash)
			return FALSE;

		pbStr = (BYTE*)str;
		if (!CryptHashData(hHash, pbStr, strlen(str), 0))
			return FALSE;

		if (!CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &dwHashSize, 0))
			return FALSE;


		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);

		char* szHash = (char*)LocalAlloc(LMEM_FIXED, 512);
		char szTemp[50] = { 0 };
		strcpy(szHash, "");

		for (DWORD i = 0; i < dwHashSize; i++)
		{
			sprintf(szTemp, "%02x", pbHash[i]);
			strcat(szHash, szTemp);
		}

		delete[]pbHash;

		fh->dwHashSize = dwHashSize;
		fh->szHashData = szHash;

		return TRUE;
	}

	BOOL Forensical::ForensicalGetMac(unsigned int HMAC_TYPE, FORENSICAL_KEY* fKey, const char* str, FORENSICAL_HMAC* fHmac)
	{
		HCRYPTPROV hProv;
		HCRYPTHASH hHash;
		HMAC_INFO hMacInfo;
		ALG_ID algId;
		BYTE* pbMac;
		DWORD dwData = sizeof(DWORD), dwMacSize = sizeof(DWORD);


		switch (HMAC_TYPE)
		{

		case HMAC_SHA:
			algId = CALG_SHA1;
			break;

		case HMAC_MD5:
			algId = CALG_MD5;
			break;

		case HMAC_SHA256:
			algId = CALG_SHA_256;
			break;

		case HMAC_SHA512:
			algId = CALG_SHA_512;
			break;

		default:

			return FALSE;

		}


		if (HMAC_TYPE == HMAC_SHA256 || HMAC_TYPE == HMAC_SHA512)
		{
			if (!CryptAcquireContext(&hProv, 0, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
				return FALSE;
		}
		else
		{
			if (!CryptAcquireContext(&hProv, 0, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
				return FALSE;
		}


		BYTE* pbKey = fKey->pbKey;
		DWORD dwKeyLen = fKey->dwKeySize;
		DWORD dwHeaderLen = sizeof(BLOBHEADER) + sizeof(ALG_ID);
		dwData = sizeof(DWORD);
		ALG_ID* pAlgId;
		BLOBHEADER* pBlob;
		HCRYPTKEY hKey, hPublicKey;

		if (!CryptGenKey(hProv, AT_KEYEXCHANGE, (2048 << 16), &hPublicKey))
			return FALSE;


		if (!CryptEncrypt(hPublicKey, 0, TRUE, 0, 0, &dwData, dwData))
			return FALSE;

		BYTE* pbData = new BYTE[dwData + dwHeaderLen];

		CopyMemory(pbData + dwHeaderLen, pbKey, fKey->dwKeySize);


		if (!CryptEncrypt(hPublicKey, 0, TRUE, 0, pbData + dwHeaderLen, &dwKeyLen, dwData))
			return FALSE;

		pBlob = (BLOBHEADER*)pbData;
		pAlgId = (ALG_ID*)(pbData + sizeof(BLOBHEADER));
		pBlob->bType = SIMPLEBLOB;
		pBlob->bVersion = 2;
		pBlob->reserved = 0;
		pBlob->aiKeyAlg = fKey->algId;

		DWORD dwAlg = sizeof(ALG_ID);
		if (!CryptGetKeyParam(hPublicKey, KP_ALGID, (BYTE*)pAlgId, &dwAlg, 0))
			return FALSE;

		if (!CryptImportKey(hProv, pbData, dwData + dwHeaderLen, hPublicKey, 0, &hKey))
			return FALSE;


		if (!CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHash))
			return FALSE;

		memset(&hMacInfo, 0, sizeof(HMAC_INFO));
		hMacInfo.cbInnerString = 0;
		hMacInfo.pbInnerString = 0;
		hMacInfo.HashAlgid = algId;
		if (!CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&hMacInfo, 0))
			return FALSE;



		dwData = sizeof(DWORD);
		if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&dwMacSize, &dwData, 0))
			return FALSE;

		BYTE* pbStr = (PBYTE)str;
		if (!CryptHashData(hHash, pbStr, strlen(str), 0))
			return FALSE;

		pbMac = new BYTE[dwMacSize];
		if (!CryptGetHashParam(hHash, HP_HASHVAL, pbMac, &dwMacSize, 0))
			return FALSE;

		CryptDestroyKey(hKey);
		CryptDestroyKey(hPublicKey);

		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);



		char temp[50] = { 0 };
		char* szMac = (char*)LocalAlloc(LMEM_FIXED, 512);
		strcpy(szMac, "");

		for (DWORD i = 0; i < dwMacSize; i++)
		{
			sprintf(temp, "%02x", pbMac[i]);
			strcat(szMac, temp);
		}

		delete[]pbMac;

		fHmac->dwHashSize = dwMacSize;
		fHmac->szHashData = szMac;



		return TRUE;

	}

	BOOL Forensical::ForensicalToBase64(const char* srcStr, char *out)
	{

		DWORD dwSize = 0;

		if (CryptBinaryToString((BYTE*)srcStr, strlen(srcStr), CRYPT_STRING_BASE64, NULL, &dwSize))
		{

			char* converted = new CHAR[dwSize];

			if (CryptBinaryToString((BYTE*)srcStr, strlen(srcStr), CRYPT_STRING_BASE64, converted, &dwSize))
			{
				strcpy(out, converted);
				return TRUE;
			}
			else
			{
				return FALSE;
			}

		}
		else
		{
			return FALSE;
		}
	}

	BOOL Forensical::ForensicalFromBase64(const char* src64, char *out)
	{
		DWORD dwSize = 0;		


		if (CryptStringToBinary(src64, strlen(src64), CRYPT_STRING_BASE64, NULL, &dwSize, 0, NULL))
		{

			char *converted = new CHAR[512];


			if (CryptStringToBinary(src64, strlen(src64), CRYPT_STRING_BASE64, (BYTE*)converted, &dwSize, 0, NULL))
			{
				strcpy(out, converted);
				return TRUE;
			}
			else
			{
				return FALSE;
			}
		}
		else
		{
			return FALSE;
		}
	}

}