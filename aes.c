#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <CommonCrypto/CommonCryptor.h>

static void aesEncrypt(void);
static void aesDecrypt(void);

int main (int argc, const char * argv[])
{
	if(argc < 2)
	{
		fprintf(stderr, "Usage: aes <e|d>\n");
		exit(1);
	}
	
	switch(tolower(argv[1][0]))
	{
		case 'e':
			aesEncrypt();
			break;
			
		case 'd':
			aesDecrypt();
			break;
			
		default:
			fprintf(stderr, "Invalid mode. Expected e or d\n");
			exit(1);
	}
	
    return 0;
}

static void aesOperation(CCOperation operation, void* key, size_t keySize, void* iv,
						  FILE *fpInput, FILE *fpOutput)
{
	CCCryptorRef cryptorRef;
	CCCryptorStatus rc;
/*
	CCCryptorCreate(CCOperation op, 
			CCAlgorithm alg, 
			CCOptions options,
         	const void *key, 
			size_t keyLength, 
			const void *iv,
         	CCCryptorRef *cryptorRef);
*/
	rc = CCCryptorCreate(operation, 
				kCCAlgorithmAES128, 
				0, 
				key, 
				keySize, 
				iv, 
				&cryptorRef);
	assert(rc == kCCSuccess);
	
	char rawData[128/8];
	size_t bytesRead;
	while((bytesRead = fread(rawData, 1, sizeof(rawData), fpInput)) > 0)
	{
		char convertedData[128/8];
		size_t dataOutMoved;
		
		if(bytesRead < sizeof(rawData))
			bzero(&rawData[bytesRead], sizeof(rawData) - bytesRead);
		
		/*
		CCCryptorUpdate(CCCryptorRef cryptorRef, 
				const void *dataIn,
			        size_t dataInLength, 
				void *dataOut, 
				size_t dataOutAvailable,
         			size_t *dataOutMoved);
		*/
		rc = CCCryptorUpdate(cryptorRef, 
					rawData, 
					sizeof(rawData), 
					convertedData, 
					sizeof(convertedData), 
					&dataOutMoved);
		assert(rc == kCCSuccess);
		//assert(dataOutMoved == sizeof(convertedData));
		if(dataOutMoved != sizeof(convertedData))
			printf("Data out moved (%zu) != converted (%s)\n", dataOutMoved, convertedData);
		
		if(dataOutMoved > 0)
			fwrite(convertedData, dataOutMoved, 1, fpOutput);
	}
	
	CCCryptorRelease(cryptorRef);
}

static void aesEncrypt(void)
{
	// Get the key from a file if the file exists, otherwise
	// generate a random key from /dev/null and save to the file
	char key[256/8];
	FILE *fpKeyFile;
	if ((fpKeyFile = fopen("aes.key", "rb"))) {
		fread(key, sizeof(key), 1, fpKeyFile);
		fclose(fpKeyFile);
	} else {
		int fdRandom = open("/dev/random", O_RDONLY);
		int status = read(fdRandom, key, sizeof(key));
		if(status != sizeof(key))
		{
			fprintf(stderr, "Could not read random key. %s\n", strerror(errno));
			exit(1);
		}
		close(fdRandom);
	
		FILE *fpKeyFile = fopen("aes.key", "wb");
		fwrite(key, sizeof(key), 1, fpKeyFile);
		fclose(fpKeyFile);
	}
	
	
	// Open the file where we'll write the ciphertext
	FILE *fpEncryptedFile = fopen("aesEncryptedFile", "w");
	
	// Use an IV if there is a file containing one, otherwise
	// Pass in NULL for the IV
	// Take plaintext from stdin, encrypt to ciphertext, put in the file and close it
	char iv[256/8];
	FILE *fpIvFile;
	if ((fpIvFile = fopen("aes.iv", "rb"))) {
		fread(iv, sizeof(iv), 1, fpIvFile);
		fclose(fpIvFile);
		aesOperation(kCCEncrypt, key, sizeof(key), iv, stdin, fpEncryptedFile);
		fclose(fpEncryptedFile);
	} else {
		aesOperation(kCCEncrypt, key, sizeof(key), NULL, stdin, fpEncryptedFile);
		fclose(fpEncryptedFile);
	}
}

static void aesDecrypt(void)
{
	// Read the key in from a file
	FILE *fpKeyFile = fopen("aes.key", "rb");
	char key[256/8];
	fread(key, sizeof(key), 1, fpKeyFile);
	fclose(fpKeyFile);

	// Open the file containing the ciphertext
	FILE *fpEncryptedFile = fopen("aesEncryptedFile", "r");
	
	// Use an IV if there is a file containing one, otherwise
	// Pass in NULL for the IV
	// Pass the plaintext to stdout
	char iv[256/8];
	FILE *fpIvFile;
	if ((fpIvFile = fopen("aes.iv", "rb"))) {
		fread(iv, sizeof(iv), 1, fpIvFile);
		fclose(fpIvFile);
		aesOperation(kCCDecrypt, key, sizeof(key), iv, fpEncryptedFile, stdout);
		fclose(fpEncryptedFile);
	} else {
		aesOperation(kCCDecrypt, key, sizeof(key), NULL, fpEncryptedFile, stdout);
		fclose(fpEncryptedFile);
	}
}

