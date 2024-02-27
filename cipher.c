#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>


/*CABRERA VAZQUEZ ITZEL BERENICE

gcc cipher.c -o cipher -lssl -lcrypto 
-lssl -lcrypto provee de funciones criptográficas de openssl 

./cipher "llave" "/home/itzeeel_cava/Cipher/plaintext.txt"

*/
void handleErrors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext){
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void digest_message(const unsigned char *message, size_t message_len, unsigned char *digest, unsigned int *digest_len){
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_new()) == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors();

	if((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		handleErrors();

	if(1 != EVP_DigestFinal_ex(mdctx, digest, digest_len))
		handleErrors();

	EVP_MD_CTX_free(mdctx);
}

int main (int argc, char *argv[]){
    if (argc != 3) {
        printf("Falta ingresar la llave secreta");
        return 1;
    }

    char *cadena = argv[1]; //obtiene la llave secreta proporcionada por el usuario 
    char *filePath = argv[2]; //obtiene la llave secreta proporcionada por el usuario 

    unsigned int l_key = 32; //32 bytes
    unsigned char key[l_key]; // Array para almacenar la llave convertida de 32 bytes

    digest_message(cadena,sizeof(cadena) , key, &l_key); //hashea la llave secreta a un hash value de 256 bits

    /* Hard code del IV (128 bits) */
    unsigned char iv[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                       0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
                     };

    /* Mensaje a tratar*/
    FILE *file;
    unsigned char *content = NULL; // Pointer to store the file content
    long length; // Length of the file

    // Open the file in read mode
    file = fopen(filePath, "rb");
    if (file == NULL) {
        printf("Error opening the file.\n");
        return 1;
    }

    // Get the file length
    fseek(file, 0, SEEK_END);
    length = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the content
    content = (char *)malloc(length * sizeof(char));
    if (content == NULL) {
        printf("Error allocating memory.\n");
        fclose(file);
        return 1;
    }

    // Read the file content into the array
    fread(content, sizeof(char), length, file);

    // Close the file
    fclose(file);
    
    // Print the content
    printf("File content:\n%s\n", content);
    
    /*
     * Buffer para el texto cifrado. Asegrar que el buffer es suficientemente largo
      para el texto cifrado, este puede ser más largo que el texto plano, dependiendo
      del algoritmo y del modo.
     */
    unsigned char ciphertext[128];

    /* Buffer para el texto decifrado */
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

    /* Encriptación*/
    ciphertext_len = encrypt (content, strlen ((char *)content), key, iv,
                              ciphertext);

    /*BIO_dump_fp es parte de la biblioteca OpenSSL, y se utiliza 
    para imprimir datos binarios en formato hexadecimal en una salida dada */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    /*Decriptación*/
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                decryptedtext);

    /*Añade el término NULL al texto decriptado*/
    decryptedtext[decryptedtext_len] = '\0';

    /* Imprime el texto decriptado*/
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

    // Free the memory allocated for the content
    free(content);
    return 0;
}
