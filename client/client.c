#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "client.h"
#include "server.h"
#include "common_constante.h"


#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16

static char PASSWORD[260] = "";

int uploadFile(const char* filename, int port);
int listFiles(int portServer, int port);
int downloadFile(const char* filename, int portServer, int port);
int renameServer(const char* oldName, const char* newName, int port);
int deleteOperation(const char* fileName, int port);
int logIn(const char* name, const char* password, int port);



/*
METHOD USE TO CRYPT/DECRYPT TEXT
*/
void handleErrors(void) {
    fprintf(stderr, "Erreur dans OpenSSL\n");
    exit(EXIT_FAILURE);
}

//Create key thanks to a password
void deriveKey(const char *password, unsigned char *key) {
    PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), NULL, 0, 10000, AES_KEY_SIZE, key);
}

//Method use to generate a 'iv' : use to avoid problem with conversion between char and unsigned char
void generateIV(unsigned char *iv) {
    if (RAND_bytes(iv, AES_IV_SIZE) != 1) {
        handleErrors();
    }
}

//Method use to encrypt a text
void encrypt(const char *plaintext, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];

    deriveKey(PASSWORD, key);
    generateIV(iv);

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int len;
    int ciphertext_len;

    EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char *)plaintext, strlen(plaintext));
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    memcpy(ciphertext + ciphertext_len, iv, AES_IV_SIZE);
    ciphertext_len += AES_IV_SIZE;

    EVP_CIPHER_CTX_free(ctx);
}

//Method use to decrypt a text
void decrypt(const unsigned char *ciphertext, char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];

    deriveKey(PASSWORD, key);

    // Extraire l'IV du texte chiffré
    memcpy(iv, ciphertext + strlen((char *)ciphertext) - AES_IV_SIZE, AES_IV_SIZE);

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int len;
    int plaintext_len;

    EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &len, ciphertext, strlen((char *)ciphertext) - AES_IV_SIZE);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}


//Method use to rename a file
int renameFile(const char* ancienNom, const char* nouveauNom) {
    if (rename(ancienNom, nouveauNom) == 0) {
        printf("The file have been rename succefully.\n");
        return 0; 
    } else {
        perror("Error while renaming the file");
        return -1;  
    }
}

//Method use to copy in memory the content of a target file
int copyFileToMemory(const char* filePath, char* fileContent, size_t* bytesRead) {
    FILE* file = fopen(filePath, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return -1;
    }

    *bytesRead = fread(fileContent, 1, MAX_FILE_SIZE, file);
    fclose(file);

    if (*bytesRead == 0) {
        perror("Error reading file");
        return -1;
    }

    return 0;
}


//Method use to write a content into a file
int writeToFile(const char* filePath, const char* fileContent, size_t fileSize) {
    FILE* file = fopen(filePath, "wb");
    if (file == NULL) {
        perror("Error opening file for writing");
        return -1;
    }

    size_t bytesWritten = fwrite(fileContent, 1, fileSize, file);
    fclose(file);

    if (bytesWritten != fileSize) {
        perror("Error writing to file");
        return -1;
    }

    return 0;
}


//Method use to generate the next available fileName in a folder 
//Use to avoid error/overwritting an existing file with the same name
//Generate up to 100 files with the same input name
//Generated this way : name(number)
int createUniqueFileName(const char* baseFileName, char* resultFileName) {
    int count = 0;
    int maxAttempts = 100; 

    do {
        if (count == 0) {
            snprintf(resultFileName, 256, "%s", baseFileName);
        } else {
            snprintf(resultFileName, 256, "%s(%d)", baseFileName, count);
        }

        FILE* testFile = fopen(resultFileName, "r");
        if (testFile == NULL) {
            break; 
        }

        fclose(testFile);

        count++;
    } while (count < maxAttempts);

    if (count == maxAttempts) {
        fprintf(stderr, "Error: Could not find a unique filename after %d attempts\n", maxAttempts);
        return -1;
    }

    return 0;
}


//MAIN
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_address> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int server_address = atoi(argv[1]);
    int port = atoi(argv[2]);
    char command[300];
    char filename[150];
    char filenameBis[150];

    while (1) {
        printf("Enter a command ('exit' to quit):\n");
        fgets(command, sizeof(command), stdin);
        command[strcspn(command, "\n")] = '\0';  
        if (strcmp(command, "exit") == 0) {
            printf("Exiting...\n");
            break;
        } else if (strncmp(command, "sectrans -up ", 13) == 0) {
            sscanf(command, "sectrans -up %s", filename);
            uploadFile(filename, server_address);
        } else if (strcmp(command, "sectrans -list") == 0) {
            listFiles(server_address, port);
        } else if (strncmp(command, "sectrans -down ", 15) == 0) {
            sscanf(command, "sectrans -down %s", filename);
            downloadFile(filename, server_address, port);
        } else if (strncmp(command, "sectrans -renamelocal ", 22) == 0) {
            sscanf(command, "sectrans -renamelocal %s %s", filename, filenameBis);
            renameFile(filename, filenameBis);
        } else if (strncmp(command, "sectrans -renameserver ", 23) == 0) {
            sscanf(command, "sectrans -renameserver %s %s", filename, filenameBis);
            renameServer(filename, filenameBis, server_address);
        } else if (strncmp(command, "sectrans -delete ", 17) == 0) {
            sscanf(command, "sectrans -delete %s", filename);
            deleteOperation(filename, server_address);
        } else if (strncmp(command, "sectrans -login ", 16) == 0) {
            sscanf(command, "sectrans -login %s %s", filename, filenameBis);
            logIn(filename, filenameBis, server_address);
        } else {
            printf("Invalid command. Please try again.\n");
        }
    }
    return 0;
}



//Method use to logIn 
int logIn(const char* name, const char* password, int port) {
    char fileContent[MAX_FILE_SIZE] = "";
    strcat(fileContent, LOG_IN);
    strcat(fileContent, name);
    strcat(fileContent, LOG_IN);
    strcat(fileContent, password);

    if (sndmsg(fileContent, port) != 0) {
        return EXIT_FAILURE;
    }
    strcpy(PASSWORD, password);
    return 0; 
}


//Method use to rename a file in the server
int renameServer(const char* oldName, const char* newName, int port) {
    char fileContent[MAX_FILE_SIZE] = "";
    strcat(fileContent, RENAME);
    strcat(fileContent, oldName);
    strcat(fileContent, RENAME);
    strcat(fileContent, newName);

    if (sndmsg(fileContent, port) != 0) {
        return EXIT_FAILURE;
    }
    return 0; 
}

//Method use to upload a file in the server
int uploadFile(const char* filename, int port) {
    const char* originalFilePath = filename;
    char fileContent[MAX_FILE_SIZE] = "";
    size_t bytesRead;
    if (copyFileToMemory(originalFilePath, fileContent, &bytesRead) == -1) {
        return EXIT_FAILURE;
    }

    unsigned char ciphertext[MAX_FILE_SIZE] = "";  
    encrypt(fileContent, ciphertext);

    if (sndmsg((char *)ciphertext, port) != 0) {
        return EXIT_FAILURE;
    }
    return 0; 
}

//Method use to get the list of the file in user server folder
int listFiles(int portServer, int port) {
    //Start a client-server to receive message from the server playing client role to send back file
    if (startserver(port) == -1) {
        fprintf(stderr, "Error starting the server\n");
        exit(EXIT_FAILURE);
    }
    char filenameInformation[MAX_FILE_SIZE] = "";
    char numberAsString[MAX_FILE_SIZE];
    sprintf(numberAsString, "%d", port);
    strcat(filenameInformation, LIST_FILE);
    strcat(filenameInformation, numberAsString);
    
    char msg_read[MAX_FILE_SIZE] = "";
    int firstLoop = 0;
    while (1) {
        if (firstLoop == 0) {
            if (sndmsg(filenameInformation, portServer) != 0) {
                return EXIT_FAILURE;
            }
            firstLoop = 1;
        }
        if (getmsg(msg_read) == -1) {
            fprintf(stderr, "Error receiving message from client\n");
            stopserver(); 
            exit(EXIT_FAILURE);
        }
        if (strlen(msg_read) > 0) {
            stopserver(); 
            break;
        }
    }
    char *token = strtok(msg_read, SEPARATOR_LIST);
    while (token != NULL) {
        if (strcmp(token,"1025") == 0) {
            printf("No file");
        } else {
            printf("%s\n", token);
        }
        token = strtok(NULL, SEPARATOR_LIST);
    }
    return 0; 
}


//Method use to download a file from the user server folder
int downloadFile(const char* filename, int portServer, int port) {
    //Start a client-server to receive message from the server playing client role to send back file
    if (startserver(port) == -1) {
        fprintf(stderr, "Error starting the server\n");
        exit(EXIT_FAILURE);
    }

    char filenameInformation[MAX_FILE_SIZE] = "";
    char numberAsString[MAX_FILE_SIZE] = "";
    sprintf(numberAsString, "%d", port);
    strcat(filenameInformation, GET_BACK_FILE);
    strcat(filenameInformation, filename);
    strcat(filenameInformation, GET_BACK_FILE);
    strcat(filenameInformation, numberAsString);
    if (sndmsg(filenameInformation, portServer) != 0) {
        return EXIT_FAILURE;
    }
    char msg_read[MAX_FILE_SIZE] = "";
    while (1) {
        if (getmsg(msg_read) == -1) {
            fprintf(stderr, "Error receiving message from client\n");
            stopserver(); 
            exit(EXIT_FAILURE);
        }
        if (strcmp(msg_read, "") != 0) {
            stopserver(); 
            break;
        }
        memset(msg_read, 0, sizeof(msg_read));
    }
    unsigned char unsignedText[256];
    strcpy((char*)unsignedText, msg_read);
    char decryptedtext[MAX_FILE_SIZE] = ""; 
    decrypt(unsignedText, decryptedtext);

    const char* baseFileName = "download_file";
    char uniqueFileName[256] = "";
    size_t bytesRead = strlen(decryptedtext);
    if (createUniqueFileName(baseFileName, uniqueFileName) == -1) {
        return EXIT_FAILURE;
    }
    if (writeToFile(uniqueFileName, decryptedtext, bytesRead) == -1) {
        return EXIT_FAILURE;
    }
    return 0;
}


//Method use to delete a file in the user server folder
int deleteOperation(const char* fileName, int port) {
    char filenameInformation[MAX_FILE_SIZE] = "";
    strcat(filenameInformation, DELETE);
    strcat(filenameInformation, fileName);
    if (sndmsg(filenameInformation, port) != 0) {
        return EXIT_FAILURE;
    }
    return 0;
}