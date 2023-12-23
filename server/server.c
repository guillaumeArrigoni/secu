#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include "server.h"
#include "client.h"
#include "common_constante.h"
#include <sys/stat.h>

#ifndef EXIT_FAILURE
#define EXIT_FAILURE 1
#endif



static char FOLDER_SAVE_LOCAL[260] = "./trash";


//Method use to add a name in the log file
void addLogINFile(const char *texte) {
    FILE *fichier = fopen("./serverUtils/login.txt", "a"); 
    if (fichier == NULL) {
        perror("Error while opening the file");
        return;
    }
    fclose(fichier);
}

//Method use to create a folder
int createFolder(const char* name) {
  int ret;
  ret = mkdir(name, 0775);
  if (ret != 0) {
    //Error
    return 1;
  }
  return 0;
}

//Method use to save a file content in memory
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


//Method use to delete a file
int deleteFile(const char *filePath) {
    if (remove(filePath) == 0) {
        return 0; 
    } else {
        return -1;
    }
}


//Method use to write a text into a file
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

//Method use to create full path witl folder and file name
int createFilePathComplete(const char* folderPath, const char* fileName, char* completFileNamePath) {
    strcpy(completFileNamePath, folderPath);
    if (completFileNamePath[strlen(completFileNamePath) - 1] != '/') {
        strcat(completFileNamePath, "/");
    }
    strcat(completFileNamePath, fileName);

    return 0;
}

//Method use to check if a file exist
int fileExists(const char* folderPath, const char* fileName) {
    char filePath[256] = "";
    createFilePathComplete(folderPath,fileName, filePath);
    if (access(filePath, F_OK) != -1) {
        //File exist
        return 1;
    } else {
        return 0;
    }
}


/*
GROUP OF METHOD USE TO ENCRYPT PASSWORD
*/
int calculateSum(const char *str) {
    int somme = 0;
    while (*str) {
        somme += *str - 'A' + 1;
        str++;
    }
    return somme;
}

void CesarCrypt(char *str, int decallage) {
    while (*str) {
        if (*str >= 'A' && *str <= 'Z') {
            *str = (*str - 'A' + decallage) % 26 + 'A';
        }
        str++;
    }
}

int LOGCrypt(const char* mdp, char* userName) {
    int somme = calculateSum(mdp);
    int index = somme % strlen(mdp);
    int decallage = mdp[index] - 'A' + 1;
    CesarCrypt(userName, decallage);
    int decallageSup = 0;
    for (int i = 0; i < strlen(userName); i++) {
        if (i % decallage == 0) {
            decallageSup++;
            userName[i] = (userName[i] - 'A' + decallageSup) % 26 + 'A';
        }
    }
    return 0;
}


int checkIfExistInLogFile(const char *mdp, const char *userName) {
    FILE *fichier = fopen("./serverUtils/login.txt", "r");
    if (fichier == NULL) {
        perror("Erreur lors de l'ouverture du fichier");
        return 0; 
    }
    char *ligne = NULL;
    size_t len = 0;
    while (getline(&ligne, &len, fichier) != -1) {
        char *token = strtok(ligne, "|");
        while (token != NULL) {
            LOGCrypt(mdp, token);
            if (strcmp(token, userName) == 0) {
                free(ligne); 
                fclose(fichier);
                return 1; 
            }

            token = strtok(NULL, "|");
        }
    }
    free(ligne); 
    fclose(fichier);
    return 0; 
}
/*
END GROUP OF METHOD USE TO ENCRYPT PASSWORD
*/



//Method use to launch logIn Operation if msg_read is correct
int logInOperation(const char* msg_read) {
    const char* firstOccurrence = strstr(msg_read, LOG_IN);
    const char* secondOccurrence = NULL;
    if (firstOccurrence != NULL) {
        secondOccurrence = strstr(firstOccurrence + strlen(LOG_IN), LOG_IN);
    }
    if (firstOccurrence != NULL && secondOccurrence != NULL) {
        char name[256] = "";
        char password[256] = "";

        strncpy(name, firstOccurrence + strlen(LOG_IN), secondOccurrence - (firstOccurrence + strlen(LOG_IN)));
        name[secondOccurrence - (firstOccurrence + strlen(LOG_IN))] = '\0';

        strncpy(password, secondOccurrence + strlen(LOG_IN), strlen(msg_read) - (secondOccurrence - msg_read));
        password[strlen(msg_read) - (secondOccurrence - msg_read)] = '\0';

        
        if (checkIfExistInLogFile(password, name)== 0) {
            createFolder(name);
            char nameModif = *name;
            LOGCrypt(password, &nameModif);
            addLogINFile(&nameModif);
        }
        strcpy(FOLDER_SAVE_LOCAL, name);
        return 0;
        
    }
    return EXIT_FAILURE;
}

//Method use to launch deletion Operation if msg_read is correct
int deleteOperation(const char* msg_read) {
    char fileName[256] = "";
    const char* occurrence = strstr(msg_read, DELETE);

    if (occurrence != NULL) {

        strncpy(fileName, occurrence + strlen(DELETE), strlen(msg_read) - (occurrence - msg_read));
        fileName[strlen(msg_read) - (occurrence - msg_read)] = '\0';

        char *folder_name = FOLDER_SAVE_LOCAL;
        if (fileExists(folder_name,fileName) != 0) {
            char filePath[256] = "";
            createFilePathComplete(folder_name,fileName, filePath);

            if (deleteFile(filePath) == 0) {
                return 0;
            } 
        }
        
    }
    return EXIT_FAILURE;
}

//Method use to rename a file
int renommerFichier(const char* ancienNom, const char* nouveauNom, const char* folderPath) {
    char filePathOld[256] = "";
    createFilePathComplete(folderPath,ancienNom, filePathOld);
    char filePathNew[256] = "";
    createFilePathComplete(folderPath,nouveauNom, filePathNew);
    if (rename(filePathOld, filePathNew) == 0) {
        return 0;  // Success
    } else {
        return -1;  // Failed
    }
}

//Method use to launch renaming Operation if msg_read is correct
int renameOperation(const char* msg_read) {
    const char* firstOccurrence = strstr(msg_read, RENAME);
    const char* secondOccurrence = NULL;
    if (firstOccurrence != NULL) {
        secondOccurrence = strstr(firstOccurrence + strlen(RENAME), RENAME);
    }
    if (firstOccurrence != NULL && secondOccurrence != NULL) {
        char oldFileName[256] = "";
        char newFileName[256] = "";

        strncpy(oldFileName, firstOccurrence + strlen(RENAME), secondOccurrence - (firstOccurrence + strlen(RENAME)));
        oldFileName[secondOccurrence - (firstOccurrence + strlen(RENAME))] = '\0';

        strncpy(newFileName, secondOccurrence + strlen(RENAME), strlen(msg_read) - (secondOccurrence - msg_read));
        newFileName[strlen(msg_read) - (secondOccurrence - msg_read)] = '\0';

        char *folder_name = FOLDER_SAVE_LOCAL;

        if (fileExists(folder_name,oldFileName) != 0) {
            if (renommerFichier(oldFileName,newFileName,folder_name) == 0) {
                return 0;
            } 
        }
    }
    return EXIT_FAILURE;
}

int convertirStringInt(const char *chaine, int* number) {

    if (sscanf(chaine, "%d", number) != 1) {
        return EXIT_FAILURE;
    }
    return 0;
}


//Method use to launch give back to user a target file Operation if msg_read is correct
int getBackOperation(const char* msg_read) {
    const char* firstOccurrence = strstr(msg_read, GET_BACK_FILE);
    const char* secondOccurrence = NULL;
    if (firstOccurrence != NULL) {
        secondOccurrence = strstr(firstOccurrence + strlen(GET_BACK_FILE), GET_BACK_FILE);
    }

    if (firstOccurrence != NULL && secondOccurrence != NULL) {
        char fileName[256];
        char port[256];

        strncpy(fileName, firstOccurrence + strlen(GET_BACK_FILE), secondOccurrence - (firstOccurrence + strlen(GET_BACK_FILE)));
        fileName[secondOccurrence - (firstOccurrence + strlen(GET_BACK_FILE))] = '\0';

        strncpy(port, secondOccurrence + strlen(GET_BACK_FILE), strlen(msg_read) - (secondOccurrence - msg_read));
        port[strlen(msg_read) - (secondOccurrence - msg_read)] = '\0';

        int numberPort;
        char *folder_name = FOLDER_SAVE_LOCAL;
        if (convertirStringInt(port,&numberPort) == 0) {
            if (fileExists(folder_name,fileName)) {
                char filePath[256] = "";
                createFilePathComplete(folder_name,fileName, filePath);
                const char* originalFilePath = filePath;
                char fileContent[50*MAX_FILE_SIZE] = "";
                size_t bytesRead;
                if (copyFileToMemory(originalFilePath, fileContent, &bytesRead) == -1) {
                    return EXIT_FAILURE;
                } 
                if (sndmsg(fileContent, numberPort) != 0) {
                    return EXIT_FAILURE;
                }
                return 0;
            }
        }   
    }
    return EXIT_FAILURE;
}



//Method use to get all the file in user folder
int getListOfFiles(const char* folderPath, char* nameAllFile) {
    DIR* dir = opendir(folderPath);

    if (dir == NULL) {
        perror("Erreur lors de l'ouverture du dossier");
        return EXIT_FAILURE;
    }

    struct dirent* entry;
    size_t totalLength = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            size_t entryLength = strlen(entry->d_name);
            size_t separatorLength = strlen(SEPARATOR_LIST);

            if (totalLength + entryLength + separatorLength < MAX_FILE_SIZE) {
                strcat(nameAllFile, entry->d_name);
                strcat(nameAllFile, SEPARATOR_LIST);
                totalLength += entryLength + separatorLength;
            } else {
                break;
            }
        }
    }

    closedir(dir);
    return 0;
}

//Method use to launch list Operation if msg_read is correct
int listFileOperation(const char* msg_read) {
    const char* occurrence = strstr(msg_read, LIST_FILE);

    if (occurrence != NULL) {
        char port[256];

        strncpy(port, occurrence + strlen(LIST_FILE), strlen(msg_read) - (occurrence - msg_read));
        port[strlen(msg_read) - (occurrence - msg_read)] = '\0';

        int numberPort;
        char listAllFile[MAX_FILE_SIZE] = "";
        char *folder_name = FOLDER_SAVE_LOCAL;
        if (convertirStringInt(port,&numberPort) == 0) {
            if (getListOfFiles(folder_name, listAllFile) == 0) {
                if (sndmsg(listAllFile, numberPort) != 0) {
                    return EXIT_FAILURE;
                }
                return 0;
            }
        }   
    }
    return EXIT_FAILURE;
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


//Method use to launch saving a file Operation if msg_read is correct
int writeNewFileOperation(const char* msg_read) {
    


    size_t bytesRead = strlen(msg_read);
    char* fileNameDefault = "newFile";
    char *folder_name = FOLDER_SAVE_LOCAL;
    char filePath[MAX_FILE_SIZE];
    createFilePathComplete(folder_name,fileNameDefault, filePath);
    char fileNameReturned[MAX_FILE_SIZE];
    if (createUniqueFileName(filePath,fileNameReturned) != 0) {
        return EXIT_FAILURE;
    }
    
    if (writeToFile(fileNameReturned, msg_read, bytesRead) == -1) {
        return EXIT_FAILURE;
    }
    return 0;
}


//MAIN
int main(int argc, char *argv[]) {
    int port;
    if (argc == 2) {
        port = atoi(argv[1]);
    } else {
        port = 8080; //DEFAULT
    }

    if (startserver(port) == -1) {
        fprintf(stderr, "Error starting the server\n");
        exit(EXIT_FAILURE);
    }

    char msg_read[MAX_FILE_SIZE];

    while (1) {
        if (getmsg(msg_read) == -1) {
            fprintf(stderr, "Error receiving message from client\n");
            stopserver(); 
            exit(EXIT_FAILURE);
        }

        if (strcmp(msg_read, "") != 0) {
            if (renameOperation(msg_read) == 0 ) {
            } else if (getBackOperation(msg_read) == 0) {
            } else if (listFileOperation(msg_read) == 0) {
            } else if (renameOperation(msg_read) == 0) {
            } else if (deleteOperation(msg_read) == 0) {
            } else if (logInOperation(msg_read) == 0) {
            } else {
                writeNewFileOperation(msg_read);
            }
        }
        memset(msg_read, 0, sizeof(msg_read));
    }
    stopserver();

    return 0;
}