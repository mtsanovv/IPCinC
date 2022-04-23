#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h> 
#include <sys/stat.h> 
#include <sys/wait.h> 
#include <signal.h> 
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

// some constants
#define MAX_USERNAME_LENGTH 32
#define MAX_PASSWORD_LENGTH 72
#define MAX_MESSAGE_LENGTH 72
#define MAX_COMMAND_LEGNTH 2048

#define PACKET_TYPE_AUTH 0
#define PACKET_TYPE_AUTH_FAILURE 1
#define PACKET_TYPE_AUTH_SUCCESS 2
#define PACKET_TYPE_END 3

#define SUSPICIOUS_ATTEMPTS 5
#define MAX_ATTEMPTS 10

const char *USERNAMES_FILE = "./data/usernames";
const char *PASSWORDS_FILE = "./data/passwords";
const char *FAILED_ATTEMPTS_FILE = "./data/failedAttempts";

const char *COMMUNICATION_REQUESTS_PIPE_NAME = "userLoginRequests";
const char *COMMUNICATION_RESPONSES_PIPE_NAME = "userLoginResponses";

pid_t childPid = 0;

typedef struct {
    char packetType;
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    char message[MAX_MESSAGE_LENGTH];
} Packet;

/* exit codes:
0 - success
1 - inter-process communication failure (issue with pipes/fifo)
2 - validation failed
3 - process creation failure
4 - file error
*/

void registerExitSignalHandlers();
static void exitHandler(void);
int checkIfNeededFilesAreAvailableAndWithCorrectPermissions();
int checkIfRequiredFilesExist();
int checkIfRequiredFilesHaveReadPermissions();
int checkIfFailedAttemptsFileNeedsWritePermissions();
void handleCoordinatorProcess(pid_t childPid);
void handleWorkerProcess();
int requestLogin(Packet *packet);
void endCoordinatorCommunication();
Packet handleLogin(Packet *packet);
int checkIfIpIsBlocked(char *username);
int isIpBlocked(char *ip);
char* findIpByUsername(char *username);
void stripNewline(char *str);
int checkCredentials(char *username, char *password);
int getIpFailedAttempts(char *ip);
void logFailedAttemptIfPossible(char *username);

int main() {
    registerExitSignalHandlers();
    if(mkfifo(COMMUNICATION_REQUESTS_PIPE_NAME, 0666) == -1 || mkfifo(COMMUNICATION_RESPONSES_PIPE_NAME, 0666) == -1) {
        printf("Failed to create named pipe for inter-process communication\n");
        return 1;
    }
    childPid = fork();
    if(childPid > 0) {
        handleCoordinatorProcess(childPid);
        return 0;
    }

    if(childPid == 0) {
        handleWorkerProcess();
        return 0;
    }

    printf("Failed creating coordinator & worker processes.\n");
    return 3;
}

void registerExitSignalHandlers() {
    atexit(exitHandler);
    signal(SIGINT, exitHandler);
    signal(SIGKILL, exitHandler);
    signal(SIGQUIT, exitHandler);
    signal(SIGTERM, exitHandler);
    signal(SIGHUP, exitHandler);
}

static void exitHandler(void) {
    printf("\n");
    fclose(stdout);
    if(childPid > 0) {
        kill(childPid, SIGKILL);
    }
    unlink(COMMUNICATION_REQUESTS_PIPE_NAME);
    unlink(COMMUNICATION_RESPONSES_PIPE_NAME);
}

void handleCoordinatorProcess(pid_t childPid) {
    if(!checkIfNeededFilesAreAvailableAndWithCorrectPermissions()) {
        exit(2);
    }

    Packet readPacket;

    while(1) {
        int pipeReadResponse = 0;
        int requestsPipeFd = open(COMMUNICATION_REQUESTS_PIPE_NAME, O_RDONLY);
        while((pipeReadResponse = read(requestsPipeFd, &readPacket, sizeof(Packet))) == 0) {
            // wait for requests by worker and check if worker is still alive
            continue;
        }
        close(requestsPipeFd);
        if(pipeReadResponse == -1) {
            printf("Error while waiting for requests by worker over %s pipe\n", COMMUNICATION_REQUESTS_PIPE_NAME);
            exit(1);
        }
        if(readPacket.packetType == PACKET_TYPE_END) {
            return;
        }

        Packet responsePacket = handleLogin(&readPacket);

        int responsesPipeFd = open(COMMUNICATION_RESPONSES_PIPE_NAME, O_WRONLY);
        if(write(responsesPipeFd, &responsePacket, sizeof(Packet)) == -1) {
            printf("Failed to send response to worker over %s pipe\n", COMMUNICATION_RESPONSES_PIPE_NAME);
            exit(1);
        }
        close(responsesPipeFd);
    }
}

Packet handleLogin(Packet *packet) {
    Packet responsePacket = { .packetType = PACKET_TYPE_AUTH_FAILURE };
    int isIpBlocked = checkIfIpIsBlocked(packet->username);
    if(isIpBlocked) {
        strcpy(responsePacket.message, "This user is not allowed to log in.");
        return responsePacket;
    }
    int areCredentialsCorrect = checkCredentials(packet->username, packet->password);
    if(areCredentialsCorrect) {
        responsePacket.packetType = PACKET_TYPE_AUTH_SUCCESS;
        strcpy(responsePacket.message, "Login successful!");
        return responsePacket;
    }
    logFailedAttemptIfPossible(packet->username);
    strcpy(responsePacket.message, "Invalid credentials, try again.");
    return responsePacket;
}

void logFailedAttemptIfPossible(char *username) {
    char commandToExecute[MAX_COMMAND_LEGNTH];
    char *ip = findIpByUsername(username);
    if(ip == NULL) {
        return;
    }
    if(access(FAILED_ATTEMPTS_FILE, F_OK)) {
        // failed attempts file does not exist, we can create it with a command to the shell
        sprintf(commandToExecute, "echo \"%s:1\" > %s", ip, FAILED_ATTEMPTS_FILE);
        system(commandToExecute);
        return;
    }
    int ipFailedAttempts = getIpFailedAttempts(ip);
    if(ipFailedAttempts == 0) {
        // failed attempts file exists and does not contain this IP, we need to append it
        sprintf(commandToExecute, "perl -pi -e 'eof && print \"%s:1\\n\"' %s", ip, FAILED_ATTEMPTS_FILE);
        system(commandToExecute);
        return;
    }

    // failed attempts file exists and contains this IP, we need to increase the number of failed attempts
    char attemptsToAppend[MAX_MESSAGE_LENGTH];
    switch(ipFailedAttempts) {
        case SUSPICIOUS_ATTEMPTS - 1:
            sprintf(attemptsToAppend, ":%d:SUSPICIOUS", ipFailedAttempts + 1);
            break;
        case MAX_ATTEMPTS - 1:
            sprintf(attemptsToAppend, ":%d:BLOCKED", ipFailedAttempts + 1);
            break;
        default:
            sprintf(attemptsToAppend, ":%d$1", ipFailedAttempts + 1);
            break;
    }
    sprintf(commandToExecute, "perl -pi -e 's/^%s:%d(.*)$/%s%s/gm' %s", ip, ipFailedAttempts, ip, attemptsToAppend, FAILED_ATTEMPTS_FILE);
    system(commandToExecute);
}

int checkCredentials(char *username, char *password) {
    FILE *fp;
    char *line = NULL;
    size_t lineLen = 0;
    int credentialsCorrect = 0;

    fp = fopen(PASSWORDS_FILE, "r");
    if(fp == NULL) {
        printf("Error opening file %s!\n", PASSWORDS_FILE);
        exit(4);
    }
    
    while (getline(&line, &lineLen, fp) != -1) {
        stripNewline(line);
        char *readUsername = strtok(line, ":");
        if(readUsername == NULL) {
            continue;
        }
        if(strcmp(readUsername, username) == 0) {
            char *readPassword = strtok(NULL, ":");
            if(readPassword == NULL) {
                // allow passwordless login
                readPassword = "";
            }
            if(strcmp(readPassword, password) == 0) {
                credentialsCorrect = 1;
            }
            break;
        }
    }

    fclose(fp);
    return credentialsCorrect;
}

int checkIfIpIsBlocked(char *username) {
     if(access(FAILED_ATTEMPTS_FILE, F_OK)) {
        // failed attempts file does not exist - so username definitely hasn't been blocked
        return 0;
    }
    char *ip = findIpByUsername(username);
    if(ip == NULL) {
        // username not found
        return 0;
    }
    return isIpBlocked(ip);
}

int isIpBlocked(char *ip) {
    FILE *fp;
    char *line = NULL;
    size_t lineLen = 0;
    int isIpBlocked = 0;

    fp = fopen(FAILED_ATTEMPTS_FILE, "r");
    if(fp == NULL) {
        printf("Error opening file %s!\n", FAILED_ATTEMPTS_FILE);
        exit(4);
    }
    
    while (getline(&line, &lineLen, fp) != -1) {
        stripNewline(line);
        char *readIp = strtok(line, ":");
        if(readIp == NULL) {
            continue;
        }
        if(strcmp(readIp, ip) == 0) {
            char *readAttemptsFromIp = strtok(NULL, ":");
            if(readAttemptsFromIp == NULL) {
                continue;
            }
            int attemptsFromIp = atoi(readAttemptsFromIp);
            if(attemptsFromIp >= MAX_ATTEMPTS) {
                isIpBlocked = 1;
            }
            break;
        }
    }

    fclose(fp);
    return isIpBlocked;
}

int getIpFailedAttempts(char *ip) {
    FILE *fp;
    char *line = NULL;
    size_t lineLen = 0;
    int ipFailedAttempts = 0;

    fp = fopen(FAILED_ATTEMPTS_FILE, "r");
    if(fp == NULL) {
        printf("Error opening file %s!\n", FAILED_ATTEMPTS_FILE);
        exit(4);
    }
    
    while (getline(&line, &lineLen, fp) != -1) {
        stripNewline(line);
        char *readIp = strtok(line, ":");
        if(readIp == NULL) {
            continue;
        }
        if(strcmp(readIp, ip) == 0) {
            char *readAttemptsFromIp = strtok(NULL, ":");
            if(readAttemptsFromIp == NULL) {
                continue;
            }
            ipFailedAttempts = atoi(readAttemptsFromIp);
            break;
        }
    }

    fclose(fp);
    return ipFailedAttempts;
}

char* findIpByUsername(char *username) {
    FILE *fp;
    char *line = NULL;
    char *ip = NULL;
    size_t lineLen = 0;

    fp = fopen(USERNAMES_FILE, "r");
    if(fp == NULL) {
        printf("Error opening file %s!\n", USERNAMES_FILE);
        exit(4);
    }
    
    while (getline(&line, &lineLen, fp) != -1) {
        stripNewline(line);
        char *currentUsername = strtok(line, ":");
        if(currentUsername == NULL) {
            continue;
        }
        if(strcmp(username, currentUsername) == 0) {
            ip = strtok(NULL, ":");
            break;
        }
    }

    fclose(fp);
    return ip;
}

void handleWorkerProcess() {
    while(1) {
        Packet packet = { .packetType = PACKET_TYPE_AUTH };

        printf("Username: ");
        fflush(stdin);
        fgets(packet.username, sizeof(packet.username), stdin);
        stripNewline(packet.username);
        if(strcmp(packet.username, "") == 0) {
            printf ("Username cannot be empty.\n");
            continue;
        }

        printf("Password: ");
        fflush(stdin);
        fgets(packet.password, sizeof(packet.password), stdin);
        stripNewline(packet.password);
        int loginSuccessful = requestLogin(&packet);
        if(loginSuccessful) {
            endCoordinatorCommunication();
            break;
        }
    }
}

void stripNewline(char *str) {
    int indexOfLastChar = strlen(str) - 1;
    if(str[indexOfLastChar] == '\n') {
        str[indexOfLastChar] = '\0';
    }
}

void endCoordinatorCommunication() {
    Packet packet = { .packetType = PACKET_TYPE_END };
    int requestsPipeFd = open(COMMUNICATION_REQUESTS_PIPE_NAME, O_WRONLY);

    if(write(requestsPipeFd, &packet, sizeof(Packet)) == -1) {
        printf("Failed to send request to coordinator over %s pipe\n", COMMUNICATION_REQUESTS_PIPE_NAME);
        exit(1);
    }
    close(requestsPipeFd);
}

int requestLogin(Packet *packet) {
    Packet readPacket;
    int pipeReadResponse = 0;
    int requestsPipeFd = open(COMMUNICATION_REQUESTS_PIPE_NAME, O_WRONLY);

    if(write(requestsPipeFd, packet, sizeof(Packet)) == -1) {
        printf("Failed to send request to coordinator over %s pipe\n", COMMUNICATION_REQUESTS_PIPE_NAME);
        exit(1);
    }
    close(requestsPipeFd);
    int responsesPipeFd = open(COMMUNICATION_RESPONSES_PIPE_NAME, O_RDONLY);
    while((pipeReadResponse = read(responsesPipeFd, &readPacket, sizeof(Packet))) == 0) {
        // wait for response by coordinator
        continue;
    }
    close(responsesPipeFd);
    if(pipeReadResponse == -1) {
        printf("Error while waiting for response by coordinator over %s pipe\n", COMMUNICATION_RESPONSES_PIPE_NAME);
        exit(1);
    }
    printf("%s\n", readPacket.message);
    if(readPacket.packetType == PACKET_TYPE_AUTH_SUCCESS) {
        return 1;
    }
    return 0;
}

int checkIfNeededFilesAreAvailableAndWithCorrectPermissions() {
    if(!checkIfRequiredFilesExist()) {
        return 0;
    }

    if(!checkIfRequiredFilesHaveReadPermissions()) {
        return 0;
    }

    if(checkIfFailedAttemptsFileNeedsWritePermissions()) {
        return 0;
    }
    return 1;
}

int checkIfFailedAttemptsFileNeedsWritePermissions() {
    if(access(FAILED_ATTEMPTS_FILE, F_OK)) {
        // file does not exist
        return 0;
    }
    // file exists so we need to make sure that it is writeable
    if(access(FAILED_ATTEMPTS_FILE, W_OK)) {
        printf("Failed attempts file: %s has been created but does not have write permmissions, which are required.\n", FAILED_ATTEMPTS_FILE);
        return 1;
    }

    return 0;
}

int checkIfRequiredFilesExist() {
    int validationSuccessful = 1;
    if(access(USERNAMES_FILE, F_OK)) {
        printf("Required file with usernames and IP addresses doesn't exist: %s\n", USERNAMES_FILE);
        validationSuccessful = 0;
    }

    if(access(PASSWORDS_FILE, F_OK)) {
        printf("Required file with usernames and passwords doesn't exist: %s\n", PASSWORDS_FILE);
        validationSuccessful = 0;
    }

    return validationSuccessful;
}

int checkIfRequiredFilesHaveReadPermissions() {
    int validationSuccessful = 1;
    if(access(USERNAMES_FILE, R_OK)) {
        printf("Required file with usernames and IP addresses doesn't have read permissions: %s\n", USERNAMES_FILE);
        validationSuccessful = 0;
    }

    if(access(PASSWORDS_FILE, R_OK)) {
        printf("Required file with usernames and passwords doesn't have read permissions: %s\n", PASSWORDS_FILE);
        validationSuccessful = 0;
    }

    return validationSuccessful;
}