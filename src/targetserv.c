#define _CRT_SECURE_NO_WARNINGS
#define MAX_RECV_BUFFER 3000

#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#pragma comment(lib, "ws2_32.lib")

char recvbuf[MAX_RECV_BUFFER];

void x(int bytesReceived)
{
    __asm(
        "push rsp           \r\n"
        "pop rcx            \r\n"
        "ret                \r\n"

        "mov rax, [rax]     \r\n"
        "ret                \r\n"

        "pop rbx            \r\n"
        "ret                \r\n"

        "mov rcx, rbx       \r\n"
        "ret                \r\n"

        "mov rdx, rbx       \r\n"
        "ret                \r\n"

        "mov r8, rbx        \r\n"
        "ret                \r\n"

        "mov r9, rbx        \r\n"
        "ret                \r\n"

        "neg rbx            \r\n"
        "ret                \r\n"
    
        "add rcx, rbx       \r\n"
        "ret                \r\n"

        "sub rcx, rbx       \r\n"
        "ret                \r\n"

        "mov qword ptr [rax], rcx     \r\n"
        "ret                \r\n"

        "xchg rax, rcx      \r\n"
        "push rax           \r\n"
        "pop rcx            \r\n"
        "ret                \r\n"

        "mov r10, rax       \r\n"
        "ret                \r\n"

        "mov r11, rax       \r\n"
        "ret                \r\n"

        "mov r12, rax       \r\n"
        "ret                \r\n"

        "mov r13, rax       \r\n"
        "ret                \r\n"
        
        "mov rcx, r10       \r\n"
        "ret                \r\n"  

        "mov rcx, r11       \r\n"
        "ret                \r\n"  

        "inc rax            \r\n"
        "ret                \r\n"

        "dec rax            \r\n"
        "ret                \r\n"

        "xchg rsp, rax      \r\n"
        "ret                \r\n"
    );
}

void use_data(int bytesReceived)
{
    printf("--> %d\n", bytesReceived);

    char buffer[100];  // Vulnerable buffer

    memcpy(buffer, recvbuf, bytesReceived);

    printf("copied: %d bytes\n", bytesReceived);
}

unsigned __stdcall client_handler(void* clientSocketPtr) {
    SOCKET clientSocket = *(SOCKET*)clientSocketPtr;

    while (true)
    {
        printf("receiving data...\n");
        int bytesReceived = recv(clientSocket, recvbuf, MAX_RECV_BUFFER, 0);
        printf("received %d bytes\n", bytesReceived);
        use_data(bytesReceived);
    }

    closesocket(clientSocket);
    return 0;
}

int main() {
    WSADATA wsaData;
    SOCKET serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    int clientAddrSize = sizeof(clientAddr);

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("Winsock Error\n");
        return 1;
    }

    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        printf("Cannot create socket\n");
        WSACleanup();
        return 1;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(9090);

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("Error during bind\n");
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("Error during listen\n");
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    printf("Server listening on port 9090 (TCP)...\n");

    while (1) {
        clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket == INVALID_SOCKET) {
            printf("Error in accept\n");
            continue;
        }

        printf("Client connected\n");

        HANDLE threadHandle;
        unsigned threadID;
        threadHandle = (HANDLE)_beginthreadex(NULL, 0, client_handler, (void*)&clientSocket, 0, &threadID);

        if (threadHandle == NULL) {
            printf("Error creating client thread\n");
            closesocket(clientSocket);
        }
        else {
            CloseHandle(threadHandle);
        }
    }

    closesocket(serverSocket);
    WSACleanup();
    return 0;
}
