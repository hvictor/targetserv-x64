#define _CRT_SECURE_NO_WARNINGS
#define MAX_RECV_BUFFER 3000

#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#pragma comment(lib, "ws2_32.lib")

char recvbuf[MAX_RECV_BUFFER];

void function_1()
{
    printf("Function_1 executing\n");
}

void function_2()
{
    printf("Function_2 executing\n");
}

void function_3()
{
    printf("Function_3 executing\n");
}

void function_4()
{
    printf("Function_4 executing\n");
}

void (*function_array[4])() = { function_1, function_2, function_3, function_4 };

// Function declarations
void CopyData1(char* pkt_data, int len);
void MoveToHeapMemoryAndSetValue(char* pkt_data, int len);

// Function to validate the packet
bool validate_packet(char* buffer, int bytesReceived)
{
    if (bytesReceived < 8) { // At least 8 bytes required (2 DWORDs)
        return false;
    }

    DWORD length = *(DWORD*)buffer;  // First DWORD: Total length
    DWORD xor_val = *(DWORD*)(buffer + 4);  // Second DWORD: XORed value

    if ((length ^ xor_val) != bytesReceived) {  // XOR validation
        return false;
    }

    return true;
}

// Function to handle the opcode
void handle_opcode(DWORD opcode, char* pkt_data, int len, uint64_t *sock_ptr)
{
    uint64_t u64buf;

    switch (opcode)
    {
        case 0x1:
            CopyData1(pkt_data, len);  // Call CopyData1 for opcode 0x1
            break;
        case 0x2:
            printf("Executing MoveToHeapMemoryAndSetValue on data with len = %d\n", len);
            MoveToHeapMemoryAndSetValue(pkt_data, len);
            break;
        case 0x3:
            printf("Sending User ID = 0x%llx\n", sock_ptr);
            u64buf = (uint64_t)sock_ptr;
            send((SOCKET)(*sock_ptr), (char *)&u64buf, 8, 0);
            break;
        case 0x99:
            printf("Sending Base Function = 0x%llx\n", (uint64_t)((uint64_t *)function_array));
            u64buf = (uint64_t)((uint64_t *)function_array);
            send((SOCKET)(*sock_ptr), (char *)&u64buf, 8, 0);
            break;            
        // Add additional cases as necessary
        default:
            printf("Unknown opcode: 0x%lx\n", opcode);
            break;
    }
}

// Copy data function (opcode 0x1)
void CopyData1(char* pkt_data, int len)
{
    char buffer[100];

    memcpy(buffer, pkt_data, len);

    printf("CopyData1 executed. Length = %d bytes\n", len);
}

// Copy data function (opcode 0x2)
void MoveToHeapMemoryAndSetValue(char* pkt_data, int len)
{
    char header[500];

    // Ensure the packet is large enough to contain two QWORDs
    if (len < 16) {
        printf("Invalid packet length. Need at least 16 bytes.\n");
        return;
    }

    // First QWORD: Address where the value will be written
    uint64_t *addr = (uint64_t*) *((uint64_t*)(pkt_data + 0));

    // Second QWORD: Value to write at the specified address
    uint64_t value = *(uint64_t*)(pkt_data + 8);

    // Extract the header
    memcpy(header, pkt_data + 16, 500);

    // The rest of the data (after the first 16 bytes) is copied to heap memory
    char *rest_of_data = pkt_data + 16 + 500;
    int data_len = len - 16 - 500;

    // Allocate memory to copy the remaining data
    DWORD oldProtect;
    VirtualProtect(header, 500, 0x40, &oldProtect);
    char *allocated_memory = VirtualAlloc(0, data_len, 0x1000, 0x4);

    // Copy the remaining data into the allocated heap memory
    memcpy(allocated_memory, rest_of_data, data_len);
    memset(rest_of_data, 0, data_len);
    printf("Data moved to heap memory at 0x%llx\n", allocated_memory);

    // Write the value to the specified memory address
    printf("Writing value 0x%llx to address 0x%llx\n", value, addr);
    *addr = value;
}

// Client handler thread
unsigned __stdcall client_handler(void* clientSocketPtr) {
    SOCKET clientSocket = *(SOCKET*)clientSocketPtr;

    while (true)
    {
        printf("receiving data...\n");
        int bytesReceived = recv(clientSocket, recvbuf, MAX_RECV_BUFFER, 0);
        printf("received %d bytes\n", bytesReceived);

        if (!validate_packet(recvbuf, bytesReceived)) {
            printf("Invalid packet received. Closing connection.\n");
            break;
        }

        DWORD opcode = *(DWORD*)(recvbuf + 8);  // Extract opcode (starts after the first 8 bytes)
        char* pkt_data = recvbuf + 12;          // Data starts after the first 12 bytes
        int len = bytesReceived - 12;           // Length of the data

        // Handle the opcode
        handle_opcode(opcode, pkt_data, len, (uint64_t *)&clientSocket);
    }

    closesocket(clientSocket);
    return 0;
}

int main()
{
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

        "sub rsp, 0x230     \r\n"
        "ret                \r\n"
    );
}
