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
void MoveToHeapMemoryAndSetValue(char *pkt_data, int len);
void ProcessFileXferRequest(uint64_t *sock_ptr, char *pkt_data);
void InitiateXferUpload(uint64_t *sock_ptr, const char *filename, uint32_t block_size);
void InitiateXferDownload(uint64_t *sock_ptr, const char *filename, uint32_t block_size);

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
        case 0x44:
            printf("Processing File Xfer Request:\n");
            ProcessFileXferRequest(sock_ptr, pkt_data);
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

void ProcessFileXferRequest(uint64_t *sock_ptr, char *pkt_data)
{
    uint32_t xfer_operation = *(uint32_t *)pkt_data;
    char dest_filename[40] = {0};
    memcpy(dest_filename, pkt_data + 4, 39);  // 39 chars + null terminator = 40

    uint32_t block_size = *(uint32_t *)(pkt_data + 44); // 4 + 40 = 44

    // Send ACK
    uint32_t ack = 0xcacabecc;
    send((SOCKET)(*sock_ptr), (char *)&ack, 4, 0);

    switch (xfer_operation)
    {
    case 1:
        // Upload
        InitiateXferUpload(sock_ptr, dest_filename, block_size);
        break;
    case 2:
        // Download
        InitiateXferDownload(sock_ptr, dest_filename, block_size);
        break;
    default:
        printf("[!] Unknown xfer_operation: %u\n", xfer_operation);
        break;
    }
}

void InitiateXferUpload(uint64_t *sock_ptr, const char *filename, uint32_t block_size)
{
    uint32_t ack = 0xcacabecc;
    uint32_t nack = 0xbecccaca;

    SOCKET s = (SOCKET)(*sock_ptr);

    // Ensure .\xfers exists
    CreateDirectoryA(".\\xfers", NULL);

    char full_path[MAX_PATH];
    snprintf(full_path, MAX_PATH, ".\\xfers\\%s", filename);

    FILE *fp = fopen(full_path, "wb");
    if (fp)
    {
        uint64_t file_id = (uint64_t)fp;
        send(s, (char *)&file_id, sizeof(file_id), 0);
    }
    else
    {
        uint64_t error_code = 0xffffffffffffffff;
        send(s, (char *)&error_code, sizeof(error_code), 0);
        return;
    }

    uint32_t expected_sequence = 0;

    while (1)
    {
        uint32_t header[2]; // sequence_number, data_len

        int received = recv(s, (char *)header, sizeof(header), MSG_WAITALL);
        if (received != sizeof(header))
        {
            printf("[!] Failed to receive packet header.\n");
            send(s, (char *)&nack, 4, 0);
            break;
        }

        uint32_t sequence_number = header[0];
        uint32_t data_len = header[1];

        if (data_len == 0)
        {
            // EOF marker
            printf("[*] EOF packet received: xfer completed.\n");
            send(s, (char *)&ack, 4, 0);
            break;
        }

        if (sequence_number != expected_sequence)
        {
            printf("[!] Unexpected sequence number. Expected %u, got %u\n", expected_sequence, sequence_number);
            send(s, (char *)&nack, 4, 0);
            break;
        }

        uint8_t *data_buf = (uint8_t *)malloc(data_len);
        if (!data_buf)
        {
            printf("[!] Memory allocation failed.\n");
            send(s, (char *)&nack, 4, 0);
            break;
        }

        received = recv(s, (char *)data_buf, data_len, MSG_WAITALL);
        if (received != (int)data_len)
        {
            printf("[!] Failed to receive full data block.\n");
            send(s, (char *)&nack, 4, 0);
            free(data_buf);
            break;
        }

        // Acknowledge the data packet
        send(s, (char *)&ack, 4, 0);

        fwrite(data_buf, 1, data_len, fp);
        free(data_buf);
    
        expected_sequence++;
    }

    fclose(fp);
    printf("[*] Upload complete: %s\n", full_path);
}

void InitiateXferDownload(uint64_t *sock_ptr, const char *filename, uint32_t block_size)
{
    SOCKET s = (SOCKET)(*sock_ptr);

    uint8_t data_buffer[100]; // <-- VULNERABLE BUFFER (POTENTIAL OVERFLOW)

    // Check if .\xfers exists
    if (GetFileAttributesA(".\\xfers") == INVALID_FILE_ATTRIBUTES)
    {
        uint64_t error_code = 0xffffffffffffffff;
        send(s, (char *)&error_code, sizeof(error_code), 0);
        return;
    }

    char full_path[MAX_PATH];
    snprintf(full_path, MAX_PATH, ".\\xfers\\%s", filename);

    FILE *fp = fopen(full_path, "rb");
    if (fp)
    {
        // Programming error: this is not the address of the file handle (within msvcrt.dll), but the address of the fp pointer.
        // Therefore, file_id is a Stack Address within this procedure's Stack Frame.
        uint64_t file_id = (uint64_t)&fp;
        printf("Sending file id = %x\n", file_id);
        send(s, (char *)&file_id, sizeof(file_id), 0);
    }
    else
    {
        uint64_t error_code = 0xffffffffffffffff;
        send(s, (char *)&error_code, sizeof(error_code), 0);
        return;
    }

    fseek(fp, 0, SEEK_END);
    uint32_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint32_t sequence_number = 0;

    while (file_size > 0)
    {
        uint32_t data_len = (file_size >= block_size) ? block_size : file_size;

        __asm("nop         \r\n");

        // Stack overflow can occur here if block_size > 1000
        size_t read_size = fread(data_buffer, 1, data_len, fp);

        if (read_size != data_len)
        {
            printf("[!] Failed to read file chunk.\n");
            break;
        }

        uint32_t header[2] = { sequence_number, data_len };

        send(s, (char *)header, sizeof(header), 0);
        send(s, (char *)data_buffer, data_len, 0);

        file_size -= data_len;
        sequence_number++;
    }

    // Send EOF marker
    uint32_t eof_header[2] = { sequence_number, 0 };
    send(s, (char *)eof_header, sizeof(eof_header), 0);

    fclose(fp);
    printf("[*] Download complete: %s\n", full_path);
}

// Client handler thread
unsigned __stdcall client_handler(void* clientSocketPtr) {
    SOCKET clientSocket = *(SOCKET*)clientSocketPtr;

    while (true)
    {
        int bytesReceived = recv(clientSocket, recvbuf, MAX_RECV_BUFFER, 0);

        if (!validate_packet(recvbuf, bytesReceived)) {
            printf("Session on socket %d terminated.\n", clientSocket);
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
