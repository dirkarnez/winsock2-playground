#ifndef UNICODE
#define UNICODE
#endif

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <schannel.h>
#include <security.h>
#include <iostream>
#include <winternl.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <iostream>

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT 80

int main() {
    //----------------------
    // Declare and initialize variables.
    int iResult;
    WSADATA wsaData;

    struct sockaddr_in clientService; 

    int recvbuflen = DEFAULT_BUFLEN;
    std::string sendbuf = "GET / HTTP/1.1\r\n\r\n";
    char recvbuf[DEFAULT_BUFLEN] = "";

    //----------------------
    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != NO_ERROR) {
        wprintf(L"WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    SCHANNEL_CRED cred = {};
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_CLIENT;
    cred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
        
    HCERTSTORE hCertStore = CertOpenSystemStore(NULL, L"MY");
    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, L"localhost", NULL);

    cred.paCred = &pCertContext;
    cred.cCreds = 1;

    
    UNICODE_STRING uStringUNISP_NAME;
    RtlInitUnicodeString(&uStringUNISP_NAME, UNISP_NAME);
    
    CredHandle credHandle;
    TimeStamp tsExpiry;
    SECURITY_STATUS statusd = AcquireCredentialsHandle(NULL, (PSECURITY_STRING)&uStringUNISP_NAME, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &credHandle, &tsExpiry);
    if (statusd != SEC_E_OK)
    {
        std::cout << "Failed to acquire credentials handle. Error code: " << statusd << std::endl;
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hCertStore, 0);
        WSACleanup();
        return 1;
    }



    //----------------------
    // Create a SOCKET for connecting to server
     SOCKET ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) {
        wprintf(L"socket failed with error: %ld\n", WSAGetLastError());
        
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hCertStore, 0);

        WSACleanup();
        return 1;
    }

    // //----------------------
    // // The sockaddr_in structure specifies the address family,
    // // IP address, and port of the server to be connected to.
    // std::string url = "google.com";
    // struct hostent *host = gethostbyname( url.c_str() );
    // clientService.sin_family = AF_INET;
    // clientService.sin_addr.s_addr = *((unsigned long *)host->h_addr);
    // clientService.sin_port = htons( DEFAULT_PORT );


    addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* result = nullptr;
    if (getaddrinfo("www.example.com", "https", &hints, &result) != 0)
    {
        std::cout << "Failed to get address info." << std::endl;
        closesocket(ConnectSocket);
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hCertStore, 0);
        WSACleanup();
        return 1;
    }

    if (connect(ConnectSocket, result->ai_addr, static_cast<int>(result->ai_addrlen)) == SOCKET_ERROR)
    {
        std::cout << "Failed to connect to server." << std::endl;
        closesocket(ConnectSocket);
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hCertStore, 0);
        WSACleanup();
        return 1;
    }

//     //----------------------
//     // Connect to server.
//     iResult = connect( ConnectSocket, (SOCKADDR*) &clientService, sizeof(clientService) );
//     if (iResult == SOCKET_ERROR) {
//         wprintf(L"connect failed with error: %d\n", WSAGetLastError() );
//         closesocket(ConnectSocket);
//         WSACleanup();
//         return 1;
//   }

    // //----------------------
    // // Send an initial buffer
    // iResult = send( ConnectSocket, sendbuf.c_str(), (int)strlen(sendbuf.c_str()), 0 );
    // if (iResult == SOCKET_ERROR) {
    //     wprintf(L"send failed with error: %d\n", WSAGetLastError());
    //     closesocket(ConnectSocket);
    //     WSACleanup();
    //     return 1;
    // }

    // printf("Bytes Sent: %d\n", iResult);

    // // shutdown the connection since no more data will be sent
    // iResult = shutdown(ConnectSocket, SD_SEND);
    // if (iResult == SOCKET_ERROR) {
    //     wprintf(L"shutdown failed with error: %d\n", WSAGetLastError());
    //     closesocket(ConnectSocket);
    //     WSACleanup();
    //     return 1;
    // }

    // // Receive until the peer closes the connection
    //  std::string website_HTML;
    //  while ((iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0)) > 0)
    //  {
    //       int i = 0;
    //       while (recvbuf[i] >= 32 || recvbuf[i] == '\n' || recvbuf[i] == '\r')
    //       {
    //            website_HTML += recvbuf[i];
    //            i += 1;
    //       }
    //  }

    //  std::cout << "->" << website_HTML << "<-" << std::endl;

    // // close the socket
    // iResult = closesocket(ConnectSocket);
    // if (iResult == SOCKET_ERROR) {
    //     wprintf(L"close failed with error: %d\n", WSAGetLastError());
    //     WSACleanup();
    //     return 1;
    // }

    // WSACleanup();


    SecBuffer outBuffers[2] = {};
    outBuffers[0].BufferType = SECBUFFER_TOKEN;
    outBuffers[0].cbBuffer = 0;
    outBuffers[0].pvBuffer = NULL;

    outBuffers[1].BufferType = SECBUFFER_EMPTY;
    outBuffers[1].cbBuffer = 0;
    outBuffers[1].pvBuffer = NULL;

    SecBufferDesc outBufferDesc = {};
    outBufferDesc.ulVersion = SECBUFFER_VERSION;
    outBufferDesc.cBuffers = 2;
    outBufferDesc.pBuffers = outBuffers;

    DWORD dwSSPIOutFlags = 0;
    TimeStamp tsExpiry;

    SecBuffer inBuffers[2] = {};
    inBuffers[0].BufferType = SECBUFFER_TOKEN;
    inBuffers[0].cbBuffer = 0;
    inBuffers[0].pvBuffer = NULL;

    inBuffers[1].BufferType = SECBUFFER_EMPTY;
    inBuffers[1].cbBuffer = 0;
    inBuffers[1].pvBuffer = NULL;

    SecBufferDesc inBufferDesc = {};
    inBufferDesc.ulVersion = SECBUFFER_VERSION;
    inBufferDesc.cBuffers = 2;
    inBufferDesc.pBuffers = inBuffers;

    SECURITY_STATUS status = SEC_E_OK;
    while (true)
    {
        if (outBuffers[1].BufferType ==SECBUFFER_EXTRA && outBuffers[1].cbBuffer != 0)
        {
            memmove(outBuffers[0].pvBuffer, outBuffers[0].pvBuffer + (outBuffers[0].cbBuffer - outBuffers[1].cbBuffer), outBuffers[1].cbBuffer);
            outBuffers[0].cbBuffer = outBuffers[1].cbBuffer;
        }
        else
        {
            outBuffers[0].cbBuffer = 0;
        }

        DWORD dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

        const wchar_t* myString = L"www.example.com";
        UNICODE_STRING uString;
        RtlInitUnicodeString(&uString, myString);
        
        status = InitializeSecurityContext(&credHandle, NULL, (PSECURITY_STRING)&uString, dwSSPIFlags, 0, SECURITY_NATIVE_DREP, &inBufferDesc, 0, NULL, &outBufferDesc, &dwSSPIOutFlags, &tsExpiry);

        if (outBuffers[0].cbBuffer != 0 && outBuffers[0].pvBuffer != NULL)
        {
            int bytesSent = send(ConnectSocket, reinterpret_cast<char*>(outBuffers[0].pvBuffer), outBuffers[0].cbBuffer, 0);
            if (bytesSent == SOCKET_ERROR)
            {
                std::cout << "Failed to send data." << std::endl;
                break;
            }

            FreeContextBuffer(outBuffers[0].pvBuffer);
            outBuffers[0].pvBuffer = NULL;
            outBuffers[0].cbBuffer = 0;
        }

        if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED || (FAILED(status) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR)))
        {
            if (inBuffers[1].BufferType == SECBUFFER_EXTRA && inBuffers[1].cbBuffer != 0)
            {
                memmove(inBuffers[0].pvBuffer, inBuffers[0].pvBuffer + (inBuffers[0].cbBuffer - inBuffers[1].cbBuffer), inBuffers[1].cbBuffer);
                inBuffers[0].cbBuffer = inBuffers[1].cbBuffer;
            }
            else
            {
                inBuffers[0].cbBuffer = 0;
            }

            int bytesReceived = recv(ConnectSocket, reinterpret_cast<char*>(inBuffers[0].pvBuffer), inBuffers[0].cbBuffer, 0);
            if (bytesReceived == SOCKET_ERROR || bytesReceived == 0)
            {
                break;
            }

            inBuffers[0].cbBuffer = bytesReceived;

            inBuffers[1].BufferType = SECBUFFER_EMPTY;
            inBuffers[1].cbBuffer = 0;
            inBuffers[1].pvBuffer = NULL;
        }

        if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED)
        {
            break;
        }
    }

    if (status == SEC_E_OK)
    {
        std::cout << "Handshake successful." << std::endl;
    }
    else
    {
        std::cout << "Handshake failed. Error code: " << status << std::endl;
    }

std::string request = "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n";
    int bytesSent = send(ConnectSocket, request.c_str(), request.length(), 0);
    if (bytesSent == SOCKET_ERROR)
    {
        std::cout << "Failed to send request." << std::endl;
        FreeCredentialsHandle(&credHandle);
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hCertStore, 0);
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

char response[1024] = {};
    int bytesReceived = 0;
    while ((bytesReceived = recv(ConnectSocket, response, sizeof(response), 0)) > 0)
    {
        std::cout << response;
        ZeroMemory(response, sizeof(response));
    }

    if (bytesReceived == SOCKET_ERROR)
    {
        std::cout << "Failed to receive response." << std::endl;
    }
FreeCredentialsHandle(&credHandle);
    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hCertStore, 0);
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}
