/*************************************************************************************************
 * Copyright 2019-2021 FieldComm Group, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************/

#include "hssyslogger.h"
#include "hsauditlog.h"
#include <iostream>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/socket.h>  
#include <ctime>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <netdb.h>
#include "debug.h"
#include <limits.h>
#include <ifaddrs.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include "hssettings.h"
#ifdef OPEN_SSL_SUPPORT
#include <openssl/tls1.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define DEFAULT_SECURE_PORT 6514
#define DEFAULT_INSECURE_PORT 514

unsigned short gl_Manufacturer = 0;
unsigned short gl_ExtendedDeviceType = 0;
char gl_DeviceRevision = 0;
unsigned int gl_DeviceID = 0;
std::string gl_sServerIPv4;
std::string gl_sServerIPv6;

#ifdef OPEN_SSL_SUPPORT
SSL_CTX *g_SSL_context = NULL;
#define IDENTITY_SYSLOG "HARTIPSYSLOG"
#define PSK_IDENTITY "HARTIPSYSLOG"
#endif


struct ConnectionToSyslog
{
#ifdef OPEN_SSL_SUPPORT
    SSL* m_sslConnection;
#endif
    std::string m_hostname;
    int m_port;
    int m_socket;
    bool m_connected;
    sockaddr_in_t m_addres;
    std::string m_PreSharedKey;
    std::string m_Password;
    MutexEx m_mutex;
} g_connectionToSyslog;

int writeMessage(char* buff, int size)
{
    if(g_connectionToSyslog.m_connected == false)
    {
        return 0;
    }
#ifdef OPEN_SSL_SUPPORT
    if(g_connectionToSyslog.m_sslConnection != NULL)
    {
        return SSL_write(g_connectionToSyslog.m_sslConnection, buff, size);
    }
    else
    {
#endif
        socklen_t len = sizeof( g_connectionToSyslog.m_addres);
        return sendto(g_connectionToSyslog.m_socket, buff, size, 0, (sockaddr*)&g_connectionToSyslog.m_addres, len);
#ifdef OPEN_SSL_SUPPORT
    }
#endif    
}

#ifdef OPEN_SSL_SUPPORT
unsigned int SSL_psk_client_cb(SSL *ssl,
                                                const char *hint,
                                                char *identity,
                                                unsigned int max_identity_len,
                                                unsigned char *psk,
                                                unsigned int max_psk_len)
{
    if(g_connectionToSyslog.m_PreSharedKey.empty())
        return 0;

    strcpy_s(identity, max_identity_len, PSK_IDENTITY);
    int idx = 0;
    for(int i = 0; i < g_connectionToSyslog.m_PreSharedKey.length(); i+=2)
    {
        unsigned char val1 = g_connectionToSyslog.m_PreSharedKey[i] - '0';
        val1 = val1 >= 0 && val1 <= 9 ? val1 : g_connectionToSyslog.m_PreSharedKey[i] - 'a' + 10;
        unsigned char val2 = g_connectionToSyslog.m_PreSharedKey[i+1] - '0';
        val2 = val2 >= 0 && val2 <= 9 ? val2 : g_connectionToSyslog.m_PreSharedKey[i+1] - 'a' + 10;
        unsigned char valRes = (val1 << 4 & 0xF0) + (val2 & 0x0F);
        psk[idx++] = valRes;

    }
    return idx;
} 
#endif

void log(int priority, int status, const char* date, const char* host, int manufacturer, int extendedDeviceType, char deviceRevision, int eventId, const char* desc, int severity, unsigned int deviceID, const char* ipv4)
{
    if (g_connectionToSyslog.m_connected == false)
    {
        return;
    }
    char logSendBuffer[2048];
    sprintf_s(logSendBuffer, sizeof(logSendBuffer) - 1, " <%d> %s %s |%X|%X|%X|%d|%s|%d|DeviceID=%X src=%s c6a2=%s %s%s\n\x00", priority, date, host, 
	manufacturer, extendedDeviceType, (int)deviceRevision, eventId, desc, severity, deviceID, gl_sServerIPv4.c_str(), gl_sServerIPv6.c_str(), ipv4 ? "dst=" : "", ipv4 ? ipv4 : "");
    int sendCount = strnlen_s(logSendBuffer, sizeof(logSendBuffer));
    writeMessage(logSendBuffer, sendCount);
}

void log(int priority, int eventId, int severity, HARTIPConnection* conn, const char* szData)
{
    if (g_connectionToSyslog.m_connected == false)
    {
        return;
    }

    struct timeval tv;
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[64], buf[64];
    gettimeofday(&tv, NULL);
    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%dT%02H:%02M:%02S", nowtm);
    sprintf_s(buf, sizeof(buf), "%s.%03ldZ", tmbuf, tv.tv_usec/1000);
    log(priority, 0, buf, Settings::Instance()->GetHostName().c_str(), gl_Manufacturer, gl_ExtendedDeviceType, gl_DeviceRevision, eventId, szData, severity, gl_DeviceID, conn ? conn->GetSessionIPv4() : NULL);
}

bool initHipSyslogger(const char* pathToCaFile)
{
#ifdef OPEN_SSL_SUPPORT
    g_connectionToSyslog.m_sslConnection = NULL;
#endif
    g_connectionToSyslog.m_port = 0;
    g_connectionToSyslog.m_socket = LINUX_ERROR;
    g_connectionToSyslog.m_connected = false;
    memset_s(&g_connectionToSyslog.m_addres, sizeof(sockaddr_in_t), 0);

#ifdef OPEN_SSL_SUPPORT
    SSL_load_error_strings();
    SSL_library_init();
#endif

{
	struct ifaddrs* ifAddrStruct = NULL;
	struct ifaddrs* ifa = NULL;
	void* tmpAddrPtr = NULL;

	getifaddrs(&ifAddrStruct);

	for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (!ifa->ifa_addr)
		{
			continue;
		}

		if (ifa->ifa_addr->sa_family == AF_INET && gl_sServerIPv4.empty())
		{
			tmpAddrPtr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
			char addressBuffer[INET_ADDRSTRLEN + 1];
			inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
			gl_sServerIPv4 = addressBuffer;
			if (gl_sServerIPv4 == "127.0.0.1")
                gl_sServerIPv4 = "";
		}
		else if (ifa->ifa_addr->sa_family == AF_INET6)
		{
			tmpAddrPtr = &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
			char addressBuffer[INET6_ADDRSTRLEN + 1];
			inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
			gl_sServerIPv6 = addressBuffer;
		}
	}

	if (ifAddrStruct != NULL)
	{
		freeifaddrs(ifAddrStruct);
	}
}

#ifdef OPEN_SSL_SUPPORT
    const SSL_METHOD *method = TLSv1_2_client_method(); /* Create new client-method instance */
    g_SSL_context = SSL_CTX_new(method);

    if (g_SSL_context == NULL)
    {
        return false;
    }

    if(1 != SSL_CTX_use_certificate_file(g_SSL_context, pathToCaFile, X509_FILETYPE_PEM))
    {
        dbgp_log("%s\n", ERR_error_string(ERR_get_error(), NULL));
        destroyHipSyslogger();
        return false;
    }
    
    if(SSL_CTX_set_srp_username(g_SSL_context, IDENTITY_SYSLOG) != 1)
    {
        dbgp_log("%s\n", ERR_error_string(ERR_get_error(), NULL));
    }
    SSL_CTX_set_psk_client_callback(g_SSL_context, SSL_psk_client_cb);

#endif
    return true;
}

void setPortToHipSyslogger(int port)
{
    {
        MutexScopeLock(g_connectionToSyslog.m_mutex);
        if(g_connectionToSyslog.m_port == port)
        {
            return;
        }
        g_connectionToSyslog.m_port = port;
        
    }
    disconnectFromSyslog();
    connect2HipSyslogger();
}

void setHostnameToHipSyslogger(const char* host)
{
    {
        MutexScopeLock(g_connectionToSyslog.m_mutex);
        if(strcmp(g_connectionToSyslog.m_hostname.c_str(), host) == 0)
        {
            return;
        }
        g_connectionToSyslog.m_hostname = host;
        
    }
    disconnectFromSyslog();
    connect2HipSyslogger();
}

void setPreSharedKeyToHipSyslogger(const char* keyValue)
{
    {
        MutexScopeLock(g_connectionToSyslog.m_mutex);
#ifdef OPEN_SSL_SUPPORT
        unsigned char psk[256];
        std::string psks = keyValue;
        if(strcmp(g_connectionToSyslog.m_PreSharedKey.c_str(), keyValue)==0)
        {
            return;
        }

        if(g_SSL_context != NULL)
        {
            if(SSL_CTX_set_cipher_list(g_SSL_context, PSK_CIPHER_SUITES) != 1)
            {
                dbgp_log("%s\n", ERR_error_string(ERR_get_error(), NULL));
            }
            
        }
#endif

        g_connectionToSyslog.m_Password.clear();
        g_connectionToSyslog.m_PreSharedKey = keyValue;
    }
    disconnectFromSyslog();
    connect2HipSyslogger();
    AuditLogger->UpdateSecurituChange();
}

void setPasswordToHipSyslogger(const char* keyValue)
{
    {
        MutexScopeLock lock(g_connectionToSyslog.m_mutex);

        if(strcmp(g_connectionToSyslog.m_Password.c_str(), keyValue) == 0)
        {
            return;
        }
        g_connectionToSyslog.m_Password = keyValue;
#ifdef OPEN_SSL_SUPPORT
        if(g_SSL_context != NULL)
        {
            if(SSL_CTX_set_srp_password(g_SSL_context, &g_connectionToSyslog.m_Password[0]) != 1)
            {
                dbgp_log("%s\n", ERR_error_string(ERR_get_error(), NULL));
                return;
            }
            if(SSL_CTX_set_cipher_list(g_SSL_context, PASSWORD_CIPHER_SUITES) != 1)
            {
                dbgp_log("%s\n", ERR_error_string(ERR_get_error(), NULL));
            }
        } 
#endif
        
        g_connectionToSyslog.m_PreSharedKey.clear();
    }

    disconnectFromSyslog();
    connect2HipSyslogger();
    AuditLogger->UpdateSecurituChange();
}

void log2HipSyslogger(int priority, int eventId, int severity, HARTIPConnection* conn, const char* format, ...)
{
    MutexScopeLock lock(g_connectionToSyslog.m_mutex);
    char logInBuffer[1024];
    va_list argptr;
    va_start(argptr, format);
    vsnprintf(logInBuffer, sizeof(logInBuffer) - 1, format, argptr);
    va_end(argptr);
    log(priority, eventId, severity, conn, logInBuffer);
}

int getPortToHipSyslogger()
{
    return g_connectionToSyslog.m_port;
}

void getHostnameToHipSyslogger(char* inBuffer, int maxInBuffer)
{
    MutexScopeLock(g_connectionToSyslog.m_mutex);
    strncpy_s(inBuffer, maxInBuffer, g_connectionToSyslog.m_hostname.c_str(), maxInBuffer);
}


void getPreSharedKeyToHipSyslogger(char* inBuffer, int maxInBuffer)
{
    MutexScopeLock lock(g_connectionToSyslog.m_mutex);
    strncpy_s(inBuffer, maxInBuffer, g_connectionToSyslog.m_PreSharedKey.c_str(), maxInBuffer);
}

void getPasswordToHipSyslogger(char* inBuffer, int maxInBuffer)
{
    MutexScopeLock lock(g_connectionToSyslog.m_mutex);
    strncpy_s(inBuffer, maxInBuffer, g_connectionToSyslog.m_Password.c_str(), maxInBuffer);
}

void log2HipSyslogger(int priority, int status, char* date, char* host, int manufacturer, int extendedDeviceType, char deviceRevision, int eventId,  char* desc, int severity, unsigned int deviceID, const char* ipv4)
{
   MutexScopeLock lock(g_connectionToSyslog.m_mutex);
   log(priority, status, date, host, manufacturer, extendedDeviceType, deviceRevision, eventId, desc, severity, deviceID, ipv4);
}

int connectToServer(const char* hostname, int port, sockaddr_in_t *addr_out, int protocol, int socktype)
{
    if(hostname == NULL)
    {
        return LINUX_ERROR;
    }
    struct hostent *host;

    if ((host = gethostbyname2(hostname, AF_INET)) == NULL)
    {
        perror(hostname);
        return LINUX_ERROR;
    }

    struct addrinfo hints = {0}, *addrs;
    hints.ai_family = AF_INET;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;
    
    char portString[6];
    // vulnerability check by inspection is OK:  this method is not accessible by the client  --  tjohnston 11/09/2021
    sprintf(portString, "%d", port);
    const int status = getaddrinfo(hostname, portString, &hints, &addrs);
    if (status != 0)
    {
        fprintf(stderr, "%s: %s\n", hostname, gai_strerror(status));
        return LINUX_ERROR;
    }

    int socket_fd, err;
    for (struct addrinfo *addr = addrs; addr != NULL; addr = addr->ai_next)
    {
        socket_fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (socket_fd == LINUX_ERROR)
        {
            err = errno;
            continue;
        }

        if (connect(socket_fd, addr->ai_addr, addr->ai_addrlen) == 0)
        {
            memcpy_s(addr_out, sizeof(sockaddr_in_t), addr->ai_addr, sizeof(sockaddr_in_t));
            break;
        }

        err = errno;
        socket_fd = LINUX_ERROR;
        close(socket_fd);
    }

    freeaddrinfo(addrs);
    return socket_fd;
}

#ifdef OPEN_SSL_SUPPORT
SSL* setSecureConnection(int socket_fd)
{
    SSL* SSLconnection = NULL;
    if(g_SSL_context != NULL)
    {
        SSLconnection = SSL_new(g_SSL_context);
        
        if(SSLconnection != NULL)
        {
            struct timeval oldVal;
            memset_s(&oldVal, sizeof(oldVal), 0);
            socklen_t sizetv = sizeof(oldVal);
            getsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &oldVal, &sizetv);
            
            struct timeval tv;  // reducing timeout for the error case
            tv.tv_sec = 5;
            tv.tv_usec = 0;
            setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            SSL_set_fd(SSLconnection, socket_fd);
            int ret = 0;


            if((ret = SSL_connect(SSLconnection)) != 1)
            {
                dbgp_log("Error connect to Syslog Server via TLS%s\n", ERR_error_string(SSL_get_error(SSLconnection, ret), NULL));
                SSL_free(SSLconnection);
                SSLconnection = NULL;
            }
            setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &oldVal, sizeof(oldVal));
        }
        else
        {
            dbgp_log("%s\n", ERR_error_string(ERR_get_error(), NULL));
        }
    }
    return SSLconnection;
}
#endif

void disconnectFromSyslog()
{
    MutexScopeLock lock(g_connectionToSyslog.m_mutex); 
    if(g_connectionToSyslog.m_connected == false)
    {
        return;
    }
#ifdef OPEN_SSL_SUPPORT
    if(g_connectionToSyslog.m_sslConnection != NULL)
    {
        SSL_shutdown(g_connectionToSyslog.m_sslConnection);
        SSL_free(g_connectionToSyslog.m_sslConnection);
        g_connectionToSyslog.m_sslConnection = NULL;
    }
#endif
    if(g_connectionToSyslog.m_socket)
    {
        shutdown(g_connectionToSyslog.m_socket, SHUT_RDWR);
        close(g_connectionToSyslog.m_socket);
        g_connectionToSyslog.m_socket = LINUX_ERROR;
    }

    g_connectionToSyslog.m_connected = false;
}

void destroyHipSyslogger()
{
#ifdef OPEN_SSL_SUPPORT
    if(g_SSL_context != NULL)
    {
        SSL_CTX_free(g_SSL_context);
        g_SSL_context = NULL;
    }
#endif
} 

void connect2HipSyslogger()
{
    MutexScopeLock lock(g_connectionToSyslog.m_mutex);

    if(g_connectionToSyslog.m_connected == true || g_connectionToSyslog.m_hostname.empty() ||  g_connectionToSyslog.m_port <= 0)
    {   
        if(g_connectionToSyslog.m_connected == false)
        {
            AuditLogger->SetStatusSyslogServer(UnableToLocateSyslogServer);
        }
        return;
    }
    AuditLogger->SetStatusSyslogServer(UnableToLocateSyslogServer, FALSE);
    int port = g_connectionToSyslog.m_port;
    int socket_fd = LINUX_ERROR;
    bool connected = false;

#ifdef OPEN_SSL_SUPPORT

    SSL* SSLconnection = NULL;

    if(!(g_connectionToSyslog.m_Password.empty() && g_connectionToSyslog.m_PreSharedKey[0] == 0))
    {
        socket_fd = connectToServer(g_connectionToSyslog.m_hostname.c_str(), g_connectionToSyslog.m_port, &g_connectionToSyslog.m_addres, IPPROTO_TCP, SOCK_STREAM);

        if (socket_fd == LINUX_ERROR && port != DEFAULT_SECURE_PORT)
        {
            port = DEFAULT_SECURE_PORT;
            socket_fd = connectToServer(g_connectionToSyslog.m_hostname.c_str(), port, &g_connectionToSyslog.m_addres, IPPROTO_TCP, SOCK_STREAM);//connect too server
        }

        if(socket_fd != LINUX_ERROR)
        {
            SSLconnection = setSecureConnection(socket_fd);
        }
    }
    if(SSLconnection == NULL)
    {
        if(socket_fd != LINUX_ERROR)
        {
            close(socket_fd);
            socket_fd = LINUX_ERROR;
        }
#endif
        port = DEFAULT_INSECURE_PORT;
        socket_fd = connectToServer(g_connectionToSyslog.m_hostname.c_str(), port, &g_connectionToSyslog.m_addres, IPPROTO_UDP, SOCK_DGRAM);
#ifdef OPEN_SSL_SUPPORT 
    }
#endif
    
    if(socket_fd != LINUX_ERROR)
    {
        connected = true;

        g_connectionToSyslog.m_connected = true;
        g_connectionToSyslog.m_socket = socket_fd;
#ifdef OPEN_SSL_SUPPORT
        g_connectionToSyslog.m_sslConnection = SSLconnection;



        if(g_connectionToSyslog.m_sslConnection == NULL)
        {
            dbgp_log("\nConnect to syslog without TLS\n");
#endif
            AuditLogger->SetStatusSyslogServer(InsecureSyslogConnection);
#ifdef OPEN_SSL_SUPPORT
        }
        else
        {
            dbgp_log("\nConnect to syslog via TLS\n");
            AuditLogger->SetStatusSyslogServer(InsecureSyslogConnection, FALSE);
        }
#endif
        AuditLogger->SetStatusSyslogServer(SyslogServerConnectionFailed, FALSE);
    }
    else
    {
        AuditLogger->SetStatusSyslogServer(SyslogServerConnectionFailed);
        dbgp_log("\nConnect to syslog fail\n");
    }
    return;
}

const char* getServerIPv4()
{
	return gl_sServerIPv4.c_str();
}

void setDeviceIdentification(unsigned short manufacturer, unsigned short extendedDeviceType, unsigned char deviceRevision, unsigned int deviceID )
{
    gl_Manufacturer = manufacturer;
    gl_ExtendedDeviceType = extendedDeviceType;
    gl_DeviceRevision = deviceRevision;
    gl_DeviceID = deviceID;
}
