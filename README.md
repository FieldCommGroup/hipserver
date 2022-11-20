# README

## ![FCG](https://avatars0.githubusercontent.com/u/26013747?s=50&v=4) FieldComm Group

## hipserver

**hipserver** is one component of the [HART-IP Developer Kit](https://github.com/FieldCommGroup/HART-IP-Developer-Kit). It manages HART-IP connections with client programs and also with the companion [**hipflowapp** ](https://github.com/FieldCommGroup/hipflowapp)component, which implements the flow device functionality.

This component is common to the HART-IP server applications developed by FieldComm Group. It is the identical software used in the HART Test System and Wireless HART Test System. Future HART-IP server applications produced by FieldComm Group will also use this component.

## Known Issues

It does not pass HART-IP Test System test cases, as there is not a released test specification for HART-IP devices.  However, that specification is in development and the HART Test System will be enhanced to include these tests.

It does not check for malformed Token-Passing PDU’s.

The Pi computer is configured for DHCP.  You will want to configure it for a static address for any production use.

It must be launched from a command line.  For production usage, it should be installed as a Linux system service instead.

It does not implement security.  Security is required by the HART-IP specification, but specific security is not defined.  For now, security is the responsibility of the system integrator.

## User Guide

Pull from the repository and build using the bash terminal:

```text
  git clone https://github.com/FieldCommGroup/hipserver
  cd hipserver/hipserver/Server/
  make
```

To launch the **hipserver**, the command line is:

```text
hipserver -v -h -p <port num> -c <client count> -C <pathToCA> -f <pathToSF> -r <pathToReadOnlyCommandsFile> <app command line>
```

where:

-v print version number and quit

-h print help text and quit

-p &lt;num&gt; specifies the port number to the app program.  The well-known default is 5094.  To operate two servers side-by-side, you will want to specify a separate port number for one of them.

-c &lt;count&gt; maximum number of clients that can connect to the server. Default is 5 clients.

-C &lt;pathToCA&gt; path to certificate file that use for secure connection via tls.

-f &lt;pathToSF&gt; path to settings file that will be loaded after start of hipserver.

-r &lt;pathToReadOnlyCommandsFile&gt; path to read only commands json file. File contains list of commands and ranges of commands which can be executed in read-only mode.

&lt;app command line&gt; is a bash command line, with options, used to launch the companion app program.  This argument is optional, as described below.

To terminate the server, type Ctrl-C on the command line.

**hipserver** always executes with a companion app program, **hipflowapp** in this case.  The everyday method to launch the server is:

```text
sudo ./hipserver -C "myCert.pem" ./hipflowapp
```

In this case, the **hipserver** will launch itself with secure connection to syslog server, then the **hipflowapp**.  Elevated privileges are required for **hipflowapp**, hence launching the server with sudo.

## Developer Guide

Read below to learn how to build and modify this component.

### Architecture

**hipserver** is the client-facing component program that manages IP connections with HART-IP client \(or host\) programs. It manages:

* HART-IP connections with up to five clients (default, could be defined during startup)
* Published message subscriptions for the clients
* Publishing burst messages to subscribed clients
* Checking HART-IP and HART message framing
* Sending and receiving HART Token-passing messages with a companion server application component program, **hipflowapp**, described [here](https://github.com/FieldCommGroup/hipflowapp).
* Provide audit log information based on HART-IP messages
* Provide system information to a syslog server

The following diagram shows how the **hipserver** is related to the other components.

![Flow Device Components](.gitbook/assets/flowcomponent.png)


Together, these two components form a HART-IP Flow Device. With this architecture, it is easy to change out one app component with another to get a completely different server application. Here are some examples:

* a pass-through to a wired HART device,
* a device simulator, or 
* access to an IO System or Gateway.

#### Additional libraries

**hipserver** uses libconfig library to save and load settings. You can install library with the command in terminal:
```text
sudo apt-get install -y libssl-dev
```

**hipserver** uses libjsoncpp library to read commands listed in readonly.json file. You can install library with the command in terminal:
```text
sudo apt-get install libjsoncpp-dev
```

**hipserver** uses network-manager to update hostname in the DNS record after a hostname change. You can install library with the command in terminal:
```text
sudo apt-get install network-manager
```

### Syslog

#### Compilation

Syslog can be compile with secure connection via tls or without. If you need compile with secure connection you should set value **'openssl'** to **CRYPTO_LIB** variable in the *Makefile_macros.inc*.

If you want compile without a secure connection, you must remove the value of the **CRYPTO_LIB** variable.


#### Set Connection to Syslog Server

**Hipserver** needs to start with option "-C" to provide certificate for openssl library.
For testing purpose it is possible to create selfsigned certificate by using openssl library.

```text
openssl req -x509 -newkey rsa:4096 -keyout myKey.pem -out myCert.pem -days 365
```

**Hipserver** will connect to the syslog server when a client send a hostname and a port of the syslog server. Commands 544 and 545 set the hostname and port for the syslog server. In this case, a connection is established between **hipserver** and *syslog server*. This connection will be insecure via UPD. 
**Hipserver** will attempt to establish a secure connection when a client sets PreSharedKey or PAKE password using commands 546 and 547. If a secure connection could not be established, then **hipserver** will use a insecure connection.

For information about commands 544-547 look HCF_SPEC-151 Revision 12.0.

#### Syslog control message

A companion app program may send syslog control message to the **Hipserver**. **Hipserver** writes this message to the syslog server. 
This message is based on HART Token-passing messages and is defined as fixed message. Below discription of fields:

![The fields of syslog control message](.gitbook/assets/syslog_message.png)

### Repository Contents

All code compiles with g++ version 7.4. 

It includes a _make_ based build system in files named Makefile\*. To build **hipserver**, move to this folder and type 'make'.  The executable output file lands in this folder and is named **hipserver**.

The repository contains five folders:

* Server
* AppConnect
* Common
* Realtime
* [safestringlib](https://github.com/intel/safestringlib)

#### Server

This folder contains the main program and functions for managing HART-IP connections and the App program connection.

Some interesting files in this folder are described in the following table.

| File | Contents |
| :--- | :--- |
| .cproject,.project | Eclipse CDT Oxygen project settings |
| debug.h | \#defines provide expanded logging output if desired |
| Makefile | Provides rules for 'all' and 'clean'  |
| Makefile.inc | Included in Makefile, specifies source files to be built |
| Makefile\_macros.inc | Included in Makefile, specifies compile and link flags |
| hsqueues.cpp,.h | Create and manage POSIX message queues for communicating with the App component |
| hsrequest.cpp,.h | Track request PDU's received from each client |
| hscommands.cpp, .h| Handles all HART-IP message requests for Token-Passing and DirectMessages |
| hssems.cpp,.h | Manage semaphores used  |
| hssigs.cpp,.h | Manage signals used |
| hssubscribe.cpp,.h | Keeps a subscription table of which clients have subscribed to what messages |
| hsthreads.cpp,.h | Manage the threads used |
| hsudp.cpp,.h | Socket management, receive and reply to HART-IP messages|
| onetcpprocessor.cpp, .h | Manage one TCP connection to receive and reply to HART-IP messges |
| tcpprocessor.cpp, .h | Manage all TCP connections, new TCP connection request create a new onetcpprocessor |
| hsauditlog.cpp, .h | Manage all audit logging information |
| hssyslogger.cpp, .h | Manage the connection to syslog server and handle syslog event creation |

#### AppConnect
This library code is shared with HART-IP server App programs, such as **hipflowapp**.  The contained classes specify what data is communicated via POSIX message queues between the **hipserver** and **hipflowapp**.

| File | Contents |
| :--- | :--- |
| app.cpp.,h | Contains the App class, which is the parent class for all Apps that communicate with **hipserver**.  The virtual methods in this class should be implemented by each App's sub-class. |
| appconnector.h | This is a template class that defines the message pump for all Apps. |
| appmsg.cpp,.h | This class defines the data that is passed between **hipserver** and its Apps. |
| apppdu.cpp,.h | This class provides convenient access to the message contents. |
| tppdu.cpp,.h | This lightweight class parses TokenPassing PDU's. |
| tpdll.h | Symbolic constants used to parse HART message frames. |


#### Common
This folder contains headers defining data types, error values and other enumeration types.

#### Realtime
This folder contains library code for managing signals, semaphores, threads and POSIX message queues.
#### safestringlib
This folder contains an adapted version of Intel's library from GitHub.  See the README file in that folder for more information.






