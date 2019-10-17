# README

## ![FCG](https://avatars0.githubusercontent.com/u/26013747?s=50&v=4) FieldComm Group

**hipserver** is one component of the [HART-IP Developer Kit](https://github.com/FieldCommGroup/HART-IP-Developer-Kit/blob/master/doc/HART-IP%20FlowDevice%20Spec.md). It manages HART-IP connections with client programs and also with the companion [**hipflowapp** ](https://github.com/FieldCommGroup/hipflowapp)component, which implements the flow device functionality.

This component is common to the HART-IP server applications developed by FieldComm Group. It is the identical software used in the HART Test System and Wireless HART Test System. Future HART-IP server applications produced by FieldComm Group will also use this component.

## Known Issues

It does not pass HART-IP Test System test cases, as there is not a released test specification for HART-IP devices.  However, that specification is in development and the HART Test System will be enhanced to include these tests.

It does not catch malformed Token-Passing PDU’s \(planned\).

It supports UDP/IP, but does not support TCP/IP \(planned\).

It does not implement security.  Security is not included in the HART-IP specification, but is currently being considered.  For now, security is the responsibility of the system integrator.

## Developer Guide

Read below to learn how to build and modify this component.

### Architecture

**hipserver** is the client-facing component program that manages IP connections with HART-IP client \(or host\) programs. It manages:

* HART-IP connections with up to three clients
* Published message subscriptions for the clients
* Publishing burst messages to subscribed clients
* Checking HART-IP and HART message framing
* Sending and receiving HART Token-passing messages with a companion server application component program, **hipflowapp**, described [here](https://github.com/FieldCommGroup/HART-IP-Developer-Kit/blob/master/doc/HART-IP%20FlowDevice%20Spec.md).

The following diagram shows how the **hipserver** is related to the other components.

![Flow Device Components](.gitbook/assets/flowcomponent.png)

Together, these two components form a HART-IP Flow Device. With this architecture, it is easy to change out one app component with another to get a completely different server application. Here are some examples:

* a pass-through to a wired HART device,
* a device simulator, or 
* access to an IO System or Gateway.

### Repository Contents

The repository contains four folders:

* Server
* AppConnect
* Common
* Realtime

#### **Server** 

This folder contains the main program and functions for managing HART-IP connections and the App program connection.

It includes a _make_ based build system in files Makefile\*. To build **hipserver**, cd to this folder and type 'make'.

| File | Contents |
| :--- | :--- |
| .cproject,.project | Eclipse CDT Oxygen project settings |
| debug.h | \#defines provide expanded logging output if desired |
| Makefile | Provides rules for 'all' and 'clean'  |
| Makefile.inc | Included in Makefile, specifies source files to be built |
| Makefile\_macros.inc | Included in Makefile, specifies compile and link flags |
| hsqueues.cpp,.h | Create and manage POSIX message queues for communicating with the App component |
| hsrequest.cpp,.h | Track request PDU's received from each client |
| hssems.cpp,.h | Manage semaphores used  |
| hssigs.cpp,.h | Manage signals used |
| hssubscribe.cpp,.h | Keeps a subscription table of which clients have subscribed to what messages |
| hsthreads.cpp,.h | Manage the threads used |
| hsudp.cpp,.h | Socket management, receive and reply to HART-IP messages, route messages |

#### **AppConnect**

This folder is library code that is used by the **hipserver** and shared with the app components.

| Files | Contents |
| :--- | :--- |
| app.cpp,.h | Contains the App base class for all App components.  Each App must have a subclass that implements the virtual functions defined |
| appconnector.h | This template class contains the message pump and calls the App object to dispatch and receive messages |
| appmsg.h | Defines the message structure of messages passed between hipserver and the app |
| apppdu.cpp,.h | Provide convenient access to the data inside an AppMsg |
| tpdll.h | Symbolic constants required to parse a HART message PDU |
| tppdu.cpp,.h | Methods in this lightweight class are used to parse a HART message |

#### **Common**

Files in this library older contain data type definitions, symbolic constants and enumerated types common to HART-IP server implementations.

#### Realtime

This component also contains library code that is used by the **hipserver** and available for use by the app components for: POSIX mqueues, semaphores, signals and threads.

