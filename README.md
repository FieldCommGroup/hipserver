# README

## ![FCG](https://avatars0.githubusercontent.com/u/26013747?s=50&v=4) FieldComm Group

## hipserver

**hipserver** is one component of the HART-IP Developer Kit. For more information on the kit and its other components, see [here](https://github.com/FieldCommGroup/HART-IP-Developer-Kit) .

This server component is common to the HART-IP server applications developed by FieldComm Group. It is the identical software used by the HART Test System and Wireless HART Test System. New HART-IP server applications produced by FieldComm Group will also use this component.

### Known Issues

It does not pass HART-IP Test System test cases \(test specification development is in progress\).

It does not catch malformed Token-Passing PDU’s.

It supports UDP, but does not support TCP-IP.

It does not implement security \(not included in the HART-IP spec\)

### Developer Guide

Read here to learn how to build and modify this component.

#### Architecture

**hipserver** is the client-facing component program that manages IP connections with HART-IP client \(or host\) programs. It manages:

* HART-IP connections with up to three clients
* Published message subscriptions for the clients
* Publishing burst messages to subscribed clients
* Checking HART-IP and HART message framing
* Sending and receiving HART Token-passing messages with a companion server application component program, hipflowapp, described [here](https://github.com/FieldCommGroup/hipflowapp).

The following diagram shows how the hipserver is related to the other components.

![Flow Device Components](.gitbook/assets/flowcomponent.png)

Together, these two components form a HART-IP Flow Device. With this architecture, it is easy to change out one app component with another to get a completely different server application. Here are some examples:

* a pass-through to a wired HART device,
* a device simulator, or 
* access to an IO System or Gateway.

#### Repository Contents

Pull a copy of the repository using tag Kit\_1\_0. It contains four folders, as follows:

**Server T**his folder contains the main program and functions for managing HART-IP connections and the App program connection.

It includes a _make_ based build system in files Makefile\*. To build hipserver, cd to this folder and type 'make'.

**AppConnect**

makefiles

#### HART-IP Functions

hsudp

hssubscribe

#### App Communication

This component also contains library code that is used by the

#### Library Functions

semaphores message queues threading

