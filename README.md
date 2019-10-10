![FCG](https://avatars0.githubusercontent.com/u/26013747?s=50&v=4) Fieldcomm Group
=====================

# hipserver

Version 3.6

This server component is common to the HART-IP server applications developed by FieldComm Group.  This is the identical software used by the HART Test System and Wireless HART Test System.  New HART-IP server applications produced by FieldComm Group will also use this component.

# Known Issues

It does not pass HART-IP Test System test cases (test specification development is in progress).

It does not catch malformed Token-Passing PDU’s.

It supports UDP, but does not support TCP-IP.

Does not implement security (not included in the HART-IP spec)

# Developer Guide

![architecture](media/6cbfeb78d00cef63e4acd001176ad27f.png)



