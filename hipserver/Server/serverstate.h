/*
 * serverstate.h
 *
 *  Created on: Apr 4, 2018
 *      Author: user1
 */

#ifndef SERVERSTATE_H_
#define SERVERSTATE_H_

/*
 * These state variables describe the internal state of the server.
 *
 * Notes:
 * The HART-IP server works in parallel with a "APP program" which
 * emulates a HART token-passing device.  It consumes HART requests
 * replies with HART responses through Posix mqueues.
 *
 * The server may launch in two different ways:
 *
 * - standard operation: the hart-ip server's command-line arguments
 * 		*are* the command line for the APP program.  After the server
 * 		launches, it spawns the APP process using the command line.
 * 		When the server is terminating, it messages the APP to quit
 * 		and waits for it to terminate before terminating itself.
 * 		example:
 * 			$ hipserver hip_native_demo
 *
 * 	- developer *debugging* operation: APP developer launches the
 * 		hart-ip server using the command line with no embedded APP
 * 		command line.   The server runs to the point that it pends
 * 		waiting a response from the APP to the INIT message.
 * 		then developer can start the  APP up using a development environment
 * 		and debug the application.
 * 		example:
 * 			$ hipserver
 * 			$ <launch developer IDE here>
 *
 * 		the APP must launch after the server, as the server owns the mqueues.
 *
 */


enum ServerState
{
	SRVR_INIT, 	// starting up threads, signals, semaphores
	SRVR_READY,	// all sub-systems are running
	SRVR_TERM 	// orderly shutdown operations
};

// this state maintained by the APP thread in the server
enum AppState
{
	APP_STOP,	// initial state, the APP is not executing, but may be started again
	APP_RUN,	// the APP executable is started, but not answered INIT message
	APP_READY,	// APP has responded positively to INIT control message
	APP_TERM 	// APP thread is has exited.
};

enum AppLaunch
{
	LNCH_AUTO,	// APP command line is supplied and launched automatically.
	LNCH_MANUAL	// APP is launched manually by the user
};

extern enum ServerState 	eServerState;
extern enum AppState 	eAppState;
extern enum AppLaunch 	eAppLaunch;

#endif /* SERVERSTATE_H_ */
