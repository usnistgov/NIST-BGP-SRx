/**
 * This software was developed at the National Institute of Standards and
 * Technology by employees of the Federal Government in the course of
 * their official duties. Pursuant to title 17 Section 105 of the United
 * States Code this software is not subject to copyright protection and
 * is in the public domain.
 * 
 * NIST assumes no responsibility whatsoever for its use by other parties,
 * and makes no guarantees, expressed or implied, about its quality,
 * reliability, or any other characteristic.
 * 
 * We would appreciate acknowledgment if the software is used.
 * 
 * NIST ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" CONDITION AND
 * DISCLAIM ANY LIABILITY OF ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING
 * FROM THE USE OF THIS SOFTWARE.
 * 
 * 
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required 
 * by this software.
 *
 * File:   concole.h
 * Author: borchert
 *
 * Created on May 24, 2011, 8:46 PM
 */
#ifndef CONSOLE_H
#define	CONSOLE_H

#include "server/configuration.h"
#include "server/command_handler.h"
#include "server/rpki_handler.h"

/** This callback method is used to allow shutdowns */
typedef void (*ShutDownMethod)();

/** contains the information needed for the server console. */
typedef struct {
  /** The method used to communicate a shutdown request. */
  ShutDownMethod shutDown;
  
  /** The system configuration. */
  Configuration* sysConfig;
  
  /** An instance of the RPKI Handler*/
  RPKIHandler* rpkiHandler;

    /** An instance of the RPKI Handler*/
  CommandHandler* commandHandler;

  // The server socket file descriptor
  int srvSockFd;
  // The client socket file descriptor;
  int clientSockFd;
  /** The thread running the console*/
  pthread_t    consoleThread;  
  /** Indicates if the console has to be stopped. */
  bool keepGoing;
  
  /** Indicates if the client sends \n\r or just \r with each command. This
   * defines if a \n has to be generated at the beginning or not. */
  bool prependNextLine;
  
  /** Contains the command to be used. */
  char* cmd;
  /* Contains the parameters to be used. */
  char* param;
  /* The size of the command buffer. */
  int cmdBuffSize;
  /* The size of the parameter buffer. */
  int paramBuffSize;
} SRXConsole;

/**
 * Create the server console and binds to the server port.
 * @param self The Console itself.
 * @param port The server port to listen on.
 * @param sysConfig The system configuration 
 * @param shutDown The shutdown method.
 * @param rpkiHandler The instance of the rpkiHandler.
 * @param commandHandler The command handler of the application.
 * 
 * @return true if the console could be established and bound to the port.
 */
bool createConsole(SRXConsole* self, int port,  ShutDownMethod shutDown, 
                   Configuration* sysConfig, RPKIHandler* rpkiHandler, 
                   CommandHandler* commHandler);

/**
 * Stops and releases the server console.
 * 
 * @param self the server console.
 * 
 * @return ture if the server console could be stopped. 
 */
bool releaseConsole(SRXConsole* self);

#endif	/* CONSOLE_H */

