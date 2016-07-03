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
 * Provides the BGP Final State Machine
 * 
 * @version 0.2.0.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.0 - 2016/05/17 - oborchert
 *            * Added receiver thread to session structure. This allows to 
 *              send signals to the thread if needed.
 *          - 2016/05/06 - oborchert
 *            * Fixed FSM problem during failed connections. (BZ: 924)
 *            * Renamed function call _shutDownTCPSession into 
 *              shutDownTCPSession
 *  0.1.0.0 - 2015/08/15 - oborchert
 *            * Created File.
 */
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bits/signum.h>
#include "bgp/BGPFinalStateMachine.h"
#include "bgp/BGPSession.h"

/**
 * Verifies that the given state has only one (known) bit set.
 * 
 * @param state the state to be checked
 * 
 * @return true if only one bit is set otherwise false. 
 */
bool _isSingleState(int state)
{
  // verify only one bit is set.
  switch (state)
  {
    case FSM_STATE_IDLE:
    case FSM_STATE_CONNECT:
    case FSM_STATE_ACTIVE:
    case FSM_STATE_OpenSent:
    case FSM_STATE_OpenConfirm:
    case FSM_STATE_ESTABLISHED:
      return true;
    default:
      return false;
  }
}

/**
 * Returns the possible next stated in the state machine
 * 
 * @param state the state whose next states are aquired.
 * 
 * @return all follow states (bit coded) or zero for an error
 */
int nextStates(int state)
{
  int nextState = 0;
  
  if (_isSingleState(state))
  {
    switch (state)
    {
      case FSM_STATE_IDLE: 
        nextState = FSM_STATE_IDLE | FSM_STATE_CONNECT;
        break;
      case FSM_STATE_CONNECT:
        nextState = FSM_STATE_IDLE | FSM_STATE_CONNECT | FSM_STATE_ACTIVE 
                    | FSM_STATE_OpenSent;
        break;
      case FSM_STATE_ACTIVE:
        nextState = FSM_STATE_IDLE | FSM_STATE_CONNECT | FSM_STATE_ACTIVE 
                    | FSM_STATE_OpenSent;
        break;
      case FSM_STATE_OpenSent:
        nextState = FSM_STATE_IDLE | FSM_STATE_ACTIVE | FSM_STATE_OpenConfirm;
        break;
      case FSM_STATE_OpenConfirm:
        nextState = FSM_STATE_IDLE | FSM_STATE_OpenSent | FSM_STATE_OpenConfirm 
                    | FSM_STATE_ESTABLISHED;
        break;
      case FSM_STATE_ESTABLISHED:
        nextState = FSM_STATE_IDLE | FSM_STATE_ESTABLISHED;
        break;
      default:
        // Error state
        nextState = 0;
    }
  }
  
  return nextState; 
}

/**
 * Switch the state of the state machine to the new given state. If the new 
 * state is invalid the function returns false and the state machine will not
 * be changed.
 * 
 * @param fsm the state machine
 * @param newState the new state in the state machine.
 * 
 * @return true if the state could be switched, otherwise false.
 */
bool fsmSwitchState(BGPFinalStateMachine* fsm, int newState)
{
  bool retVal = true;
  if (fsm == NULL)
  {
    return false;
  }
  
  if ((newState & nextStates(fsm->state)) == newState)
  {
    fsm->state = newState;
    if (newState == FSM_STATE_ESTABLISHED)
    {
      // Reset the lastSent which is needed to force a regular keep alive
      // as answer for the established session.
      BGPSession* session = (BGPSession*)fsm->session;
      session->lastSent = 0;
    }
  }
  else
  {
    retVal = false;
  }
  
  return retVal;
}

/**
 * Checks if the state machine can switch into the given next state.
 * 
 * @param fsm the state machine
 * @param state to be checked if the state machine can switch into this state.
 * 
 * @return true if it can, otherwise false.
 */
bool fsmCanSwitchTo(BGPFinalStateMachine* fsm, int state)
{
  bool retVal = false;
  int next;
  
  if (_isSingleState(state))
  {
    next = nextStates(fsm->state);
    if ((next & state) == state)
    {
      retVal = true;
    }
  }
  
  return retVal;
}

/**
 * Initializes the final state machine
 * 
 * @param fsm the fonal state machine
 */
void fsmInit(BGPFinalStateMachine* fsm)
{
  fsm->state               = FSM_STATE_IDLE;
  fsm->connectRetryCounter = 0;
  fsm->connectRetryTime    = FSM_RECONNECT_TIME;
  fsm->keepAliveTime       = FSM_KEEPALIVE_TIME;
}

/**
 * Establish a BGP connection.s
s * 
 * @param fsm The state machine
 * 
 * @return false if unsuccessful, otherwise true
 */
bool fsmEstablishBGP(BGPFinalStateMachine* fsm)
{
  BGPSession* session = (BGPSession*)fsm->session;
  if (session == NULL)
  {
    printf ("ERROR: Session is NULL\n");
    return false;
  }
  
  // run through the state machine until established or session stopped.
  while (fsm->state != FSM_STATE_ESTABLISHED && session->run 
         && session->fsm.connectRetryCounter < FSM_MAX_RETRY)
  {
    switch (fsm->state)
    {
      case FSM_STATE_IDLE:
        fsmInit(fsm);
        fsmSwitchState(fsm, FSM_STATE_CONNECT);
        break;
      case FSM_STATE_CONNECT:
        if (fsm->connectRetryCounter > 0)
        {
          printf("Connection failed, retry in %d seconds.\n", 
                 FSM_RECONNECT_TIME);
          sleep(FSM_RECONNECT_TIME);
        }
        if (establishTCPSession(session))
        {
          // Goto OpenSent
          fsmSwitchState(fsm, FSM_STATE_OpenSent);
        }
        else
        {
          fsm->connectRetryCounter++;
          shutDownTCPSession(session, false);
          fsmSwitchState(fsm, FSM_STATE_ACTIVE);          
        }
        break;
      case FSM_STATE_ACTIVE:
        // To keep it simple, just move back to FSM_STATE_CONNECT and lets try
        // to reconnect
        fsmSwitchState(fsm, FSM_STATE_CONNECT);
        break;
      case FSM_STATE_OpenSent:
        if (sendOpenMessage(session))
        {
          // now read the BGP session receiver - No timeout
          int read = readNextBGPMessage(session, SESS_TIMEOUT_RCV_OPEN);
          if (read > 0)
          {
            if (checkMessageHeader(session))
            {
              processOpenMessage(session);
            }
          }
          else 
          {
            // The socket seems to be stale
            printf("WARNING: Seems to be a stale connection - Abort!\n");
            // Stop any further attempts
            session->fsm.connectRetryCounter = FSM_MAX_RETRY;
          }
        }
        else
        {
          // Stop the BGP thread;
          session->fsm.connectRetryCounter = FSM_MAX_RETRY;
        }
        break;
      case FSM_STATE_OpenConfirm:
        if (fsmSwitchState(fsm, FSM_STATE_ESTABLISHED))
        {
          if (!sendKeepAlive(session))
          {
            printf("ERROR: Could not send initial KeepAlive receipt!\n");
            sendNotification(session, BGP_ERR6_CEASE,
                             BGP_ERR6_SUB_ADMIN_SHUTDOWN, 0, NULL);
          }
        }
        else
        {
          printf ("ERROR: Could not set FSM to ESTABLISHED!\n");
          sendNotification(session, BGP_ERR5_FSM, BGP_ERR_SUB_UNDEFINED, 
                           0, NULL);
        }
        break;
      case FSM_STATE_ESTABLISHED:
        printf ("INFO: Session to AS %usucessully established!\n", 
                session->bgpConf.peerAS);
        break;
      default:
        printf ("???? Invalid State!!!");
        session->run = false;
    }
  }
  
  return fsm->state == FSM_STATE_ESTABLISHED;
}

/**
 * Run the loop for the holdTime if in ESTABLISHED mode. It might take 1/3 of 
 * the hold time to recognize the loop needs to stop.
 *  
 * @param fsm The state machine
 */
void fsmRunHoldTimeLoop(BGPFinalStateMachine* fsm)
{
  int secToSleep;
  
  BGPSession* session = (BGPSession*)fsm->session;
  time_t now;
  if (session->bgpConf.holdTime < 3)
  {
    return;
  }

  int intervalTime = (int)(session->bgpConf.holdTime / 3);
  
  // Use a signal base waiting to allow faster shutdown. Signal is send by 
  // receiver thread.      
  // Set the timeout (sleep time)
  struct timespec timeout;
  bool   useSleep = session->sessHoldTimerSem == NULL;

  while (session->run && session->fsm.state == FSM_STATE_ESTABLISHED )
  {
    // Nothing happens anymore because the FSM itself is NOT running in a 
    // thread.

    // The FSM in established state will actively sleep for some seconds 
    // (FSM_DEF_SLEEP_TIME)
    // If the hold timer is set to 0 the time will be 1 second, otherwise
    // it will be set to 1/3 of the hold time or max FSM_MAX_SLEEP_TIME.
    secToSleep = FSM_DEF_SLEEP_TIME;
    now = time(0);

    // First check if we received everything - like update or keep alive ?
    if (now > (session->lastReceived + session->bgpConf.holdTime))
    {
      printf("ERROR: Did not hear back from peer AS %u - seems dead!\n",
             session->bgpConf.peerAS);
      sendNotification(session, BGP_ERR4_HOLD_TIMER_EXPIRED, 
                       BGP_ERR_SUB_UNDEFINED, 0, NULL);
      break;
    }

    // Yeah we're still good with an alive peer
    // Now calculate if we need to send a keep alive
    if ((session->lastSent + intervalTime) <= now)
    {
      // its time to send a keep alive
      if (!sendKeepAlive(session))
      {
        // let the peer handle with the missing keep alive - the next one might 
        // work and we have time to send approx. 2 more keep alive messages.
        printf ("WARNING: Problems sending KeepAlive to AS %u\n", 
                session->bgpConf.peerAS);
      }
    }
    
    // Recalculate the sleep time until next keep alive is to be send.
    secToSleep = (now - session->lastSent) + intervalTime;                    
    
    if (secToSleep > 0)
    {
      // the max sleep time allows the session to stay up for maximum the given
      // amount of time. one also could envision a 1/2 sec sleep and loop it.      
      int sleepFor = (secToSleep < FSM_MAX_SLEEP_TIME) ? secToSleep 
                                                       : FSM_MAX_SLEEP_TIME;
      //sleep (sleepFor);
      if (useSleep)
      {
        // Use good old sleeping.
        sleep(sleepFor);
      }
      else
      {
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec  += sleepFor;        
        //sem_wait(session-0>sessHoldTimerSem);
        sem_timedwait(session->sessHoldTimerSem, &timeout);
      }      
    }    
  }
}