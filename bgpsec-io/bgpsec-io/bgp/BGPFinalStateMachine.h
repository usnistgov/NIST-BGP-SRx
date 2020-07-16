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
 * Contains the state machine
 * 
 * @version 0.2.0.0
 * 
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *  0.2.0.0 - 2016/05/06 - oborchert
 *            * Fixed BZ924 - more detail in c file
 *  0.1.0.0 - 2015/08/18 - oborchert
 *            * Created File.
 */
#ifndef BGPSTATEMACHINE_H
#define	BGPSTATEMACHINE_H

#include <stdbool.h>

#define FSM_STATE_IDLE        0x01
#define FSM_STATE_CONNECT     0x02
#define FSM_STATE_ACTIVE      0x04
#define FSM_STATE_OpenSent    0x08
#define FSM_STATE_OpenConfirm 0x10
#define FSM_STATE_ESTABLISHED 0x20

// The default reconnect time
#define FSM_RECONNECT_TIME 30
// The default keep alive time will be overwritten by holdtime / 3
#define FSM_KEEPALIVE_TIME 180

#define FSM_DEF_SLEEP_TIME  5
#define FSM_MAX_SLEEP_TIME 30

#define FSM_MAX_RETRY      2

typedef struct {
  int state;
  int connectRetryCounter;
  int connectRetryTime;
  int keepAliveTime;
  
  void* session;
} BGPFinalStateMachine;

/**
 * Switch the state of the state machine to the new given state. If the new 
 * state is invalid the function returns false and the state machine will not
 * be changed.
 * 
 * @param fsm the final state machine
 * @param newState the new state in the state machine.
 * 
 * @return true if the state could be switched, otherwise false.
 */
bool fsmSwitchState(BGPFinalStateMachine* fsm, int newState);

/**
 * Returns the possible next stated in the state machine
 * 
 * @param state the state whose next states are aquired.
 * 
 * @return all follow states (bit coded)
 */
int nextStates(int state);

/**
 * Checks if the state machine can switch into the given next state.
 * 
 * @param fsm the final state machine
 * @param state to be checked if the state machine can switch into this state.
 * 
 * @return true if it can, otherwise false.
 */
bool fsmCanSwitchTo(BGPFinalStateMachine* fsm, int state);


/**
 * Initializes the final state machine
 * 
 * @param fsm the fonal state machine
 */
void fsmInit(BGPFinalStateMachine* fsm);

/**
 * Does a Connect of the FSM
 * 
 * @param fsm The state machine
 * 
 * @return false if unsuccessful, otherwise true
 */
bool fsmEstablishBGP(BGPFinalStateMachine* fsm);

/**
 * Run the loop for the holdTime if in ESTABLISHED mode. It might take 1/3 of 
 * the hold time to recognize the loop needs to stop.
 *  
 * @param fsm The state machine
 */
void fsmRunHoldTimeLoop(BGPFinalStateMachine* fsm);

#endif	/* BGPSTATEMACHINE_H */

