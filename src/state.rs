// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Simple state machine wrapper

#[derive(Debug)]
pub(crate) enum State<S, R> {
    Next(S),
    Return(R, S),
}

pub(crate) trait StateMachine {
    type State;
    type Return;
    type Error;

    fn take_state(&mut self) -> Self::State;
    fn put_state(&mut self, state: Self::State);
}

pub(crate) fn turn<SM, F>(state_machine: &mut SM, mut f: F) -> Result<SM::Return, SM::Error>
where
    SM: StateMachine,
    F: FnMut(SM::State, &mut SM) -> Result<State<SM::State, SM::Return>, SM::Error>,
{
    let mut current_state = state_machine.take_state();
    loop {
        match f(current_state, state_machine) {
            Ok(State::Next(next)) => {
                current_state = next;
            }
            Ok(State::Return(value, next)) => {
                state_machine.put_state(next);
                return Ok(value);
            }
            Err(e) => {
                // After an error, the state is assumed to be invalid and it
                // is not put back. It is up to the implementers of
                // `StateMachine` to decide what to do when the state hasn't
                // been returned. Panicking or resetting the state machine are
                // two good options.
                return Err(e);
            }
        }
    }
}

pub(crate) fn err<S, R, E>(e: E) -> Result<State<S, R>, E> {
    Err(e)
}

pub(crate) fn next<S, R, E>(next_state: S) -> Result<State<S, R>, E> {
    Ok(State::Next(next_state))
}

pub(crate) fn ret<S, R, E>(retval: R, next_state: S) -> Result<State<S, R>, E> {
    Ok(State::Return(retval, next_state))
}
