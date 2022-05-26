use std::time::{ Duration, Instant };
use std::sync::{ Arc, Mutex };
use neqo_common::{ qtrace, qinfo };
use crate::trace::Packet;
use crate::defences::{ Defencev2, CapacityInfo };


#[derive(Debug)]
struct RRState {
    defence: Box<dyn Defencev2 + Send>,
    regulated_ids: Vec<u32>,
    curr_index_inc: usize,
    curr_index_out: usize,
    event: Option<Packet>,
    start_time: Option<Instant>,
    n_skipped: usize,
    strict_rr: bool,
}


#[derive(Debug)]
pub struct RRSharedDefence {
    id: u32,
    // Pair of active ids and the index of the next id
    state: Arc<Mutex<RRState>>,
    own_app_complete: bool,
}

impl RRSharedDefence {
    fn maybe_update_index(curr_index: &mut usize, index: usize, n_regulated_ids: usize) {
        if *curr_index == index && *curr_index == n_regulated_ids {
            *curr_index = 0;
        }
        if *curr_index > index {
            *curr_index = curr_index.saturating_sub(1);
        }
    }
}

impl std::fmt::Display for RRSharedDefence {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "RRSharedDefence({})", self.id)
    }
}

impl Drop for RRSharedDefence
{
    fn drop(&mut self) {
        // When this drops, we need to remove it from the list of ids, and
        // adjust curr_index accordingly.
        if let Ok(mut state) = self.state.lock() {
            let index = state.regulated_ids.iter().position(|x| *x == self.id)
                .expect("Should have been tracked.");
            state.regulated_ids.remove(index);

            let n_ids = state.regulated_ids.len();
            RRSharedDefence::maybe_update_index(&mut state.curr_index_inc, index, n_ids);
            RRSharedDefence::maybe_update_index(&mut state.curr_index_out, index, n_ids);
        }
        qtrace!([self], "Dropping")
    }
}


impl Defencev2 for RRSharedDefence
{
    fn next_event(&mut self, _since_start: Duration) -> Option<Packet> {
        panic!("[SharedDefence {}] next_event() should not be called", self.id);
    }

    fn next_event_with_details(&mut self, since_start: Duration, capacity: CapacityInfo) -> Option<Packet> {
        let mut state = self.state.lock().unwrap();
        state.event = state.event.clone().or_else(|| state.defence.next_event(since_start));

        if let Some(pkt) = state.event.clone() {
            if (pkt.is_outgoing() && state.regulated_ids[state.curr_index_out] != self.id)
                || (pkt.is_incoming() && state.regulated_ids[state.curr_index_inc] != self.id) {
                    return None;
            }
        } else {
            return None;
        }
        assert!(state.event.is_some());

        let available_incoming = capacity.available_incoming(state.defence.is_padding_only());
        match state.event.clone() {
            // We always assign outgoing events.
            Some(pkt) if pkt.is_outgoing() => {
                assert!(state.regulated_ids[state.curr_index_out] == self.id);

                qtrace!([self], "assigned packet: {:?}", pkt);
                state.curr_index_out = (state.curr_index_out + 1) % state.regulated_ids.len();

                state.event = None;
                Some(pkt)
            }
            Some(pkt) => {
                assert!(state.regulated_ids[state.curr_index_inc] == self.id);

                // We assign incoming events whenever there is sufficient capacity
                // to pull or this is the only stream.
                // If we are using strict round robin, assign it regardless of its
                // availability of data
                if state.strict_rr
                        || available_incoming >= u64::from(pkt.length())
                        || state.regulated_ids.len() == 1
                        || capacity.app_incoming > 0 && capacity.incoming_used == 0
                        // If we have done a full round without any having enough capacity, assign it
                        || state.n_skipped == state.regulated_ids.len()
                {
                    assert!(state.regulated_ids[state.curr_index_inc] == self.id);

                    qtrace!([self], "assigned packet: {:?}", pkt);
                    state.curr_index_inc = (state.curr_index_inc + 1) % state.regulated_ids.len();
                    state.n_skipped = 0;

                    state.event = None;
                    Some(pkt)
                } else {
                    // For the remaining incoming packets, the requesting connection is not suitable
                    // to be assigned the packet, therefore we move on to the next connection.
                    qtrace!([self], "advancing connection as insufficient capacity: {} of {} ({:?})",
                        available_incoming, pkt.length(), capacity);
                    state.curr_index_inc = (state.curr_index_inc + 1) % state.regulated_ids.len();
                    state.n_skipped += 1;

                    // Store the packet until the next call
                    state.event = Some(pkt);
                    None
                }
            },
            None => None,
        }
    }

    fn next_event_at(&self) -> Option<Duration> {
        let state = self.state.lock().unwrap();

        state.event
            .as_ref()
            .map(|pkt| pkt.duration())
            .or_else(|| match state.defence.next_event_at() {
                None => {
                    qtrace!([self], "no more events to come.");
                    None
                }
                Some(dur) if state.regulated_ids[state.curr_index_inc] != self.id
                    && state.regulated_ids[state.curr_index_out] != self.id
                => {
                    Some(dur + Duration::from_millis(1))
                }
                Some(dur) => Some(dur)
            })
    }

    fn start(&mut self) -> Instant {
        let mut state = self.state.lock().unwrap();
        if state.start_time.is_none() {
            state.start_time = Some(Instant::now());
        }
        state.start_time.clone().unwrap()
    }

    fn is_complete(&self) -> bool {
        // We keep all the connections open until the defence is altogether,
        // complete which allows us to make use of chaff available on all of
        // the connections.
        //
        // In the case of strict_rr, immediately mark a  connection as complete
        // if there are other connections open and this connections own app is
        // complete, so that it does not hog data.
        let state = self.state.lock().unwrap();
        if state.strict_rr && state.regulated_ids.len() > 1 {
            self.own_app_complete
        } else {
            state.event.is_none() && state.defence.is_complete()
        }
    }

    fn is_outgoing_complete(&self) -> bool {
        let state = self.state.lock().unwrap();
        (state.event.is_none() || state.event.as_ref().unwrap().is_incoming())
            && state.defence.is_outgoing_complete()
    }

    fn is_padding_only(&self) -> bool {
        self.state.lock().unwrap().defence.is_padding_only()
    }

    fn on_application_complete(&mut self) {
        // Individual connections cannot know if another connection will be
        // started some time after their completiton. Therefore, we need to
        // get a signal from the managing code that no more URLs will be
        // requested.
        //
        // See the `on_all_applications_complete()` function.
        self.own_app_complete = true;
    }
}


#[derive(Debug)]
pub struct RRSharedDefenceBuilder {
    state: Arc<Mutex<RRState>>,
    next_id: u32,
}

impl std::fmt::Display for RRSharedDefenceBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "RRSharedDefenceBuilder")
    }
}

impl RRSharedDefenceBuilder
{
    /// Create a new RRSharedDefenceBuilder for sharing the provided
    /// defence.
    pub fn new(defence: Box<dyn Defencev2 + Send>, strict_rr: bool) -> Self {
        qtrace!("Creating shared defence around {:?}", defence);
        RRSharedDefenceBuilder {
            state: Arc::new(Mutex::new(RRState {
                defence,
                regulated_ids: Vec::new(),
                curr_index_inc: 0,
                curr_index_out: 0,
                event: None,
                start_time: None,
                n_skipped: 0,
                strict_rr,
            })),
            next_id: 0,
        }
    }

    /// To be called by the managing code to signal that no more URLs need to
    /// be collected, and it is therefore safe to stop the defence.
    pub fn on_all_applications_complete(&mut self) {
        self.state.lock().unwrap().defence.on_application_complete()
    }

    /// Create a new instance of the shared defence over the originally
    /// provided defence.
    pub fn new_shared(&mut self) -> RRSharedDefence {
        let shared = RRSharedDefence {
            id: self.next_id,
            state: self.state.clone(),
            own_app_complete: false
        };
        self.next_id += 1;

        let mut state = self.state.lock().unwrap();
        state.regulated_ids.push(shared.id);

        qinfo!([self], "newly created: {}", shared.id);
        shared
    }

    #[cfg(test)]
    fn shared_count(&self) -> usize {
        self.state.lock().unwrap().regulated_ids.len()
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::defences::{ Front, FrontConfig };

    #[test]
    fn new_shared() {
        let front = Front::new(FrontConfig::default());
        let mut builder = RRSharedDefenceBuilder::new(Box::new(front), false);

        assert_eq!(builder.shared_count(), 0);

        let defence = builder.new_shared();
        assert_eq!(builder.shared_count(), 1);
        assert_eq!(builder.next_id, 1);
        assert_eq!(defence.id, 0);
        assert_eq!(builder.state.lock().unwrap().regulated_ids, vec![0, ]);

        let defence = builder.new_shared();
        assert_eq!(builder.shared_count(), 2);
        assert_eq!(builder.next_id, 2);
        assert_eq!(defence.id, 1);
        assert_eq!(builder.state.lock().unwrap().regulated_ids, vec![0, 1]);
    }

    mod drop {
        use super::*;

        #[test]
        fn simple() {
            let front = Front::new(FrontConfig::default());
            let mut builder = RRSharedDefenceBuilder::new(Box::new(front), false);

            {
                let _defence = builder.new_shared();
                assert_eq!(builder.shared_count(), 1);

                {
                    let _defence = builder.new_shared();
                    assert_eq!(builder.shared_count(), 2);
                    assert_eq!(builder.state.lock().unwrap().regulated_ids, vec![0, 1]);
                }
                assert_eq!(builder.shared_count(), 1);
                assert_eq!(builder.state.lock().unwrap().regulated_ids, vec![0]);
            }
            assert_eq!(builder.shared_count(), 0);
            assert_eq!(builder.state.lock().unwrap().regulated_ids, Vec::<u32>::new());
        }

        #[test]
        fn single_removed() {
            let front = Front::new(FrontConfig::default());
            let mut builder = RRSharedDefenceBuilder::new(Box::new(front), false);

            {
                let _defence = builder.new_shared();
                assert_eq!(builder.state.lock().unwrap().curr_index_inc, 0);
                assert_eq!(builder.state.lock().unwrap().regulated_ids, [0]);
            }
            assert_eq!(builder.state.lock().unwrap().curr_index_inc, 0);
            assert_eq!(builder.state.lock().unwrap().regulated_ids, Vec::<u32>::new());
        }

        fn setup() -> (RRSharedDefenceBuilder, Vec<RRSharedDefence>) {
            let front = Front::new(FrontConfig::default());
            let mut builder = RRSharedDefenceBuilder::new(Box::new(front), false);

            let defences = vec![
                builder.new_shared(), builder.new_shared(), builder.new_shared(),
                builder.new_shared(), builder.new_shared(),
            ];
            assert_eq!(builder.shared_count(), 5);

            (builder, defences)
        }

       #[test]
       fn curr_index_before_removed() {
           let (builder, mut defences) = setup();

           builder.state.lock().unwrap().curr_index_inc = 2;
           defences.remove(3);

           let state = builder.state.lock().unwrap();
           assert_eq!(state.curr_index_inc, 2);
           assert_eq!(state.regulated_ids, [0, 1, 2, 4]);
       }

       #[test]
       fn curr_index_same_as_removed() {
           let (builder, mut defences) = setup();

           builder.state.lock().unwrap().curr_index_inc = 2;
           defences.remove(2);

           let state = builder.state.lock().unwrap();
           assert_eq!(state.curr_index_inc, 2);
           assert_eq!(state.regulated_ids, [0, 1, 3, 4]);
       }

       #[test]
       fn curr_index_at_end_removed() {
           let (builder, mut defences) = setup();

           builder.state.lock().unwrap().curr_index_inc = defences.len() - 1;
           defences.remove(defences.len() - 1);

           let state = builder.state.lock().unwrap();
           assert_eq!(state.curr_index_inc, 0);
           assert_eq!(state.regulated_ids, [0, 1, 2, 3]);
       }

       #[test]
       fn curr_index_after_removed() {
           let (builder, mut defences) = setup();

           builder.state.lock().unwrap().curr_index_inc = 2;
           defences.remove(0);

           let state = builder.state.lock().unwrap();
           assert_eq!(state.curr_index_inc, 1);
           assert_eq!(state.regulated_ids, [ 1, 2, 3, 4]);
       }
    }
}
