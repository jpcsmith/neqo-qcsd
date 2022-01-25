use std::time::Duration;
use std::sync::{ Arc, Mutex };
use crate::trace::Packet;
use crate::defences::{ Defencev2, CapacityInfo };


#[derive(Debug)]
struct RRState {
    defence: Box<dyn Defencev2 + Send>,
    regulated_ids: Vec<u32>,
    curr_index: usize,
    event: Option<Packet>,
}


#[derive(Debug)]
pub struct RRSharedDefence {
    id: u32,
    // Pair of active ids and the index of the next id
    state: Arc<Mutex<RRState>>,
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

            if state.curr_index == index && state.curr_index == state.regulated_ids.len() {
                state.curr_index = 0;
            }
            if state.curr_index > index {
                state.curr_index = state.curr_index.saturating_sub(1);
            }
        }
    }
}


impl Defencev2 for RRSharedDefence
{
    fn next_event(&mut self, _since_start: Duration) -> Option<Packet> {
        panic!("[SharedDefence {}] next_event() should not be called", self.id);
    }

    fn next_event_with_details(&mut self, since_start: Duration, capacity: CapacityInfo) -> Option<Packet> {
        let mut state = self.state.lock().unwrap();
        if state.regulated_ids[state.curr_index] != self.id {
            return None;
        }

        match state.event.clone().or_else(|| state.defence.next_event(since_start)) {
            // We always assign outgoing events. We assign incoming events whenever
            // there is sufficient capacity to pull or this is the only stream.
            Some(pkt) if pkt.is_incoming() 
                && capacity.incoming < u64::from(pkt.length())
                && state.regulated_ids.len() > 1 =>
            {
                eprintln!("[SharedDefence {}] advancing connection as insufficient capacity: {} of {}",
                    self.id, capacity.incoming, pkt.length());
                state.event = Some(pkt);
                state.curr_index = (state.curr_index + 1) % state.regulated_ids.len();
                None
            },
            Some(pkt) => {
                eprintln!("[SharedDefence {}] assigned packet: {:?}", self.id, pkt);
                state.curr_index = (state.curr_index + 1) % state.regulated_ids.len();

                state.event = None;
                Some(pkt)
            },
            None => None,
        }
    }

    fn next_event_at(&self) -> Option<Duration> {
        let state = self.state.lock().unwrap();

        match state.defence.next_event_at() {
            None => {
                eprintln!("[SharedDefence {}] no more events to come.", self.id);
                None
            }
            Some(dur) if state.regulated_ids[state.curr_index] != self.id 
                => Some(dur + Duration::from_millis(1)),
            Some(dur) => Some(dur)
        }
    }

    fn is_complete(&self) -> bool {
        // We keep all the connections open until the defence is altogether,
        // complete which allows us to make use of chaff available on all of
        // the connections.
        self.state.lock().unwrap().defence.is_complete()
    }

    fn is_outgoing_complete(&self) -> bool {
        self.state.lock().unwrap().defence.is_outgoing_complete()
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
    }
}


#[derive(Debug)]
pub struct RRSharedDefenceBuilder {
    state: Arc<Mutex<RRState>>,
    next_id: u32,
}


impl RRSharedDefenceBuilder
{
    /// Create a new RRSharedDefenceBuilder for sharing the provided
    /// defence.
    pub fn new(defence: Box<dyn Defencev2 + Send>) -> Self {
        RRSharedDefenceBuilder {
            state: Arc::new(Mutex::new(RRState {
                defence,
                regulated_ids: Vec::new(),
                curr_index: 0,
                event: None,
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
            state: self.state.clone()
        };
        self.next_id += 1;

        let mut state = self.state.lock().unwrap();
        state.regulated_ids.push(shared.id);

        eprintln!("[SharedDefence {}] newly created", shared.id);
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
        let mut builder = RRSharedDefenceBuilder::new(Box::new(front));

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
            let mut builder = RRSharedDefenceBuilder::new(Box::new(front));

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
            let mut builder = RRSharedDefenceBuilder::new(Box::new(front));

            {
                let _defence = builder.new_shared();
                assert_eq!(builder.state.lock().unwrap().curr_index, 0);
                assert_eq!(builder.state.lock().unwrap().regulated_ids, [0]);
            }
            assert_eq!(builder.state.lock().unwrap().curr_index, 0);
            assert_eq!(builder.state.lock().unwrap().regulated_ids, Vec::<u32>::new());
        }

        fn setup() -> (RRSharedDefenceBuilder, Vec<RRSharedDefence>) {
            let front = Front::new(FrontConfig::default());
            let mut builder = RRSharedDefenceBuilder::new(Box::new(front));

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

           builder.state.lock().unwrap().curr_index = 2;
           defences.remove(3);

           let state = builder.state.lock().unwrap();
           assert_eq!(state.curr_index, 2);
           assert_eq!(state.regulated_ids, [0, 1, 2, 4]);
       }

       #[test]
       fn curr_index_same_as_removed() {
           let (builder, mut defences) = setup();

           builder.state.lock().unwrap().curr_index = 2;
           defences.remove(2);

           let state = builder.state.lock().unwrap();
           assert_eq!(state.curr_index, 2);
           assert_eq!(state.regulated_ids, [0, 1, 3, 4]);
       }

       #[test]
       fn curr_index_at_end_removed() {
           let (builder, mut defences) = setup();

           builder.state.lock().unwrap().curr_index = defences.len() - 1;
           defences.remove(defences.len() - 1);

           let state = builder.state.lock().unwrap();
           assert_eq!(state.curr_index, 0);
           assert_eq!(state.regulated_ids, [0, 1, 2, 3]);
       }

       #[test]
       fn curr_index_after_removed() {
           let (builder, mut defences) = setup();

           builder.state.lock().unwrap().curr_index = 2;
           defences.remove(0);

           let state = builder.state.lock().unwrap();
           assert_eq!(state.curr_index, 1);
           assert_eq!(state.regulated_ids, [ 1, 2, 3, 4]);
       }
    }
}
