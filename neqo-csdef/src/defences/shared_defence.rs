use std::time::Duration;
use std::sync::{ Arc, Mutex };
use crate::trace::Packet;
use crate::defences::Defencev2;


#[derive(Debug)]
struct RegulatedDefence<T: Defencev2> {
    id: u64,
    regulator: Arc<Mutex<DefenceRegulatorInner<T>>>,
}


impl<T> Defencev2 for RegulatedDefence<T> 
where
    T: Defencev2,
{
    fn next_event(&mut self, since_start: Duration) -> Option<Packet> {
        None
        // self.regulator.lock().unwrap().next_event(self.id, since_start)
    }

    fn next_event_at(&self) -> Option<Duration> {
        None
        // self.regulator.lock().unwrap().next_event_at(self.id)
    }

    fn is_complete(&self) -> bool {
        false
        // self.regulator.lock().unwrap().is_complete(self.id)
    }

    fn is_outgoing_complete(&self) -> bool {
        false
        // self.regulator.lock().unwrap().is_outgoing_complete(self.id)
    }

    fn is_padding_only(&self) -> bool {
        true
        // self.regulator.lock().unwrap().is_padding_only()
    }

    fn on_application_complete(&mut self) {
        // self.regulator.lock().unwrap().on_application_complete(self.id)
    }
}

impl<T> Drop for RegulatedDefence<T> 
where
    T: Defencev2,
{
    fn drop(&mut self) {
        // self.regulator.lock().unwrap().disconnect(self.id);
    }
}


#[derive(Debug)]
struct DefenceRegulatorInner<T: Defencev2> {
    defence: T,
    regulated_ids: Vec<u64>,
    next_index: usize,
}

impl<T> DefenceRegulatorInner<T> 
where
    T: Defencev2,
{
    // Remove the specified regulated defence from the round-robin queue.
    // fn disconnect(&mut self, id: u64) {
    //     assert!(self.defence.is_complete() || !self.regulated_ids.is_empty());
    // }
}

#[derive(Debug)]
pub struct DefenceRegulator<T: Defencev2> {
    inner: Arc<Mutex<DefenceRegulatorInner<T>>>,
    next_id: u64,
}

impl<T> DefenceRegulator<T> 
where
    T: Defencev2,
{
    /// Create a new DefenceRegulator for sharing the provided defence.
    fn new(defence: T) -> Self {
        DefenceRegulator {
            inner: Arc::new(Mutex::new(DefenceRegulatorInner {
                defence,
                regulated_ids: Vec::new(),
                next_index: 0,
            })),
            next_id: 0,
        }
    }

    fn add_regulated(&mut self) -> RegulatedDefence<T> {
        let regulated = RegulatedDefence {
            id: self.next_id,
            regulator: self.inner.clone()
        };
        self.inner.lock().unwrap().regulated_ids.push(regulated.id);
        self.next_id += 1;

        regulated
    }

    fn regulated_count(&self) -> usize {
        self.inner.lock().unwrap().regulated_ids.len()
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::defences::{ Front, FrontConfig };

    #[test]
    fn add_regulated() {
        let front = Front::new(FrontConfig::default());
        let mut regulator = DefenceRegulator::new(front);

        assert_eq!(regulator.regulated_count(), 0);
        regulator.add_regulated();
        assert_eq!(regulator.regulated_count(), 1);
        regulator.add_regulated();
        assert_eq!(regulator.regulated_count(), 2);
    }

    // #[test]
    // fn disconnect() {
    // }
}




// 
// 
// impl<T> Defencev2 for SharedDefence<T> 
// where
//     T: Defencev2,
// {
//     fn next_event(&mut self, since_start: Duration) -> Option<Packet> {
//         self.defence.next_event(since_start)
//     }
//     fn on_application_complete(&mut self) {
//         self.defence.on_application_complete()
//     }
// 
//     fn next_event_at(&self) -> Option<Duration> { self.defence.next_event_at() }
//     fn is_complete(&self) -> bool { self.defence.is_complete() }
//     fn is_outgoing_complete(&self) -> bool { self.defence.is_outgoing_complete() }
//     fn is_padding_only(&self) -> bool { true }
// }
