/* Ring buffer implementing the WireGuard queuing semantics:
 *
 * 1. A fixed sized buffer
 * 2. Inserting into the buffer always succeeds, but might overwrite the oldest item
 */

const BUFFER_SIZE : usize = 1024;

pub struct DiscardingRingBuffer<T> {
    buf  : [ Option<T> ; BUFFER_SIZE],
    idx  : usize,
    next : usize
}

impl <T>DiscardingRingBuffer<T> where T: Copy {
    pub fn new() -> Self {
        DiscardingRingBuffer{
            buf  : [None; BUFFER_SIZE],
            idx  : 0,
            next : 0
        }
    }

    pub fn empty(&mut self) {
        self.next = 0;
        self.idx = 0;
        for i in 1..BUFFER_SIZE {
            self.buf[i] = None;
        }
    }

    pub fn push(&mut self, val : T) {
        // assign next slot (free / oldest)
        self.buf[self.idx] = Some(val);
        self.idx += 1;
        self.idx %= BUFFER_SIZE;

        // check for wrap-around
        if self.idx == self.next {
            self.next += 1;
            self.next %= BUFFER_SIZE;
        }
    }

    pub fn consume(&mut self) -> Option<T> {
        match self.buf[self.next] {
            None => None,
            some => {
                self.buf[self.next] = None;
                self.next += 1;
                self.next %= BUFFER_SIZE;
                some
            }
        }
    }

    pub fn has_element(&self) -> bool {
        match self.buf[self.next] {
            None => true,
            _ => false
        }
    }
}


proptest! {
        #[test]
        fn test_order(elems: Vec<usize>) {
            let mut buf = DiscardingRingBuffer<usize>::new();

            for e in &elems {
                buf.push(e);
            }

        }
}