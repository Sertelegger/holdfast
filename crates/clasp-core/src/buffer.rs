//! Fixed-capacity ring buffer of raw PTY bytes, addressed by absolute
//! byte offsets. Offsets never repeat, so an agent-held cursor is always
//! unambiguous even after the buffer wraps.

/// Result of a read against the buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferRead {
    /// Bytes from the effective start offset up to the read end.
    pub bytes: Vec<u8>,
    /// Absolute offset just past the returned bytes. The agent passes
    /// this back as `since_cursor` on its next read.
    pub cursor: u64,
    /// True when the requested cursor was older than `tail`, meaning
    /// bytes were missed.
    pub truncated_at_tail: bool,
}

#[derive(Debug)]
pub struct OutputBuffer {
    data: Vec<u8>,
    capacity: usize,
    /// Absolute offset just past the newest byte.
    head: u64,
}

impl OutputBuffer {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "buffer capacity must be non-zero");
        Self { data: Vec::new(), capacity, head: 0 }
    }

    pub fn head(&self) -> u64 {
        self.head
    }

    pub fn tail(&self) -> u64 {
        self.head - self.data.len() as u64
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Append bytes, evicting from the front once capacity is exceeded.
    pub fn push(&mut self, bytes: &[u8]) {
        self.head += bytes.len() as u64;
        if bytes.len() >= self.capacity {
            // The new chunk alone fills or overflows the buffer.
            self.data.clear();
            self.data.extend_from_slice(&bytes[bytes.len() - self.capacity..]);
            return;
        }
        self.data.extend_from_slice(bytes);
        let overflow = self.data.len().saturating_sub(self.capacity);
        if overflow > 0 {
            self.data.drain(..overflow);
        }
    }

    /// Read from `since` up to at most `max_bytes`.
    pub fn read_from(&self, since: u64, max_bytes: usize) -> BufferRead {
        let tail = self.tail();
        let truncated_at_tail = since < tail;
        let start = since.max(tail).min(self.head);
        let avail = (self.head - start) as usize;
        let take = avail.min(max_bytes);
        let off = (start - tail) as usize;
        BufferRead {
            bytes: self.data[off..off + take].to_vec(),
            cursor: start + take as u64,
            truncated_at_tail,
        }
    }

    /// Read the last `n` bytes.
    pub fn read_tail_bytes(&self, n: usize) -> BufferRead {
        let take = n.min(self.data.len());
        BufferRead {
            bytes: self.data[self.data.len() - take..].to_vec(),
            cursor: self.head,
            truncated_at_tail: false,
        }
    }

    /// Read the last `n` newline-delimited lines.
    pub fn read_tail_lines(&self, n: usize) -> BufferRead {
        if n == 0 || self.data.is_empty() {
            return BufferRead { bytes: Vec::new(), cursor: self.head, truncated_at_tail: false };
        }
        // Walk backwards counting newlines, ignoring a single trailing one.
        let mut seen = 0usize;
        let mut idx = self.data.len();
        let search_end = if *self.data.last().unwrap() == b'\n' {
            self.data.len() - 1
        } else {
            self.data.len()
        };
        for i in (0..search_end).rev() {
            if self.data[i] == b'\n' {
                seen += 1;
                if seen == n {
                    idx = i + 1;
                    break;
                }
            }
            idx = i;
        }
        BufferRead {
            bytes: self.data[idx..].to_vec(),
            cursor: self.head,
            truncated_at_tail: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_read_from_zero() {
        let mut b = OutputBuffer::new(1024);
        b.push(b"hello");
        let r = b.read_from(0, 1024);
        assert_eq!(r.bytes, b"hello");
        assert_eq!(r.cursor, 5);
        assert!(!r.truncated_at_tail);
    }

    #[test]
    fn cursor_advances_across_reads() {
        let mut b = OutputBuffer::new(1024);
        b.push(b"abc");
        let r1 = b.read_from(0, 1024);
        assert_eq!(r1.cursor, 3);
        b.push(b"def");
        let r2 = b.read_from(r1.cursor, 1024);
        assert_eq!(r2.bytes, b"def");
        assert_eq!(r2.cursor, 6);
    }

    #[test]
    fn max_bytes_caps_the_read() {
        let mut b = OutputBuffer::new(1024);
        b.push(b"0123456789");
        let r = b.read_from(0, 4);
        assert_eq!(r.bytes, b"0123");
        assert_eq!(r.cursor, 4);
    }

    #[test]
    fn head_and_tail_track_eviction() {
        let mut b = OutputBuffer::new(4);
        b.push(b"abcdef");
        assert_eq!(b.head(), 6);
        assert_eq!(b.tail(), 2);
        assert_eq!(b.len(), 4);
    }

    #[test]
    fn stale_cursor_reports_truncation() {
        let mut b = OutputBuffer::new(4);
        b.push(b"abcdef"); // tail is now 2
        let r = b.read_from(0, 1024);
        assert!(r.truncated_at_tail);
        assert_eq!(r.bytes, b"cdef");
        assert_eq!(r.cursor, 6);
    }

    #[test]
    fn push_larger_than_capacity_keeps_newest() {
        let mut b = OutputBuffer::new(3);
        b.push(b"abcdefgh");
        assert_eq!(b.read_from(b.tail(), 1024).bytes, b"fgh");
        assert_eq!(b.head(), 8);
    }

    #[test]
    fn read_at_head_returns_empty() {
        let mut b = OutputBuffer::new(64);
        b.push(b"xyz");
        let r = b.read_from(3, 1024);
        assert!(r.bytes.is_empty());
        assert_eq!(r.cursor, 3);
    }

    #[test]
    fn tail_bytes_returns_newest() {
        let mut b = OutputBuffer::new(64);
        b.push(b"0123456789");
        let r = b.read_tail_bytes(3);
        assert_eq!(r.bytes, b"789");
        assert_eq!(r.cursor, 10);
    }

    #[test]
    fn tail_lines_counts_from_the_end() {
        let mut b = OutputBuffer::new(1024);
        b.push(b"one\ntwo\nthree\n");
        let r = b.read_tail_lines(2);
        assert_eq!(r.bytes, b"two\nthree\n");
    }

    #[test]
    fn tail_lines_more_than_present_returns_all() {
        let mut b = OutputBuffer::new(1024);
        b.push(b"a\nb\n");
        assert_eq!(b.read_tail_lines(10).bytes, b"a\nb\n");
    }
}
