use std::io::{self, Read};

/// An immutable view into a slice of bytes that allows arbitrary bulk reads with memory of the last
/// location read (the needle) and the freedom to manipulate that position using the method
/// `set_needle`. The needle initially starts at index 0 of the underlying slice when the view is
/// first created.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct View<'a> {
    inner: &'a [u8],
    needle: usize,
}

impl<'a> View<'a> {
    pub fn new(inner: &'a [u8]) -> Self {
        Self { inner, needle: 0 }
    }

    /// Tries to return a slice of `n` bytes from the [View]. If the current needle position + `n`
    /// is out of bounds, it will take a slice from the current needle to the end of the [View].
    ///
    /// Note: This method will move the needle forward the number of bytes read.
    pub fn read_n_bytes(&mut self, mut n: usize) -> &[u8] {
        let needle = self.needle();
        let len = self.len();

        if needle + n > len {
            n = len - needle;
        }

        let slice = &self.inner[needle..needle + n];
        self.needle += n;

        slice
    }

    /// Same as [read_n_bytes] but returns a [Vec] instead of a slice.
    pub fn read_n_bytes_owned(&mut self, n: usize) -> Vec<u8> {
        self.read_n_bytes(n).to_vec()
    }

    /// Returns a slice from the needle's current position to the end of the view.
    /// Returns an empty slice if already at the end of the view.
    pub fn read_all(&mut self) -> &[u8] {
        if self.needle >= self.len() {
            return &[];
        }

        let slice = &self.inner[self.needle..];
        self.needle = self.len();

        slice
    }

    /// Same as [read_all] but returns a [Vec] instead of a slice.
    pub fn read_all_owned(&mut self) -> Vec<u8> {
        self.read_all().to_vec()
    }

    /// The position the next read from this view will start from.
    pub fn needle(&self) -> usize {
        self.needle
    }

    /// Set the needle's index value to `index` in the view.
    pub fn set_needle(&mut self, index: usize) {
        if index >= self.len() {
            panic!(
                "needle must be in the range 0..{}, got {}",
                self.len(),
                index
            );
        }

        self.needle = index;
    }

    /// Rewinds the needle `n` indices backwards. Default to the 0 index If rewinding `n` indicies
    /// will result in a negative index for the needle. Rewinding the value of the needle will
    /// reset the needle to the very beginning of the view.
    pub fn rewind(&mut self, mut n: usize) {
        if n > self.needle() {
            n = self.needle();
        }
        self.set_needle(self.needle() - n);
    }

    /// Moves the needle forward by `n` indicies. Sets the needle index to the length of the view
    /// if the current needle + `n` exceeds the view length.
    pub fn forward(&mut self, mut n: usize) {
        if self.needle() + n >= self.needle() {
            n = self.len();
        }
        self.set_needle(n);
    }

    /// Checks if the needle is pointing at the end of the view, in other words, if there is no more bytes to
    /// read in the view without rewinding.
    pub fn is_at_end(&self) -> bool {
        self.needle >= self.len()
    }

    /// Returns the complete length of the view regardless of needle position.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns the number of bytes between the needle and the end of the view
    pub fn remaining(&self) -> usize {
        self.len() - self.needle
    }
}

impl<'a> Read for View<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let view = &self.inner[self.needle..];
        let view_len = view.len();
        let buf_len = buf.len();

        let bytes_copied = if buf_len > view_len {
            buf[..view_len].copy_from_slice(view);
            view_len
        } else {
            buf.copy_from_slice(&view[..buf_len]);
            buf_len
        };

        self.needle += bytes_copied;

        io::Result::Ok(bytes_copied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_read_n_bytes_after_setting_needle() {
        let mut view = View::new(&[0, 1, 2, 3, 4]);

        view.set_needle(2);
        let bytes = view.read_n_bytes(2);

        assert_eq!(bytes, &[2, 3]);
    }
}
