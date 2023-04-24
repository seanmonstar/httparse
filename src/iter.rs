#[allow(missing_docs)]
pub struct Bytes<'a> {
    start: *const u8,
    end: *const u8,
    cursor: *const u8,
    phantom: core::marker::PhantomData<&'a ()>,
}

#[allow(missing_docs)]
impl<'a> Bytes<'a> {
    #[inline]
    pub fn new(slice: &'a [u8]) -> Bytes<'a> {
        let start = slice.as_ptr();
        let end = unsafe { start.add(slice.len()) };
        let cursor = start;
        Bytes {
            start,
            end,
            cursor,
            phantom: core::marker::PhantomData,
        }
    }

    #[inline]
    pub fn pos(&self) -> usize {
        self.cursor as usize - self.start as usize
    }

    #[inline]
    pub fn peek(&self) -> Option<u8> {
        if self.cursor < self.end {
            // SAFETY: bounds checked
            Some(unsafe { *self.cursor })
        } else {
            None
        }
    }

    #[inline]
    pub fn peek_ahead(&self, n: usize) -> Option<u8> {
        let ptr = unsafe { self.cursor.add(n) };
        if ptr < self.end {
            // SAFETY: bounds checked
            Some(unsafe { *ptr })
        } else {
            None
        }
    }
    
    #[inline]
    pub fn peek_n<U>(&self, n: usize) -> Option<U> {
        // TODO: drop `n` arg in favour of const
        // let n = core::mem::size_of::<U>();
        // Boundary check then read array from ptr
        if self.len() >= n {
            let ptr = self.cursor as *const U;
            let x = unsafe { core::ptr::read_unaligned(ptr) };
            Some(x)
        } else {
            None
        }
    }

    #[inline]
    pub unsafe fn bump(&mut self) {
        self.advance(1)
    }

    #[inline]
    pub unsafe fn advance(&mut self, n: usize) {
        self.cursor = self.cursor.add(n);
        debug_assert!(self.cursor <= self.end, "overflow");
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.end as usize - self.cursor as usize
    }

    #[inline]
    pub fn slice(&mut self) -> &'a [u8] {
        // not moving position at all, so it's safe
        let slice = unsafe { slice_from_ptr_range(self.start, self.cursor) };
        self.commit();
        slice
    }

    // TODO: this is an anti-pattern, should be removed
    #[inline]
    pub unsafe fn slice_skip(&mut self, skip: usize) -> &'a [u8] {
        debug_assert!(self.cursor.sub(skip) >= self.start);
        let head = slice_from_ptr_range(self.start, self.cursor.sub(skip));
        self.commit();
        head
    }
    
    #[inline]
    pub fn commit(&mut self) {
        self.start = self.cursor
    }

    #[inline]
    pub unsafe fn advance_and_commit(&mut self, n: usize) {
        self.advance(n);
        self.commit();
    }
    
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.cursor
    }

    #[inline]
    pub fn start(&self) -> *const u8 {
        self.start
    }
    
    #[inline]
    pub fn end(&self) -> *const u8 {
        self.end
    }
    
    #[inline]
    pub unsafe fn set_cursor(&mut self, ptr: *const u8) {
        debug_assert!(ptr >= self.start);
        debug_assert!(ptr <= self.end);
        self.cursor = ptr;
    }
}

impl<'a> AsRef<[u8]> for Bytes<'a> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        unsafe { slice_from_ptr_range(self.cursor, self.end) }
    }
}

#[inline]
unsafe fn slice_from_ptr_range<'a>(start: *const u8, end: *const u8) -> &'a [u8] {
    debug_assert!(start <= end);
    core::slice::from_raw_parts(start, end as usize - start as usize)
}

impl<'a> Iterator for Bytes<'a> {
    type Item = u8;

    #[inline]
    fn next(&mut self) -> Option<u8> {
        if self.cursor < self.end {
            // SAFETY: bounds checked
            unsafe {
                let b = *self.cursor;
                self.bump();
                Some(b)
            }
        } else {
            None
        }
    }
}
