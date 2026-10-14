#[derive(Clone, Copy)]
pub(crate) struct ByteView<'a> {
    bytes: &'a [u8],
    end: usize,
}

impl<'a> ByteView<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            end: bytes.len(),
        }
    }

    pub(crate) fn bounded(bytes: &'a [u8], end: usize) -> Self {
        Self {
            bytes,
            end: end.min(bytes.len()),
        }
    }

    pub(crate) fn slice(self, offset: usize, length: usize) -> Result<&'a [u8], String> {
        let end = offset.checked_add(length).ok_or("byte range overflow")?;

        if end > self.end {
            return Err("read beyond input boundary".to_owned());
        }

        self.bytes
            .get(offset..end)
            .ok_or("read beyond input boundary".to_owned())
    }

    pub(crate) fn u8(self, offset: usize) -> Result<u8, String> {
        self.slice(offset, 1).map(|bytes| bytes[0])
    }

    pub(crate) fn u16(self, offset: usize) -> Result<u16, String> {
        let bytes = self.slice(offset, 2)?;

        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn u32(self, offset: usize) -> Result<u32, String> {
        let bytes = self.slice(offset, 4)?;

        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Cursor<'a> {
    view: ByteView<'a>,
    offset: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(bytes: &'a [u8], offset: usize) -> Result<Self, String> {
        Self::from_view(ByteView::new(bytes), offset)
    }

    pub(crate) fn from_view(view: ByteView<'a>, offset: usize) -> Result<Self, String> {
        view.slice(offset, 0)?;

        Ok(Self { view, offset })
    }

    pub(crate) fn offset(self) -> usize {
        self.offset
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, String> {
        let value = self.view.u8(self.offset)?;

        self.offset += 1;

        Ok(value)
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16, String> {
        let value = self.view.u16(self.offset)?;

        self.offset += 2;

        Ok(value)
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32, String> {
        let value = self.view.u32(self.offset)?;

        self.offset += 4;

        Ok(value)
    }

    pub(crate) fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], String> {
        let bytes = self.view.slice(self.offset, length)?;

        self.offset += length;

        Ok(bytes)
    }

    pub(crate) fn skip(&mut self, length: usize) -> Result<(), String> {
        self.read_bytes(length).map(|_| ())
    }
}
