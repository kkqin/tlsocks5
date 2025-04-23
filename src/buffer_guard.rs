use bytes::BytesMut;
// Assuming BufferPool is defined in another module, import it
use crate::buffer_pool::BufferPool;

pub struct BufferGuard<'a> {
    buffer: Option<BytesMut>,
    buffer_pool: &'a BufferPool,
}

impl<'a> BufferGuard<'a> {
    pub fn new(buffer: BytesMut, buffer_pool: &'a BufferPool) -> Self {
        BufferGuard {
            buffer: Some(buffer),
            buffer_pool,
        }
    }

    pub fn take(&mut self) -> BytesMut {
        self.buffer.take().unwrap()
    }
}

impl<'a> Drop for BufferGuard<'a> {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            let buffer_pool = self.buffer_pool.clone();
            tokio::spawn(async move {
                buffer_pool.return_buffer(buffer).await;
            });
        }
    }
}