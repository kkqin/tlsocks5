use bytes::BytesMut;
use std::sync::LazyLock;
use std::{collections::VecDeque, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct BufferPool {
    pool: Arc<Mutex<VecDeque<BytesMut>>>,
    buffer_size: usize,
}

impl BufferPool {
    pub fn new(buffer_size: usize, pool_size: usize) -> Self {
        let mut pool = VecDeque::with_capacity(pool_size);
        for _ in 0..pool_size {
            pool.push_back(BytesMut::with_capacity(buffer_size)); // 预分配 buffer
        }
        BufferPool {
            pool: Arc::new(Mutex::new(pool)),
            buffer_size,
        }
    }

    pub async fn get_buffer(&self) -> BytesMut {
        let mut pool = self.pool.lock().await;
        pool.pop_front()
            .unwrap_or_else(|| BytesMut::with_capacity(self.buffer_size))
    }

    pub async fn return_buffer(&self, buffer: BytesMut) {
        let mut pool = self.pool.lock().await;
        if pool.len() < pool.capacity() {
            pool.push_back(buffer);
        }
    }

    pub async fn get_buffer_with_size(&self, size: usize) -> BytesMut {
        let mut pool = self.pool.lock().await;
        if size <= self.buffer_size {
            pool.pop_front()
                .unwrap_or_else(|| BytesMut::with_capacity(self.buffer_size))
        } else {
            BytesMut::with_capacity(size)
        }
    }
}

pub static POOL: LazyLock<crate::buffer_pool::BufferPool> =
    LazyLock::new(|| crate::buffer_pool::BufferPool::new(8 * 1024, 1000));
