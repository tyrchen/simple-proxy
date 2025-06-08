use super::{RateLimiter};

use papaya::HashMap;
use anyhow::Result;
use std::sync::{Arc};
use std::time::{Duration, Instant};

// 每秒最多一个请求
static MAX_REQ_PER_SEC: usize = 1;
// 时间窗口为3秒
static WINDOW_SIZE: Duration = Duration::from_secs(3);

impl RateLimiter {
    pub fn try_new() -> Result<Self> {

        let requests = HashMap::new();

        Ok(RateLimiter{
            max_requests: MAX_REQ_PER_SEC,
            time_window: WINDOW_SIZE,
            requests: Arc::new(requests),
        })
    }

    pub fn check(&self, url: &String) -> Result<bool> {

        let now = Instant::now();
        let requests = self.requests.pin();

        // 获取或初始化 url 的请求限制列表
        let entry = requests.get_or_insert(url.clone(), Vec::new());

        // 清理过期的请求
        let mut entry_new = entry.clone();
        entry_new.retain(|&time| now.duration_since(time) < self.time_window);

        if entry_new.len() < self.max_requests {

            // 记录当前请求时间
            entry_new.push(now);
            requests.insert(url.clone(), entry_new);

            Ok(false)               // 请求被允许
        } else {
            Ok(true)                // 请求被拒绝
        }
    }
}
