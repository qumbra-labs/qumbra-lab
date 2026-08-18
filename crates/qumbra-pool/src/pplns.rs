//! PPLNS-class share window. Constants are **[devnet-placeholder]**.
//!
//! Window = last [`PPLNS_WINDOW_SHARES`] accepted shares, weighted by
//! the difficulty the pool assigned. A later stage can retune the
//! window; the type is the seam.

use std::collections::{HashMap, VecDeque};

/// Last-N accepted shares that score. [devnet-placeholder].
pub const PPLNS_WINDOW_SHARES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowShare {
    pub login: String,
    pub difficulty: u64,
}

#[derive(Clone, Debug)]
pub struct PplnsWindow {
    shares: VecDeque<WindowShare>,
    cap: usize,
}

impl Default for PplnsWindow {
    fn default() -> Self {
        Self::new(PPLNS_WINDOW_SHARES)
    }
}

impl PplnsWindow {
    pub fn new(cap: usize) -> Self {
        Self {
            shares: VecDeque::new(),
            cap: cap.max(1),
        }
    }

    pub fn push(&mut self, share: WindowShare) {
        if share.difficulty == 0 {
            return;
        }
        self.shares.push_back(share);
        while self.shares.len() > self.cap {
            self.shares.pop_front();
        }
    }

    pub fn len(&self) -> usize {
        self.shares.len()
    }

    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    /// Difficulty-weighted scores, insertion order of first appearance.
    pub fn weights(&self) -> Vec<(String, u128)> {
        let mut order: Vec<String> = Vec::new();
        let mut map: HashMap<String, u128> = HashMap::new();
        for s in &self.shares {
            if !map.contains_key(&s.login) {
                order.push(s.login.clone());
            }
            *map.entry(s.login.clone()).or_insert(0) += s.difficulty as u128;
        }
        order
            .into_iter()
            .map(|login| {
                let w = map[&login];
                (login, w)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_evicts_oldest_and_weights_by_difficulty() {
        let mut w = PplnsWindow::new(3);
        w.push(WindowShare {
            login: "a".into(),
            difficulty: 10,
        });
        w.push(WindowShare {
            login: "b".into(),
            difficulty: 20,
        });
        w.push(WindowShare {
            login: "a".into(),
            difficulty: 10,
        });
        w.push(WindowShare {
            login: "c".into(),
            difficulty: 5,
        });
        // "a"/10 evicted; remaining: b20, a10, c5
        assert_eq!(w.len(), 3);
        let weights = w.weights();
        assert_eq!(
            weights,
            vec![("b".into(), 20), ("a".into(), 10), ("c".into(), 5),]
        );
    }

    #[test]
    fn empty_window_has_no_weights() {
        assert!(PplnsWindow::default().weights().is_empty());
    }
}
