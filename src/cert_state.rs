// Shared certificate state written by AcmeManager on each renewal
// and read by StatusHandler for the live dashboard.  Defined here
// to avoid either module importing the other.

use std::sync::{Arc, RwLock};

#[derive(Clone, Debug)]
pub struct CertState {
    pub domains: Vec<String>,
    // Unix timestamp of cert notAfter.
    pub expiry_ts: i64,
    // expiry_ts - 30 * 86400: when next renewal attempt is scheduled.
    pub next_renewal_ts: i64,
}

pub type SharedCertState = Arc<RwLock<Vec<CertState>>>;

pub fn new_shared() -> SharedCertState {
    Arc::new(RwLock::new(Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arc_clone_shares_state() {
        let shared = new_shared();
        {
            let mut v = shared.write().unwrap();
            v.push(CertState {
                domains: vec!["example.com".into()],
                expiry_ts: 9_999_999_999,
                next_renewal_ts: 9_997_406_399,
            });
        }
        // Arc::clone should share the same underlying vector.
        let cloned = shared.clone();
        assert_eq!(
            shared.read().unwrap().len(),
            cloned.read().unwrap().len(),
        );
    }

    #[test]
    fn cert_state_clone_is_value_copy() {
        let cs = CertState {
            domains: vec!["a.com".into()],
            expiry_ts: 1_000,
            next_renewal_ts: 900,
        };
        let mut copy = cs.clone();
        copy.expiry_ts = 2_000;
        // Original is unchanged.
        assert_eq!(cs.expiry_ts, 1_000);
    }
}
