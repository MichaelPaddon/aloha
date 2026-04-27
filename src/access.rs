// Firewall-style access control: IP, user, and group rules evaluated
// per-request against the authenticated principal.  Rules use first-match
// semantics; an implicit deny-403 fires when no rule matches.

use crate::auth::Principal;
use ipnet::IpNet;
use std::net::IpAddr;

// -- Types ---------------------------------------------------------

#[derive(Clone, Debug)]
pub enum AccessCondition {
    Ip(IpNet),
    User(String),
    Group(String),
    Authenticated,
}

#[derive(Clone, Debug)]
pub enum AccessAction {
    Allow,
    Deny { code: u16 },
    Redirect { to: String, code: u16 },
}

#[derive(Clone, Debug)]
pub struct AccessRule {
    pub conditions: Vec<AccessCondition>,
    pub action: AccessAction,
}

#[derive(Clone, Debug)]
pub struct AccessPolicy {
    pub rules: Vec<AccessRule>,
}

pub enum AccessOutcome {
    Allow,
    Deny(u16),
    Redirect(String, u16),
}

// -- Evaluation ---------------------------------------------------

impl AccessPolicy {
    pub fn evaluate(
        &self,
        peer: IpAddr,
        principal: &Principal,
    ) -> AccessOutcome {
        let peer = normalise(peer);
        for rule in &self.rules {
            if rule_matches(&rule.conditions, peer, principal) {
                return match &rule.action {
                    AccessAction::Allow => AccessOutcome::Allow,
                    AccessAction::Deny { code } => AccessOutcome::Deny(*code),
                    AccessAction::Redirect { to, code } => {
                        AccessOutcome::Redirect(to.clone(), *code)
                    }
                };
            }
        }
        // Implicit deny when no rule matches (firewall default-deny).
        AccessOutcome::Deny(403)
    }
}

// Conditions within a rule use OR within the same type, AND across
// types.  A rule with no conditions always matches (catch-all).
fn rule_matches(
    conditions: &[AccessCondition],
    peer: IpAddr,
    principal: &Principal,
) -> bool {
    if conditions.is_empty() {
        return true;
    }

    // Collect conditions by type and check each bucket.
    let mut has_ip = false;
    let mut ip_ok = false;
    let mut has_user = false;
    let mut user_ok = false;
    let mut has_group = false;
    let mut group_ok = false;
    let mut has_authenticated = false;

    for cond in conditions {
        match cond {
            AccessCondition::Ip(net) => {
                has_ip = true;
                if net.contains(&peer) {
                    ip_ok = true;
                }
            }
            AccessCondition::User(u) => {
                has_user = true;
                if let Principal::Authenticated(id) = principal {
                    if &id.username == u {
                        user_ok = true;
                    }
                }
            }
            AccessCondition::Group(g) => {
                has_group = true;
                if let Principal::Authenticated(id) = principal {
                    if id.groups.contains(g) {
                        group_ok = true;
                    }
                }
            }
            AccessCondition::Authenticated => {
                has_authenticated = true;
            }
        }
    }

    if has_ip && !ip_ok {
        return false;
    }
    if has_user && !user_ok {
        return false;
    }
    if has_group && !group_ok {
        return false;
    }
    if has_authenticated && !matches!(principal, Principal::Authenticated(_)) {
        return false;
    }
    true
}

// Normalise IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) to plain IPv4
// so that `ip "10.0.0.0/8"` matches whether the socket reports the
// peer as 10.1.2.3 or ::ffff:10.1.2.3.
fn normalise(addr: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = addr {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
    }
    addr
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Identity, Principal};

    fn anon() -> Principal {
        Principal::Anonymous
    }

    fn authed(username: &str, groups: &[&str]) -> Principal {
        Principal::Authenticated(Identity {
            username: username.to_owned(),
            groups: groups.iter().map(|s| s.to_string()).collect(),
        })
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn policy(rules: Vec<AccessRule>) -> AccessPolicy {
        AccessPolicy { rules }
    }

    fn allow_rule(conds: Vec<AccessCondition>) -> AccessRule {
        AccessRule { conditions: conds, action: AccessAction::Allow }
    }

    fn deny_rule(conds: Vec<AccessCondition>, code: u16) -> AccessRule {
        AccessRule {
            conditions: conds,
            action: AccessAction::Deny { code },
        }
    }

    fn redirect_rule(
        conds: Vec<AccessCondition>,
        to: &str,
        code: u16,
    ) -> AccessRule {
        AccessRule {
            conditions: conds,
            action: AccessAction::Redirect {
                to: to.to_owned(),
                code,
            },
        }
    }

    // -- No rules -------------------------------------------------

    #[test]
    fn no_rules_implicit_deny() {
        let p = policy(vec![]);
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &anon()),
            AccessOutcome::Deny(403)
        ));
    }

    // -- IP conditions ---------------------------------------------

    #[test]
    fn ip_in_range_allows() {
        let p = policy(vec![
            allow_rule(vec![AccessCondition::Ip(net("10.0.0.0/8"))]),
            deny_rule(vec![], 403),
        ]);
        assert!(matches!(
            p.evaluate(ip("10.1.2.3"), &anon()),
            AccessOutcome::Allow
        ));
    }

    #[test]
    fn ip_out_of_range_falls_through_to_deny() {
        let p = policy(vec![
            allow_rule(vec![AccessCondition::Ip(net("10.0.0.0/8"))]),
            deny_rule(vec![], 403),
        ]);
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &anon()),
            AccessOutcome::Deny(403)
        ));
    }

    #[test]
    fn two_ip_conditions_are_or() {
        // Either network should allow.
        let p = policy(vec![
            allow_rule(vec![
                AccessCondition::Ip(net("10.0.0.0/8")),
                AccessCondition::Ip(net("192.168.0.0/16")),
            ]),
            deny_rule(vec![], 403),
        ]);
        assert!(matches!(
            p.evaluate(ip("10.0.0.1"), &anon()),
            AccessOutcome::Allow
        ));
        assert!(matches!(
            p.evaluate(ip("192.168.1.1"), &anon()),
            AccessOutcome::Allow
        ));
        // Neither range -> deny.
        assert!(matches!(
            p.evaluate(ip("8.8.8.8"), &anon()),
            AccessOutcome::Deny(403)
        ));
    }

    // -- IP + identity AND -----------------------------------------

    #[test]
    fn ip_and_group_both_required() {
        let p = policy(vec![
            allow_rule(vec![
                AccessCondition::Ip(net("10.0.0.0/8")),
                AccessCondition::Group("admin".into()),
            ]),
            deny_rule(vec![], 403),
        ]);
        // Right IP, right group -> allow.
        assert!(matches!(
            p.evaluate(ip("10.0.0.1"), &authed("alice", &["admin"])),
            AccessOutcome::Allow
        ));
        // Right IP, wrong group -> deny.
        assert!(matches!(
            p.evaluate(ip("10.0.0.1"), &authed("alice", &["users"])),
            AccessOutcome::Deny(403)
        ));
        // Wrong IP, right group -> deny.
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &authed("alice", &["admin"])),
            AccessOutcome::Deny(403)
        ));
    }

    // -- Custom codes ----------------------------------------------

    #[test]
    fn deny_custom_code() {
        let p = policy(vec![deny_rule(vec![], 429)]);
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &anon()),
            AccessOutcome::Deny(429)
        ));
    }

    // -- Redirect action -------------------------------------------

    #[test]
    fn redirect_action() {
        let p = policy(vec![redirect_rule(
            vec![AccessCondition::Ip(net("1.2.3.4/32"))],
            "/blocked/",
            302,
        )]);
        match p.evaluate(ip("1.2.3.4"), &anon()) {
            AccessOutcome::Redirect(to, code) => {
                assert_eq!(to, "/blocked/");
                assert_eq!(code, 302);
            }
            other => panic!("expected Redirect, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn redirect_custom_code() {
        let p = policy(vec![redirect_rule(vec![], "/x/", 301)]);
        match p.evaluate(ip("1.2.3.4"), &anon()) {
            AccessOutcome::Redirect(_, code) => assert_eq!(code, 301),
            _ => panic!("expected Redirect"),
        }
    }

    // -- Identity conditions ---------------------------------------

    #[test]
    fn identity_conditions_never_match_anonymous() {
        for cond in [
            AccessCondition::User("alice".into()),
            AccessCondition::Group("admin".into()),
            AccessCondition::Authenticated,
        ] {
            let p = policy(vec![
                allow_rule(vec![cond]),
                deny_rule(vec![], 403),
            ]);
            assert!(
                matches!(
                    p.evaluate(ip("1.2.3.4"), &anon()),
                    AccessOutcome::Deny(403)
                ),
                "anonymous should not match identity condition"
            );
        }
    }

    #[test]
    fn authenticated_condition_matches_any_logged_in_user() {
        let p = policy(vec![
            allow_rule(vec![AccessCondition::Authenticated]),
            deny_rule(vec![], 403),
        ]);
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &authed("alice", &[])),
            AccessOutcome::Allow
        ));
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &anon()),
            AccessOutcome::Deny(403)
        ));
    }

    #[test]
    fn user_condition_matches_exact_name() {
        let p = policy(vec![
            allow_rule(vec![AccessCondition::User("alice".into())]),
            deny_rule(vec![], 403),
        ]);
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &authed("alice", &[])),
            AccessOutcome::Allow
        ));
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &authed("bob", &[])),
            AccessOutcome::Deny(403)
        ));
    }

    #[test]
    fn group_condition_matches_membership() {
        let p = policy(vec![
            allow_rule(vec![AccessCondition::Group("admin".into())]),
            deny_rule(vec![], 403),
        ]);
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &authed("alice", &["admin"])),
            AccessOutcome::Allow
        ));
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &authed("bob", &["users"])),
            AccessOutcome::Deny(403)
        ));
    }

    // -- IPv4-mapped normalisation ---------------------------------

    #[test]
    fn ipv4_mapped_v6_matches_v4_rule() {
        let p = policy(vec![
            allow_rule(vec![AccessCondition::Ip(net("10.0.0.0/8"))]),
            deny_rule(vec![], 403),
        ]);
        // ::ffff:10.0.0.1 should normalise to 10.0.0.1 and match.
        let mapped: IpAddr =
            "::ffff:10.0.0.1".parse::<std::net::Ipv6Addr>().unwrap().into();
        assert!(matches!(
            p.evaluate(mapped, &anon()),
            AccessOutcome::Allow
        ));
    }

    // -- Rule ordering ---------------------------------------------

    #[test]
    fn first_matching_rule_wins() {
        // First rule allows, second would deny. First match should win.
        let p = policy(vec![
            allow_rule(vec![AccessCondition::Ip(net("10.0.0.0/8"))]),
            deny_rule(vec![AccessCondition::Ip(net("10.0.0.0/8"))], 403),
        ]);
        assert!(matches!(
            p.evaluate(ip("10.0.0.1"), &anon()),
            AccessOutcome::Allow
        ));
    }

    // -- No-condition rule (catch-all) -----------------------------

    #[test]
    fn no_condition_rule_always_matches() {
        let p = policy(vec![allow_rule(vec![])]);
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &anon()),
            AccessOutcome::Allow
        ));
        assert!(matches!(
            p.evaluate(ip("8.8.8.8"), &authed("bob", &[])),
            AccessOutcome::Allow
        ));
    }

    // -- Multiple user/group conditions (OR within type) -----------

    #[test]
    fn multiple_user_conditions_are_or() {
        let p = policy(vec![
            allow_rule(vec![
                AccessCondition::User("alice".into()),
                AccessCondition::User("bob".into()),
            ]),
            deny_rule(vec![], 403),
        ]);
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &authed("alice", &[])),
            AccessOutcome::Allow
        ));
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &authed("bob", &[])),
            AccessOutcome::Allow
        ));
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &authed("charlie", &[])),
            AccessOutcome::Deny(403)
        ));
    }

    #[test]
    fn multiple_group_conditions_are_or() {
        let p = policy(vec![
            allow_rule(vec![
                AccessCondition::Group("admin".into()),
                AccessCondition::Group("ops".into()),
            ]),
            deny_rule(vec![], 403),
        ]);
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &authed("alice", &["admin"])),
            AccessOutcome::Allow
        ));
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &authed("bob", &["ops"])),
            AccessOutcome::Allow
        ));
        assert!(matches!(
            p.evaluate(ip("1.2.3.4"), &authed("charlie", &["users"])),
            AccessOutcome::Deny(403)
        ));
    }
}
