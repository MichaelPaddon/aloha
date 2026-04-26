use async_trait::async_trait;
use hyper::Request;
use hyper::body::Incoming;

pub struct Identity {
    pub username: String,
    pub groups: Vec<String>,
}

#[allow(dead_code)] // Authenticated is unused until a real authenticator ships
pub enum Principal {
    Anonymous,
    Authenticated(Identity),
}

#[derive(Clone, Debug)]
pub enum AuthRule {
    // Any authenticated user, regardless of group membership.
    Authenticated,
    // Principal's username must match exactly.
    User(String),
    // Principal must be a member of this group.
    Group(String),
}

/// Outcome of evaluating an `AuthPolicy` against a `Principal`.
#[derive(Debug, PartialEq)]
pub enum AuthDecision {
    /// Access is granted.
    Allow,
    /// An explicit deny rule matched, or the principal is authenticated
    /// but does not satisfy any allow rule.  Returns 403.
    Deny,
    /// The request carries no identity.  The client should authenticate
    /// and retry.  Returns 401.
    Unauthenticated,
}

#[derive(Clone, Debug)]
pub struct AuthPolicy {
    /// OR semantics: any one matched rule grants access.
    /// Must be non-empty (enforced at config parse time).
    pub allow: Vec<AuthRule>,
    /// Deny takes precedence over allow.  An authenticated principal
    /// that matches any deny rule gets 403 regardless of allow rules.
    pub deny: Vec<AuthRule>,
}

impl AuthPolicy {
    pub fn evaluate(&self, principal: &Principal) -> AuthDecision {
        let id = match principal {
            // No identity present — challenge the client to authenticate.
            // Deny rules are not checked: anonymous has no identity to
            // match against user/group/authenticated rules.
            Principal::Anonymous => return AuthDecision::Unauthenticated,
            Principal::Authenticated(id) => id,
        };
        if self.deny.iter().any(|r| rule_matches(r, id)) {
            return AuthDecision::Deny;
        }
        if self.allow.iter().any(|r| rule_matches(r, id)) {
            AuthDecision::Allow
        } else {
            AuthDecision::Deny
        }
    }
}

fn rule_matches(rule: &AuthRule, id: &Identity) -> bool {
    match rule {
        AuthRule::Authenticated => true,
        AuthRule::User(u) => &id.username == u,
        AuthRule::Group(g) => id.groups.contains(g),
    }
}

/// Pluggable authentication mechanism.
///
/// Implementations inspect the request (headers, cookies, tokens)
/// and return the caller's identity.  `AnonymousAuthenticator` is the
/// default until a real mechanism is configured.
#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, req: &Request<Incoming>) -> Principal;
}

/// Always returns `Principal::Anonymous`.
/// Replaced by a real implementation once auth config is wired up.
pub struct AnonymousAuthenticator;

#[async_trait]
impl Authenticator for AnonymousAuthenticator {
    async fn authenticate(&self, _req: &Request<Incoming>) -> Principal {
        Principal::Anonymous
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(username: &str, groups: &[&str]) -> Identity {
        Identity {
            username: username.to_string(),
            groups: groups.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn allow(rules: Vec<AuthRule>) -> AuthPolicy {
        AuthPolicy { allow: rules, deny: vec![] }
    }

    fn auth(allow: Vec<AuthRule>, deny: Vec<AuthRule>) -> AuthPolicy {
        AuthPolicy { allow, deny }
    }

    // ── allow rules ───────────────────────────────────────────────

    #[test]
    fn anonymous_always_unauthenticated() {
        for rule in [
            AuthRule::Authenticated,
            AuthRule::User("alice".into()),
            AuthRule::Group("admin".into()),
        ] {
            assert_eq!(
                allow(vec![rule]).evaluate(&Principal::Anonymous),
                AuthDecision::Unauthenticated
            );
        }
    }

    #[test]
    fn authenticated_rule_accepts_any_logged_in_user() {
        let p = allow(vec![AuthRule::Authenticated]);
        assert_eq!(
            p.evaluate(&Principal::Authenticated(identity("alice", &[]))),
            AuthDecision::Allow
        );
    }

    #[test]
    fn user_rule_matches_exact_username() {
        let p = allow(vec![AuthRule::User("alice".into())]);
        assert_eq!(
            p.evaluate(&Principal::Authenticated(identity("alice", &[]))),
            AuthDecision::Allow
        );
        assert_eq!(
            p.evaluate(&Principal::Authenticated(identity("bob", &[]))),
            AuthDecision::Deny
        );
    }

    #[test]
    fn group_rule_matches_membership() {
        let p = allow(vec![AuthRule::Group("admin".into())]);
        assert_eq!(
            p.evaluate(&Principal::Authenticated(
                identity("alice", &["admin", "users"])
            )),
            AuthDecision::Allow
        );
        assert_eq!(
            p.evaluate(&Principal::Authenticated(
                identity("bob", &["users"])
            )),
            AuthDecision::Deny
        );
    }

    #[test]
    fn multiple_allow_rules_are_or() {
        let p = allow(vec![
            AuthRule::Group("admin".into()),
            AuthRule::User("alice".into()),
        ]);
        // alice matches the user rule even though she's not in admin
        assert_eq!(
            p.evaluate(&Principal::Authenticated(
                identity("alice", &["users"])
            )),
            AuthDecision::Allow
        );
        // bob matches the group rule
        assert_eq!(
            p.evaluate(&Principal::Authenticated(
                identity("bob", &["admin"])
            )),
            AuthDecision::Allow
        );
        // charlie matches neither
        assert_eq!(
            p.evaluate(&Principal::Authenticated(
                identity("charlie", &["users"])
            )),
            AuthDecision::Deny
        );
    }

    // ── deny rules ────────────────────────────────────────────────

    #[test]
    fn deny_overrides_matching_allow_rule() {
        // mallory is in "users" (allow) but also in "banned" (deny)
        let p = auth(
            vec![AuthRule::Group("users".into())],
            vec![AuthRule::Group("banned".into())],
        );
        assert_eq!(
            p.evaluate(&Principal::Authenticated(
                identity("mallory", &["users", "banned"])
            )),
            AuthDecision::Deny
        );
        // alice is in "users" but not "banned" — allow stands
        assert_eq!(
            p.evaluate(&Principal::Authenticated(
                identity("alice", &["users"])
            )),
            AuthDecision::Allow
        );
    }

    #[test]
    fn deny_user_blocks_specific_user() {
        let p = auth(
            vec![AuthRule::Authenticated],
            vec![AuthRule::User("mallory".into())],
        );
        assert_eq!(
            p.evaluate(&Principal::Authenticated(identity("mallory", &[]))),
            AuthDecision::Deny
        );
        assert_eq!(
            p.evaluate(&Principal::Authenticated(identity("alice", &[]))),
            AuthDecision::Allow
        );
    }

    #[test]
    fn deny_authenticated_blocks_all_logged_in_users() {
        // "deny authenticated" with no deny-bypassing allow is unusual
        // but parseable; useful if the allow rules are only for specific
        // anonymous-visible paths and this test validates the logic.
        let p = auth(
            vec![AuthRule::User("service-account".into())],
            vec![AuthRule::Authenticated],
        );
        // Everyone who is authenticated gets denied...
        assert_eq!(
            p.evaluate(&Principal::Authenticated(
                identity("service-account", &[])
            )),
            AuthDecision::Deny
        );
        // ...and anonymous gets challenged
        assert_eq!(
            p.evaluate(&Principal::Anonymous),
            AuthDecision::Unauthenticated
        );
    }

    #[test]
    fn deny_does_not_affect_anonymous() {
        // Anonymous users always get Unauthenticated regardless of deny rules.
        let p = auth(
            vec![AuthRule::Authenticated],
            vec![AuthRule::User("nobody".into())],
        );
        assert_eq!(
            p.evaluate(&Principal::Anonymous),
            AuthDecision::Unauthenticated
        );
    }
}
