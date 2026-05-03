// Composable named-block access control system.
//
// Blocks contain sequentially-evaluated statements.  Each statement has
// conditions (AND across types, OR within type) and one of four actions:
//
//   allow    — terminal allow (propagates up through Apply frames)
//   deny     — terminal deny
//   redirect — terminal redirect
//   pass     — non-terminal: exit current block; caller continues
//
// Apply(sub-block) evaluates the sub-block; Terminal outcomes propagate
// up; Next (pass or block fall-through) continues in the calling block.
//
// Top-level evaluate() maps a final Next to Deny(default_deny_code),
// which is 401 when the block contains identity conditions, 403 otherwise.

use crate::auth::Principal;
use async_trait::async_trait;
use ipnet::IpNet;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

// -- Auth provider ------------------------------------------------

/// Provides authenticated identity on demand inside the evaluator.
/// Called at most once per request (result is cached in EvalContext).
#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authenticate(&self) -> Principal;
}

/// Always returns `Principal::Anonymous`.  Used for TCP proxy contexts
/// where HTTP authentication is not available.
pub struct AnonymousAuthProvider;

#[async_trait]
impl AuthProvider for AnonymousAuthProvider {
    async fn authenticate(&self) -> Principal {
        Principal::Anonymous
    }
}

// -- Conditions and actions ----------------------------------------

#[derive(Clone, Debug)]
pub enum AccessCondition {
    Ip(IpNet),
    /// ISO 3166-1 alpha-2 country code, stored uppercase (e.g. "US").
    Country(String),
    User(String),
    Group(String),
    Authenticated,
}

#[derive(Clone, Debug)]
pub enum AccessAction {
    Allow,
    Deny { code: u16 },
    Redirect { to: String, code: u16 },
    /// Non-terminal: exit the current block; the caller continues.
    Pass,
}

// -- Block structure -----------------------------------------------

#[derive(Clone, Debug)]
pub enum AccessStatement {
    Rule {
        conditions: Vec<AccessCondition>,
        action: AccessAction,
    },
    /// Evaluate a pre-resolved named block.
    Apply(Arc<AccessBlock>),
}

#[derive(Clone, Debug)]
pub struct AccessBlock {
    pub statements: Vec<AccessStatement>,
    /// Pre-computed (recursively): true iff any statement uses Country.
    /// Lets the caller skip the GeoIP lookup when unnecessary.
    pub needs_geoip: bool,
    /// Pre-computed (recursively): true iff any statement uses an
    /// identity condition (User / Group / Authenticated).
    pub needs_auth: bool,
    /// Implicit deny code when the block falls through without a
    /// terminal decision: 401 when the block tests identity, 403 otherwise.
    pub default_deny_code: u16,
}

impl AccessBlock {
    pub fn new(statements: Vec<AccessStatement>) -> Self {
        let needs_geoip = statements.iter().any(|s| s.needs_geoip());
        let needs_auth  = statements.iter().any(|s| s.needs_auth());
        AccessBlock {
            statements,
            needs_geoip,
            needs_auth,
            default_deny_code: if needs_auth { 401 } else { 403 },
        }
    }

    pub async fn evaluate(
        &self,
        ctx: &mut EvalContext<'_>,
    ) -> AccessOutcome {
        match evaluate_block(self, ctx).await {
            BlockResult::Terminal(out) => out,
            BlockResult::Next =>
                AccessOutcome::Deny(self.default_deny_code),
        }
    }
}

impl AccessStatement {
    fn needs_geoip(&self) -> bool {
        match self {
            Self::Rule { conditions, .. } => {
                conditions.iter().any(|c| {
                    matches!(c, AccessCondition::Country(_))
                })
            }
            Self::Apply(b) => b.needs_geoip,
        }
    }

    fn needs_auth(&self) -> bool {
        match self {
            Self::Rule { conditions, .. } => {
                conditions.iter().any(|c| {
                    matches!(
                        c,
                        AccessCondition::User(_)
                            | AccessCondition::Group(_)
                            | AccessCondition::Authenticated
                    )
                })
            }
            Self::Apply(b) => b.needs_auth,
        }
    }
}

// -- Public outcome ------------------------------------------------

#[derive(Debug)]
pub enum AccessOutcome {
    Allow,
    Deny(u16),
    Redirect(String, u16),
}

// -- Evaluation context --------------------------------------------

pub struct EvalContext<'a> {
    pub peer: IpAddr,
    pub country: Option<&'a str>,
    // None until the first identity condition is evaluated.
    principal: Option<Principal>,
    auth: &'a dyn AuthProvider,
}

impl<'a> EvalContext<'a> {
    pub fn new(
        peer: IpAddr,
        country: Option<&'a str>,
        auth: &'a dyn AuthProvider,
    ) -> Self {
        EvalContext {
            peer: normalise(peer),
            country,
            principal: None,
            auth,
        }
    }

    /// Return the cached principal after evaluation for use by
    /// header-rule substitution.
    pub fn take_principal(self) -> Principal {
        self.principal.unwrap_or(Principal::Anonymous)
    }
}

// -- Internal evaluation -------------------------------------------

enum BlockResult {
    Terminal(AccessOutcome),
    Next,
}

// Box the future so recursive Apply chains compile without a fixed
// stack frame size.
fn evaluate_block<'a>(
    block: &'a AccessBlock,
    ctx: &'a mut EvalContext<'_>,
) -> Pin<Box<dyn Future<Output = BlockResult> + Send + 'a>> {
    Box::pin(async move {
        for stmt in &block.statements {
            match stmt {
                AccessStatement::Rule { conditions, action } => {
                    if condition_matches(conditions, ctx).await {
                        return match action {
                            AccessAction::Allow => {
                                BlockResult::Terminal(
                                    AccessOutcome::Allow,
                                )
                            }
                            AccessAction::Deny { code } => {
                                BlockResult::Terminal(
                                    AccessOutcome::Deny(*code),
                                )
                            }
                            AccessAction::Redirect { to, code } => {
                                BlockResult::Terminal(
                                    AccessOutcome::Redirect(
                                        to.clone(),
                                        *code,
                                    ),
                                )
                            }
                            AccessAction::Pass => BlockResult::Next,
                        };
                    }
                }
                AccessStatement::Apply(sub) => {
                    match evaluate_block(sub, ctx).await {
                        BlockResult::Terminal(out) => {
                            return BlockResult::Terminal(out);
                        }
                        BlockResult::Next => {}
                    }
                }
            }
        }
        BlockResult::Next
    })
}

// Evaluates conditions for a single rule against the context.
// Conditions are AND across types, OR within the same type.
// Non-identity conditions (IP, country) are checked first; auth is
// only called when those pass, avoiding unnecessary authentication.
async fn condition_matches(
    conditions: &[AccessCondition],
    ctx: &mut EvalContext<'_>,
) -> bool {
    if conditions.is_empty() {
        return true;
    }

    let mut has_ip = false;
    let mut ip_ok = false;
    let mut has_country = false;
    let mut country_ok = false;
    let mut needs_auth = false;

    for cond in conditions {
        match cond {
            AccessCondition::Ip(net) => {
                has_ip = true;
                ip_ok |= net.contains(&ctx.peer);
            }
            AccessCondition::Country(code) => {
                has_country = true;
                country_ok |= ctx
                    .country
                    .map_or(false, |c| c == code.as_str());
            }
            AccessCondition::User(_)
            | AccessCondition::Group(_)
            | AccessCondition::Authenticated => {
                needs_auth = true;
            }
        }
    }

    // Short-circuit: skip authentication when non-auth checks fail.
    if has_ip && !ip_ok {
        return false;
    }
    if has_country && !country_ok {
        return false;
    }

    if needs_auth {
        if ctx.principal.is_none() {
            ctx.principal = Some(ctx.auth.authenticate().await);
        }
        let principal = ctx.principal.as_ref().unwrap();

        let mut has_user = false;
        let mut user_ok = false;
        let mut has_group = false;
        let mut group_ok = false;
        let mut has_auth_flag = false;

        for cond in conditions {
            match cond {
                AccessCondition::User(u) => {
                    has_user = true;
                    if let Principal::Authenticated(id) = principal {
                        user_ok |= &id.username == u;
                    }
                }
                AccessCondition::Group(g) => {
                    has_group = true;
                    if let Principal::Authenticated(id) = principal {
                        group_ok |= id.groups.contains(g);
                    }
                }
                AccessCondition::Authenticated => {
                    has_auth_flag = true;
                }
                _ => {}
            }
        }

        if has_user && !user_ok {
            return false;
        }
        if has_group && !group_ok {
            return false;
        }
        if has_auth_flag
            && !matches!(principal, Principal::Authenticated(_))
        {
            return false;
        }
    }

    true
}

// Normalise IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) to plain IPv4
// so that `ip "10.0.0.0/8"` matches whether the peer is reported as
// 10.1.2.3 or ::ffff:10.1.2.3.
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
    use crate::auth::Identity;
    use std::sync::Mutex;

    // -- Mock auth provider ------------------------------------------

    struct MockAuth {
        identity: Option<(String, Vec<String>)>,
        calls: Mutex<usize>,
    }

    impl MockAuth {
        fn anon() -> Self {
            MockAuth { identity: None, calls: Mutex::new(0) }
        }

        fn authed(username: &str, groups: &[&str]) -> Self {
            MockAuth {
                identity: Some((
                    username.to_owned(),
                    groups.iter().map(|s| s.to_string()).collect(),
                )),
                calls: Mutex::new(0),
            }
        }

        fn call_count(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    #[async_trait]
    impl AuthProvider for MockAuth {
        async fn authenticate(&self) -> Principal {
            *self.calls.lock().unwrap() += 1;
            match &self.identity {
                None => Principal::Anonymous,
                Some((username, groups)) => {
                    Principal::Authenticated(Identity {
                        username: username.clone(),
                        groups: groups.clone(),
                    })
                }
            }
        }
    }

    // -- Test helpers -----------------------------------------------

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }
    fn net(s: &str) -> IpNet { s.parse().unwrap() }

    fn ctx<'a>(
        peer: &str,
        country: Option<&'a str>,
        auth: &'a dyn AuthProvider,
    ) -> EvalContext<'a> {
        EvalContext::new(ip(peer), country, auth)
    }

    fn rule(
        conds: Vec<AccessCondition>,
        action: AccessAction,
    ) -> AccessStatement {
        AccessStatement::Rule { conditions: conds, action }
    }

    fn block(stmts: Vec<AccessStatement>) -> Arc<AccessBlock> {
        Arc::new(AccessBlock::new(stmts))
    }

    // -- Basic terminal actions -------------------------------------

    #[tokio::test]
    async fn allow_terminal() {
        let b = block(vec![rule(vec![], AccessAction::Allow)]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, AccessOutcome::Allow));
    }

    #[tokio::test]
    async fn deny_terminal() {
        let b = block(vec![
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(
            b.evaluate(&mut c).await,
            AccessOutcome::Deny(403)
        ));
    }

    #[tokio::test]
    async fn redirect_terminal() {
        let b = block(vec![rule(vec![], AccessAction::Redirect {
            to: "/login".into(),
            code: 302,
        })]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        match b.evaluate(&mut c).await {
            AccessOutcome::Redirect(to, code) => {
                assert_eq!(to, "/login");
                assert_eq!(code, 302);
            }
            _ => panic!("expected redirect"),
        }
    }

    #[tokio::test]
    async fn empty_block_implicit_deny_403() {
        let b = block(vec![]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(
            b.evaluate(&mut c).await,
            AccessOutcome::Deny(403)
        ));
    }

    // -- Pass action ------------------------------------------------

    #[tokio::test]
    async fn pass_at_top_level_is_implicit_deny() {
        // pass at top level = block fell through = implicit deny
        let b = block(vec![rule(vec![], AccessAction::Pass)]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(
            b.evaluate(&mut c).await,
            AccessOutcome::Deny(403)
        ));
    }

    #[tokio::test]
    async fn pass_exits_block_caller_continues() {
        // Inner block: pass (non-terminal). Outer block: allow after Apply.
        let inner = block(vec![rule(vec![], AccessAction::Pass)]);
        let outer = block(vec![
            AccessStatement::Apply(inner),
            rule(vec![], AccessAction::Allow),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(
            outer.evaluate(&mut c).await,
            AccessOutcome::Allow
        ));
    }

    // -- Apply semantics --------------------------------------------

    #[tokio::test]
    async fn allow_from_apply_is_terminal() {
        // allow inside an applied sub-block propagates immediately;
        // the rule after Apply must not be reached.
        let inner = block(vec![rule(vec![], AccessAction::Allow)]);
        let outer = block(vec![
            AccessStatement::Apply(inner),
            rule(vec![], AccessAction::Deny { code: 999 }),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(
            outer.evaluate(&mut c).await,
            AccessOutcome::Allow
        ));
    }

    #[tokio::test]
    async fn deny_from_apply_is_terminal() {
        let inner = block(vec![
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let outer = block(vec![
            AccessStatement::Apply(inner),
            rule(vec![], AccessAction::Allow),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(
            outer.evaluate(&mut c).await,
            AccessOutcome::Deny(403)
        ));
    }

    #[tokio::test]
    async fn apply_fallthrough_continues_in_caller() {
        // Inner block has a rule that doesn't match → falls through.
        // Outer block's allow after the Apply must be reached.
        let inner = block(vec![rule(
            vec![AccessCondition::Ip(net("10.0.0.0/8"))],
            AccessAction::Deny { code: 403 },
        )]);
        let outer = block(vec![
            AccessStatement::Apply(inner),
            rule(vec![], AccessAction::Allow),
        ]);
        let a = MockAuth::anon();
        // 1.2.3.4 doesn't match 10.0.0.0/8; inner falls through.
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(
            outer.evaluate(&mut c).await,
            AccessOutcome::Allow
        ));
    }

    // -- Chained apply: geo-filter + require-auth pattern -----------

    #[tokio::test]
    async fn chained_apply_geo_then_auth() {
        // geo-filter: pass if US, else deny 403
        let geo = block(vec![
            rule(
                vec![AccessCondition::Country("US".into())],
                AccessAction::Pass,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        // require-auth: pass if authenticated, else deny 401
        let require_auth = block(vec![
            rule(
                vec![AccessCondition::Authenticated],
                AccessAction::Pass,
            ),
            rule(vec![], AccessAction::Deny { code: 401 }),
        ]);
        let policy = block(vec![
            AccessStatement::Apply(geo),
            AccessStatement::Apply(require_auth),
            rule(vec![], AccessAction::Allow),
        ]);

        // US + authenticated → allow
        let a = MockAuth::authed("alice", &[]);
        let mut c = ctx("1.2.3.4", Some("US"), &a);
        assert!(matches!(
            policy.evaluate(&mut c).await,
            AccessOutcome::Allow
        ));

        // US + anonymous → 401
        let a2 = MockAuth::anon();
        let mut c2 = ctx("1.2.3.4", Some("US"), &a2);
        assert!(matches!(
            policy.evaluate(&mut c2).await,
            AccessOutcome::Deny(401)
        ));

        // non-US → 403 (geo-filter denies before auth is checked)
        let a3 = MockAuth::authed("alice", &[]);
        let mut c3 = ctx("1.2.3.4", Some("DE"), &a3);
        assert!(matches!(
            policy.evaluate(&mut c3).await,
            AccessOutcome::Deny(403)
        ));
    }

    // -- Lazy authentication ----------------------------------------

    #[tokio::test]
    async fn lazy_auth_not_called_for_ip_only_policy() {
        let a = MockAuth::anon();
        let b = block(vec![
            rule(
                vec![AccessCondition::Ip(net("10.0.0.0/8"))],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let mut c = ctx("10.0.0.1", None, &a);
        b.evaluate(&mut c).await;
        assert_eq!(
            a.call_count(), 0,
            "auth must not be called for IP-only policy"
        );
    }

    #[tokio::test]
    async fn lazy_auth_called_once_even_with_multiple_identity_conds() {
        let a = MockAuth::authed("alice", &["admin"]);
        // Two identity conditions in one rule → auth called once.
        let b = block(vec![rule(
            vec![
                AccessCondition::Authenticated,
                AccessCondition::Group("admin".into()),
            ],
            AccessAction::Allow,
        )]);
        let mut c = ctx("1.2.3.4", None, &a);
        b.evaluate(&mut c).await;
        assert_eq!(a.call_count(), 1, "auth must be called exactly once");
    }

    #[tokio::test]
    async fn lazy_auth_skipped_when_ip_fails_first() {
        let a = MockAuth::authed("alice", &[]);
        // Rule: IP AND Authenticated.  IP doesn't match → auth skipped.
        let b = block(vec![
            rule(
                vec![
                    AccessCondition::Ip(net("10.0.0.0/8")),
                    AccessCondition::Authenticated,
                ],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let mut c = ctx("1.2.3.4", None, &a);
        b.evaluate(&mut c).await;
        assert_eq!(
            a.call_count(), 0,
            "auth must not be called when IP check fails first"
        );
    }

    #[tokio::test]
    async fn lazy_auth_skipped_when_country_fails_first() {
        let a = MockAuth::authed("alice", &[]);
        let b = block(vec![
            rule(
                vec![
                    AccessCondition::Country("US".into()),
                    AccessCondition::Authenticated,
                ],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        // DE does not match US → auth skipped
        let mut c = ctx("1.2.3.4", Some("DE"), &a);
        b.evaluate(&mut c).await;
        assert_eq!(
            a.call_count(), 0,
            "auth must not be called when country check fails first"
        );
    }

    // -- Default deny codes -----------------------------------------

    #[tokio::test]
    async fn default_deny_401_for_block_with_auth_conditions() {
        let b = block(vec![rule(
            vec![AccessCondition::Authenticated],
            AccessAction::Pass,
        )]);
        assert_eq!(b.default_deny_code, 401);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        // Anonymous: pass rule doesn't match, block falls through → 401
        assert!(matches!(
            b.evaluate(&mut c).await,
            AccessOutcome::Deny(401)
        ));
    }

    #[tokio::test]
    async fn default_deny_403_for_ip_only_block() {
        let b = block(vec![rule(
            vec![AccessCondition::Ip(net("10.0.0.0/8"))],
            AccessAction::Pass,
        )]);
        assert_eq!(b.default_deny_code, 403);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(
            b.evaluate(&mut c).await,
            AccessOutcome::Deny(403)
        ));
    }

    #[tokio::test]
    async fn default_deny_401_propagates_from_nested_auth_block() {
        // An outer block that applies an auth block inherits 401 default.
        let auth_block = block(vec![rule(
            vec![AccessCondition::Authenticated],
            AccessAction::Pass,
        )]);
        let outer = AccessBlock::new(vec![
            AccessStatement::Apply(auth_block),
        ]);
        assert_eq!(outer.default_deny_code, 401);
    }

    // -- IP conditions ----------------------------------------------

    #[tokio::test]
    async fn ip_in_range_allows() {
        let b = block(vec![
            rule(
                vec![AccessCondition::Ip(net("10.0.0.0/8"))],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("10.1.2.3", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, AccessOutcome::Allow));
    }

    #[tokio::test]
    async fn ip_out_of_range_falls_through() {
        let b = block(vec![
            rule(
                vec![AccessCondition::Ip(net("10.0.0.0/8"))],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(
            b.evaluate(&mut c).await,
            AccessOutcome::Deny(403)
        ));
    }

    #[tokio::test]
    async fn two_ip_conditions_are_or() {
        let b = block(vec![
            rule(
                vec![
                    AccessCondition::Ip(net("10.0.0.0/8")),
                    AccessCondition::Ip(net("192.168.0.0/16")),
                ],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let a = MockAuth::anon();
        for peer in ["10.0.0.1", "192.168.1.1"] {
            let mut c = ctx(peer, None, &a);
            assert!(
                matches!(b.evaluate(&mut c).await, AccessOutcome::Allow),
                "{peer} should match"
            );
        }
        let mut c = ctx("8.8.8.8", None, &a);
        assert!(matches!(
            b.evaluate(&mut c).await,
            AccessOutcome::Deny(403)
        ));
    }

    // -- Country conditions -----------------------------------------

    #[tokio::test]
    async fn country_allow_matching_code() {
        let b = block(vec![
            rule(
                vec![AccessCondition::Country("US".into())],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("1.2.3.4", Some("US"), &a);
        assert!(matches!(b.evaluate(&mut c).await, AccessOutcome::Allow));
    }

    #[tokio::test]
    async fn country_none_never_satisfies_condition() {
        let b = block(vec![
            rule(
                vec![AccessCondition::Country("US".into())],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("127.0.0.1", None, &a);
        assert!(matches!(
            b.evaluate(&mut c).await,
            AccessOutcome::Deny(403)
        ));
    }

    #[tokio::test]
    async fn multiple_country_codes_are_or() {
        let b = block(vec![
            rule(
                vec![
                    AccessCondition::Country("US".into()),
                    AccessCondition::Country("CA".into()),
                    AccessCondition::Country("GB".into()),
                ],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let a = MockAuth::anon();
        for cc in ["US", "CA", "GB"] {
            let mut c = ctx("1.2.3.4", Some(cc), &a);
            assert!(
                matches!(b.evaluate(&mut c).await, AccessOutcome::Allow),
                "{cc} should match"
            );
        }
        let mut c = ctx("1.2.3.4", Some("DE"), &a);
        assert!(matches!(
            b.evaluate(&mut c).await,
            AccessOutcome::Deny(403)
        ));
    }

    // -- Identity conditions ----------------------------------------

    #[tokio::test]
    async fn authenticated_matches_logged_in_user() {
        let b = block(vec![
            rule(
                vec![AccessCondition::Authenticated],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let authed = MockAuth::authed("alice", &[]);
        let mut c = ctx("1.2.3.4", None, &authed);
        assert!(matches!(b.evaluate(&mut c).await, AccessOutcome::Allow));

        let anon = MockAuth::anon();
        let mut c2 = ctx("1.2.3.4", None, &anon);
        assert!(matches!(
            b.evaluate(&mut c2).await,
            AccessOutcome::Deny(403)
        ));
    }

    #[tokio::test]
    async fn user_condition_exact_name() {
        let b = block(vec![
            rule(
                vec![AccessCondition::User("alice".into())],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let alice = MockAuth::authed("alice", &[]);
        let mut c = ctx("1.2.3.4", None, &alice);
        assert!(matches!(b.evaluate(&mut c).await, AccessOutcome::Allow));

        let bob = MockAuth::authed("bob", &[]);
        let mut c2 = ctx("1.2.3.4", None, &bob);
        assert!(matches!(
            b.evaluate(&mut c2).await,
            AccessOutcome::Deny(403)
        ));
    }

    #[tokio::test]
    async fn group_condition_membership() {
        let b = block(vec![
            rule(
                vec![AccessCondition::Group("admin".into())],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let admin = MockAuth::authed("alice", &["admin"]);
        let mut c = ctx("1.2.3.4", None, &admin);
        assert!(matches!(b.evaluate(&mut c).await, AccessOutcome::Allow));

        let user = MockAuth::authed("bob", &["users"]);
        let mut c2 = ctx("1.2.3.4", None, &user);
        assert!(matches!(
            b.evaluate(&mut c2).await,
            AccessOutcome::Deny(403)
        ));
    }

    #[tokio::test]
    async fn multiple_user_conditions_are_or() {
        let b = block(vec![
            rule(
                vec![
                    AccessCondition::User("alice".into()),
                    AccessCondition::User("bob".into()),
                ],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let a = MockAuth::authed("alice", &[]);
        let mut c = ctx("1.2.3.4", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, AccessOutcome::Allow));

        let b2 = MockAuth::authed("bob", &[]);
        let mut c2 = ctx("1.2.3.4", None, &b2);
        assert!(matches!(b.evaluate(&mut c2).await, AccessOutcome::Allow));

        let charlie = MockAuth::authed("charlie", &[]);
        let mut c3 = ctx("1.2.3.4", None, &charlie);
        assert!(matches!(
            b.evaluate(&mut c3).await,
            AccessOutcome::Deny(403)
        ));
    }

    #[tokio::test]
    async fn multiple_group_conditions_are_or() {
        let b = block(vec![
            rule(
                vec![
                    AccessCondition::Group("admin".into()),
                    AccessCondition::Group("ops".into()),
                ],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let admin = MockAuth::authed("alice", &["admin"]);
        let mut c1 = ctx("1.2.3.4", None, &admin);
        assert!(matches!(b.evaluate(&mut c1).await, AccessOutcome::Allow));

        let ops = MockAuth::authed("bob", &["ops"]);
        let mut c2 = ctx("1.2.3.4", None, &ops);
        assert!(matches!(b.evaluate(&mut c2).await, AccessOutcome::Allow));

        let user = MockAuth::authed("charlie", &["users"]);
        let mut c3 = ctx("1.2.3.4", None, &user);
        assert!(matches!(
            b.evaluate(&mut c3).await,
            AccessOutcome::Deny(403)
        ));
    }

    // -- AND across types -------------------------------------------

    #[tokio::test]
    async fn ip_and_group_both_required() {
        let b = block(vec![
            rule(
                vec![
                    AccessCondition::Ip(net("10.0.0.0/8")),
                    AccessCondition::Group("admin".into()),
                ],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let admin = MockAuth::authed("alice", &["admin"]);
        let user  = MockAuth::authed("alice", &["users"]);

        let mut c1 = ctx("10.0.0.1", None, &admin);
        assert!(matches!(b.evaluate(&mut c1).await, AccessOutcome::Allow));
        let mut c2 = ctx("10.0.0.1", None, &user);
        assert!(matches!(
            b.evaluate(&mut c2).await,
            AccessOutcome::Deny(403)
        ));
        let mut c3 = ctx("1.2.3.4", None, &admin);
        assert!(matches!(
            b.evaluate(&mut c3).await,
            AccessOutcome::Deny(403)
        ));
    }

    #[tokio::test]
    async fn ip_and_authenticated_both_required() {
        let b = block(vec![
            rule(
                vec![
                    AccessCondition::Ip(net("10.0.0.0/8")),
                    AccessCondition::Authenticated,
                ],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let authed = MockAuth::authed("alice", &[]);
        let anon = MockAuth::anon();

        let mut c1 = ctx("10.0.0.1", None, &authed);
        assert!(matches!(b.evaluate(&mut c1).await, AccessOutcome::Allow));
        let mut c2 = ctx("10.0.0.1", None, &anon);
        assert!(matches!(
            b.evaluate(&mut c2).await,
            AccessOutcome::Deny(403)
        ));
        let mut c3 = ctx("1.2.3.4", None, &authed);
        assert!(matches!(
            b.evaluate(&mut c3).await,
            AccessOutcome::Deny(403)
        ));
    }

    // -- IPv4-mapped normalisation ----------------------------------

    #[tokio::test]
    async fn ipv4_mapped_v6_matches_v4_rule() {
        let b = block(vec![
            rule(
                vec![AccessCondition::Ip(net("10.0.0.0/8"))],
                AccessAction::Allow,
            ),
            rule(vec![], AccessAction::Deny { code: 403 }),
        ]);
        let a = MockAuth::anon();
        let mapped: IpAddr =
            "::ffff:10.0.0.1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .into();
        let mut c = EvalContext::new(mapped, None, &a);
        assert!(matches!(b.evaluate(&mut c).await, AccessOutcome::Allow));
    }

    // -- needs_geoip / needs_auth flags ----------------------------

    #[tokio::test]
    async fn needs_geoip_true_when_country_in_apply() {
        let inner = block(vec![rule(
            vec![AccessCondition::Country("US".into())],
            AccessAction::Allow,
        )]);
        let outer = AccessBlock::new(vec![
            AccessStatement::Apply(inner),
        ]);
        assert!(outer.needs_geoip);
    }

    #[tokio::test]
    async fn needs_geoip_false_for_ip_only() {
        let b = AccessBlock::new(vec![rule(
            vec![AccessCondition::Ip(net("10.0.0.0/8"))],
            AccessAction::Allow,
        )]);
        assert!(!b.needs_geoip);
    }

    #[tokio::test]
    async fn needs_auth_true_when_group_in_apply() {
        let inner = block(vec![rule(
            vec![AccessCondition::Group("admin".into())],
            AccessAction::Allow,
        )]);
        let outer = AccessBlock::new(vec![
            AccessStatement::Apply(inner),
        ]);
        assert!(outer.needs_auth);
    }

    // -- First-match ordering ---------------------------------------

    #[tokio::test]
    async fn first_matching_rule_wins() {
        let b = block(vec![
            rule(
                vec![AccessCondition::Ip(net("10.0.0.0/8"))],
                AccessAction::Allow,
            ),
            // Second rule also matches but must not be reached.
            rule(
                vec![AccessCondition::Ip(net("10.0.0.0/8"))],
                AccessAction::Deny { code: 403 },
            ),
        ]);
        let a = MockAuth::anon();
        let mut c = ctx("10.0.0.1", None, &a);
        assert!(matches!(b.evaluate(&mut c).await, AccessOutcome::Allow));
    }

    // -- Catch-all (no-condition) rules -----------------------------

    #[tokio::test]
    async fn no_condition_rule_always_matches() {
        let b = block(vec![rule(vec![], AccessAction::Allow)]);
        let a = MockAuth::anon();
        for peer in ["1.2.3.4", "8.8.8.8"] {
            let mut c = ctx(peer, None, &a);
            assert!(
                matches!(b.evaluate(&mut c).await, AccessOutcome::Allow)
            );
        }
    }
}
