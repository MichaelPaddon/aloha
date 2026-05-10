use ::kdl::{KdlNode, KdlValue};
use anyhow::anyhow;

pub(super) fn arg_str(node: &KdlNode, pos: usize) -> Option<String> {
    node.get(pos)?.as_string().map(String::from)
}

// Returns every positional string argument of a node, in order.
// (KDL distinguishes positional `entries` -- name() is None -- from
// named properties.)
pub(super) fn positional_strs(node: &KdlNode) -> Vec<String> {
    node.entries()
        .iter()
        .filter(|e| e.name().is_none())
        .filter_map(|e| e.value().as_string().map(String::from))
        .collect()
}

pub(super) fn req_arg_str(
    node: &KdlNode,
    pos: usize,
) -> anyhow::Result<String> {
    arg_str(node, pos).ok_or_else(|| {
        anyhow!(
            "'{}' missing required argument at position {pos}",
            node.name().value()
        )
    })
}

// Returns the first positional argument of the named child node.
pub(super) fn child_str(node: &KdlNode, key: &str) -> Option<String> {
    node.children()?
        .nodes()
        .iter()
        .find(|n| n.name().value() == key)
        .and_then(|n| arg_str(n, 0))
}

// Returns the value of a string-typed entry, looking first at named
// properties on the node and falling back to a same-named child node.
// Lets callers accept either property form (`tls-file cert="..."`) or
// block form (`tls-file { cert "..." }`).
pub(super) fn prop_or_child_str(node: &KdlNode, key: &str) -> Option<String> {
    node.get(key)
        .and_then(|e| e.as_string())
        .map(String::from)
        .or_else(|| child_str(node, key))
}

pub(super) fn prop_or_child_bool(node: &KdlNode, key: &str) -> Option<bool> {
    node.get(key)
        .and_then(|e| e.as_bool())
        .or_else(|| child_bool(node, key))
}

pub(super) fn prop_or_child_i64(node: &KdlNode, key: &str) -> Option<i64> {
    node.get(key)
        .and_then(|e| e.as_integer().map(|n| n as i64))
        .or_else(|| child_i64(node, key))
}

pub(super) fn req_child_str(
    node: &KdlNode,
    key: &str,
) -> anyhow::Result<String> {
    child_str(node, key).ok_or_else(|| {
        anyhow!(
            "'{}' missing required child node '{key}'",
            node.name().value()
        )
    })
}

// Returns the first positional argument of the named child node as i64.
pub(super) fn child_i64(node: &KdlNode, key: &str) -> Option<i64> {
    let children = node.children()?;
    let child = children.nodes().iter().find(|n| n.name().value() == key)?;
    child.get(0)?.as_integer().map(|n| n as i64)
}

pub(super) fn child_bool(node: &KdlNode, key: &str) -> Option<bool> {
    node.children()?
        .nodes()
        .iter()
        .find(|n| n.name().value() == key)?
        .get(0)?
        .as_bool()
}

// Like child_str but distinguishes absent / null / string, mirroring
// prop_null_or_str for child nodes.
pub(super) fn child_null_or_str(
    node: &KdlNode,
    key: &str,
) -> Option<Option<String>> {
    let children = node.children()?;
    let child = children.nodes().iter().find(|n| n.name().value() == key)?;
    Some(match child.get(0)? {
        KdlValue::Null => None,
        other => other.as_string().map(String::from),
    })
}
