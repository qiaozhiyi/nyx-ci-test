//! Session 本地元数据存储 + `/sessions` 过滤语法解析（纯函数）。
//!
//! 服务端 `SessionView` 不含 alias/tag/notes/favorite，这些操作员自定元数据
//! 完全在客户端维护，落到 `~/.nyx/sessions.json`。存取用注入路径可单测，
//! 过滤解析是纯函数。

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// 一个 session 的本地元数据。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionMeta {
    pub alias: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub notes: Option<String>,
}

/// 所有 session 的元数据集合。
#[derive(Default)]
pub struct SessionStore {
    pub map: HashMap<String, SessionMeta>,
}

impl SessionStore {
    pub fn path() -> PathBuf {
        match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(".nyx").join("sessions.json"),
            None => PathBuf::from(".nyx").join("sessions.json"),
        }
    }
    pub fn load() -> SessionStore {
        Self::load_from(&Self::path())
    }
    pub fn load_from(path: &Path) -> SessionStore {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => return SessionStore::default(),
        };
        match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(v) => Self::from_value(&v),
            Err(_) => SessionStore::default(),
        }
    }
    pub fn save(&self) -> std::io::Result<()> {
        self.save_to(&Self::path())
    }
    pub fn save_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let value = self.to_value();
        let pretty = serde_json::to_string_pretty(&value)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, pretty)
    }
    pub fn get(&self, id: &str) -> SessionMeta {
        self.map.get(id).cloned().unwrap_or_default()
    }
    pub fn rename(&mut self, id: &str, name: &str) {
        self.map.entry(id.to_string()).or_default().alias = Some(name.to_string());
    }
    pub fn tag(&mut self, id: &str, tag: &str) {
        let m = self.map.entry(id.to_string()).or_default();
        if !m.tags.iter().any(|t| t == tag) {
            m.tags.push(tag.to_string());
        }
    }
    pub fn untag(&mut self, id: &str, tag: &str) {
        if let Some(m) = self.map.get_mut(id) {
            m.tags.retain(|t| t != tag);
        }
    }
    pub fn toggle_star(&mut self, id: &str) {
        let m = self.map.entry(id.to_string()).or_default();
        m.favorite = !m.favorite;
    }
    pub fn note(&mut self, id: &str, text: &str) {
        self.map.entry(id.to_string()).or_default().notes = Some(text.to_string());
    }

    fn to_value(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        for (id, meta) in &self.map {
            obj.insert(id.clone(), meta_to_value(meta));
        }
        serde_json::Value::Object(obj)
    }
    fn from_value(v: &serde_json::Value) -> SessionStore {
        let mut store = SessionStore::default();
        if let Some(obj) = v.as_object() {
            for (id, meta_v) in obj {
                store.map.insert(id.clone(), meta_from_value(meta_v));
            }
        }
        store
    }
}

fn meta_to_value(m: &SessionMeta) -> serde_json::Value {
    let mut o = serde_json::Map::new();
    o.insert(
        "alias".into(),
        match &m.alias {
            Some(a) => serde_json::Value::String(a.clone()),
            None => serde_json::Value::Null,
        },
    );
    o.insert("favorite".into(), serde_json::Value::Bool(m.favorite));
    o.insert(
        "tags".into(),
        serde_json::Value::Array(m.tags.iter().map(|t| serde_json::Value::String(t.clone())).collect()),
    );
    o.insert(
        "notes".into(),
        match &m.notes {
            Some(n) => serde_json::Value::String(n.clone()),
            None => serde_json::Value::Null,
        },
    );
    serde_json::Value::Object(o)
}

fn meta_from_value(v: &serde_json::Value) -> SessionMeta {
    let mut m = SessionMeta::default();
    if let Some(o) = v.as_object() {
        if let Some(a) = o.get("alias").and_then(|x| x.as_str()) {
            m.alias = Some(a.to_string());
        }
        if let Some(b) = o.get("favorite").and_then(|x| x.as_bool()) {
            m.favorite = b;
        }
        if let Some(arr) = o.get("tags").and_then(|x| x.as_array()) {
            m.tags = arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
        }
        if let Some(n) = o.get("notes").and_then(|x| x.as_str()) {
            m.notes = Some(n.to_string());
        }
    }
    m
}

/// `/sessions <filter>` 过滤条件。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionFilter {
    pub tags: Vec<String>,
    pub star_only: bool,
    pub alias_contains: Option<String>,
}

/// 解析过滤串。纯函数。`tag:x` / `star` / `alias:sub`，不认识的 token 忽略。
pub fn parse_filter(query: &str) -> SessionFilter {
    let mut f = SessionFilter::default();
    for tok in query.split_whitespace() {
        if tok == "star" {
            f.star_only = true;
        } else if let Some(t) = tok.strip_prefix("tag:") {
            if !t.is_empty() && !f.tags.iter().any(|x| x == t) {
                f.tags.push(t.to_string());
            }
        } else if let Some(a) = tok.strip_prefix("alias:") {
            if !a.is_empty() {
                f.alias_contains = Some(a.to_string());
            }
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// 进程内单调计数器，保证并行测试文件名唯一。
    fn counter() -> usize {
        static C: OnceLock<std::sync::atomic::AtomicUsize> = OnceLock::new();
        C.get_or_init(|| std::sync::atomic::AtomicUsize::new(0))
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    fn tmp_path(name: &str) -> PathBuf {
        let pid = std::process::id();
        let c = counter();
        std::env::temp_dir().join(format!("nyx-session-meta-{pid}-{name}-{c}.json"))
    }

    #[test]
    fn parse_filter_empty_is_all() {
        assert_eq!(parse_filter(""), SessionFilter::default());
    }

    #[test]
    fn parse_filter_star_only() {
        assert!(parse_filter("star").star_only);
    }

    #[test]
    fn parse_filter_tags_multiple() {
        assert_eq!(parse_filter("tag:web tag:db").tags, vec!["web".to_string(), "db".to_string()]);
    }

    #[test]
    fn parse_filter_alias_contains() {
        assert_eq!(parse_filter("alias:prod").alias_contains, Some("prod".to_string()));
    }

    #[test]
    fn parse_filter_combined() {
        let f = parse_filter("tag:web star");
        assert_eq!(f.tags, vec!["web".to_string()]);
        assert!(f.star_only);
    }

    #[test]
    fn parse_filter_garbage_ignored() {
        assert_eq!(parse_filter("garbage"), SessionFilter::default());
    }

    #[test]
    fn rename_sets_alias() {
        let mut s = SessionStore::default();
        s.rename("a1", "db-prod");
        assert_eq!(s.get("a1").alias.as_deref(), Some("db-prod"));
    }

    #[test]
    fn tag_dedupes() {
        let mut s = SessionStore::default();
        s.tag("a1", "web");
        s.tag("a1", "web");
        assert_eq!(s.get("a1").tags, vec!["web".to_string()]);
    }

    #[test]
    fn toggle_star_flips() {
        let mut s = SessionStore::default();
        s.toggle_star("a1");
        assert!(s.get("a1").favorite);
        s.toggle_star("a1");
        assert!(!s.get("a1").favorite);
    }

    #[test]
    fn save_load_roundtrip() {
        let p = tmp_path("roundtrip");
        let _ = std::fs::remove_file(&p);
        let mut s = SessionStore::default();
        s.rename("a1", "db-prod");
        s.tag("a1", "web");
        s.toggle_star("a1");
        s.save_to(&p).unwrap();
        let loaded = SessionStore::load_from(&p);
        assert_eq!(loaded.get("a1").alias.as_deref(), Some("db-prod"));
        assert!(loaded.get("a1").favorite);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn load_missing_returns_empty() {
        let p = tmp_path("missing");
        let _ = std::fs::remove_file(&p);
        assert!(SessionStore::load_from(&p).map.is_empty());
    }

    #[test]
    fn load_corrupt_returns_empty() {
        let p = tmp_path("corrupt");
        std::fs::write(&p, "{ not json").unwrap();
        assert!(SessionStore::load_from(&p).map.is_empty());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn save_creates_parent_dir() {
        let dir = std::env::temp_dir().join(format!("nyx-sm-parent-{}-{}", std::process::id(), counter()));
        let p = dir.join("sessions.json");
        let mut s = SessionStore::default();
        s.tag("a1", "web");
        s.save_to(&p).unwrap();
        assert!(p.exists());
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_dir(&dir);
    }
}
