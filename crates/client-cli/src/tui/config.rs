//! TUI 本地配置（持久化到 ~/.nyx/config.json）。
//!
//! 目前只存命令别名（alias）。读写均为 best-effort：文件不存在或解析失败
//! 时回退到空配置，绝不让 TUI 因为配置问题起不来。

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;

/// TUI 本地配置，存 `$HOME/.nyx/config.json`。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct Config {
    /// 命令别名表：name -> 展开后的 shell 命令串。
    #[serde(default)]
    pub aliases: HashMap<String, String>,
    /// 主题选择："mocha"(默认) / "frappe" / "macchiato" / "highcontrast" / "nocolor"。
    /// 启动时传给 `theme::init`；`NO_COLOR` 环境变量优先级更高。
    #[serde(default)]
    pub theme: String,
}

impl Config {
    /// 配置文件路径：`$HOME/.nyx/config.json`。
    pub(crate) fn path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(home).join(".nyx").join("config.json")
    }

    /// 读取配置。失败一律返回空 `Config`。
    pub(crate) fn load() -> Config {
        match std::fs::read(Self::path()) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Config::default(),
        }
    }

    /// 写入配置。会自动创建 `~/.nyx` 目录。
    pub(crate) fn save(&self) -> std::io::Result<()> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    /// 增加或覆盖一个别名。
    pub(crate) fn set_alias(&mut self, name: &str, cmd: &str) {
        self.aliases.insert(name.into(), cmd.into());
    }

    /// 删除一个别名。命中返回 `true`。
    pub(crate) fn del_alias(&mut self, name: &str) -> bool {
        self.aliases.remove(name).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_no_aliases() {
        assert!(Config::default().aliases.is_empty());
    }

    #[test]
    fn set_and_del_alias() {
        let mut cfg = Config::default();
        cfg.set_alias("ll", "ls -la");
        assert_eq!(cfg.aliases.get("ll").map(|s| s.as_str()), Some("ls -la"));
        assert!(cfg.del_alias("ll"));
        assert!(!cfg.del_alias("ll"));
    }
}
