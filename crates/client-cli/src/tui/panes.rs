//! tmux 式窗格树。
//!
//! 一个可递归分割的布局：叶节点持有一个视图（Console/Files/...），
//! 内节点持有一对子窗格 + 分割方向 + 比例。所有树操作（split/close/
//! move_focus/layout）都是纯函数，与渲染解耦，独立 TDD。

#![allow(dead_code)]

use ratatui::layout::{Rect};

// ---- 分割方向 ----

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitDir {
    /// 上下分割（水平线）。
    Horizontal,
    /// 左右分割（垂直线）。
    Vertical,
}

// ---- 窗格视图类型 ----

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PaneView {
    Console,
    SessionList,
    Files,
    Procs,
    Creds,
    Topology,
}

impl PaneView {
    /// Ctrl+1..6 对应的视图。
    pub fn from_index(i: u8) -> Option<PaneView> {
        match i {
            1 => Some(PaneView::Console),
            2 => Some(PaneView::SessionList),
            3 => Some(PaneView::Files),
            4 => Some(PaneView::Procs),
            5 => Some(PaneView::Creds),
            6 => Some(PaneView::Topology),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            PaneView::Console => "console",
            PaneView::SessionList => "sessions",
            PaneView::Files => "files",
            PaneView::Procs => "procs",
            PaneView::Creds => "creds",
            PaneView::Topology => "topology",
        }
    }
}

// ---- 窗格树 ----

/// 一个可递归分割的窗格。
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Pane {
    Leaf {
        id: usize,
        view: PaneView,
        #[serde(default)]
        bound_session: Option<String>,
    },
    Split {
        dir: SplitDir,
        /// 第一个子窗格占比（0.0-1.0）。
        #[serde(default = "default_ratio")]
        ratio: f32,
        children: Vec<Pane>, // 恒为 2 个
    }
}

fn default_ratio() -> f32 { 0.5 }

/// 焦点移动方向。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FocusDir {
    Left,
    Right,
    Up,
    Down,
}

impl Pane {
    /// 创建单叶窗格（默认布局）。
    pub fn single(id: usize) -> Self {
        Pane::Leaf { id, view: PaneView::Console, bound_session: None }
    }

    /// 收集所有叶节点的 (id, view)。
    pub fn leaves(&self) -> Vec<(usize, PaneView)> {
        match self {
            Pane::Leaf { id, view, .. } => vec![(*id, *view)],
            Pane::Split { children, .. } => {
                let mut v = children[0].leaves();
                v.extend(children[1].leaves());
                v
            }
        }
    }

    /// 找当前所有叶 id 中最大的 +1，给新叶分配唯一 id。
    pub fn next_id(&self) -> usize {
        self.leaves().iter().map(|(id, _)| *id).max().unwrap_or(0) + 1
    }

    /// 把 id == target 的叶节点一分为二，返回新树。新叶继承视图。
    /// 新叶成为第一个子，原叶内容成为第二个子（焦点会移到新叶）。
    pub fn split(self, target: usize, dir: SplitDir) -> Pane {
        match self {
            Pane::Leaf { id, view, bound_session } if id == target => {
                let new_id = id + 100; // 简单递增（split 时 next_id 已在外部算好）
                Pane::Split {
                    dir,
                    ratio: 0.5,
                    children: vec![
                        Pane::Leaf { id: new_id, view, bound_session: bound_session.clone() },
                        Pane::Leaf { id, view, bound_session },
                    ],
                }
            }
            Pane::Leaf { .. } => self,
            Pane::Split { dir: d, ratio, children } => {
                Pane::Split {
                    dir: d,
                    ratio,
                    children: children.into_iter().map(|c| c.split(target, dir)).collect(),
                }
            }
        }
    }

    /// 关闭 id == target 的叶节点。父 Split 收缩，兄弟提升。
    /// 返回 (新树, 剩余叶数)。如果只剩一个叶，不删。
    pub fn close(self, target: usize) -> Pane {
        if self.leaf_count() <= 1 {
            return self; // 不删最后一个
        }
        match self.close_inner(target) {
            Some(p) => p,
            None => Pane::single(1), // 不应发生（已检查 leaf_count>1）
        }
    }

    fn close_inner(self, target: usize) -> Option<Pane> {
        match self {
            Pane::Leaf { id, .. } if id == target => None, // 删掉
            Pane::Leaf { .. } => Some(self),
            Pane::Split { children, dir, ratio } => {
                let a = children[0].clone().close_inner(target);
                let b = children[1].clone().close_inner(target);
                match (a, b) {
                    (Some(a), Some(b)) => Some(Pane::Split { dir, ratio, children: vec![a, b] }),
                    (Some(a), None) => Some(a), // b 被删，a 提升
                    (None, Some(b)) => Some(b), // a 被删，b 提升
                    (None, None) => None,
                }
            }
        }
    }

    /// 叶节点总数。
    pub fn leaf_count(&self) -> usize {
        match self {
            Pane::Leaf { .. } => 1,
            Pane::Split { children, .. } => children[0].leaf_count() + children[1].leaf_count(),
        }
    }

    /// 改 id == target 的叶的视图。
    pub fn set_view(self, target: usize, view: PaneView) -> Pane {
        match self {
            Pane::Leaf { id, bound_session, .. } if id == target => {
                Pane::Leaf { id, view, bound_session }
            }
            Pane::Leaf { .. } => self,
            Pane::Split { dir, ratio, children } => Pane::Split {
                dir, ratio,
                children: children.into_iter().map(|c| c.set_view(target, view)).collect(),
            },
        }
    }

    /// 改 id == target 的叶的 bound_session。
    pub fn set_session(self, target: usize, session: Option<String>) -> Pane {
        match self {
            Pane::Leaf { id, view, .. } if id == target => {
                Pane::Leaf { id, view, bound_session: session }
            }
            Pane::Leaf { .. } => self,
            Pane::Split { dir, ratio, children } => {
                let mut iter = children.into_iter();
                let a = iter.next().unwrap();
                let b = iter.next().unwrap();
                let s = session.clone();
                Pane::Split {
                    dir, ratio,
                    children: vec![a.set_session(target, session), b.set_session(target, s)],
                }
            }
        }
    }

    /// 递归布局：给定总 rect，返回每个叶的 (id, rect)。
    pub fn layout(&self, rect: Rect) -> Vec<(usize, Rect)> {
        match self {
            Pane::Leaf { id, .. } => vec![(*id, rect)],
            Pane::Split { dir, ratio, children } => {
                let (r0, r1) = split_rect(rect, *dir, *ratio);
                let mut v = children[0].layout(r0);
                v.extend(children[1].layout(r1));
                v
            }
        }
    }

    /// 焦点移动：从 current_id 出发，按方向找最近的相邻叶。
    /// 用屏幕坐标判断：找到 current 的 rect，然后在该方向上找最近的叶。
    pub fn move_focus(&self, current: usize, dir: FocusDir, full_rect: Rect) -> usize {
        let layouts = self.layout(full_rect);
        let cur_rect = layouts.iter().find(|(id, _)| *id == current).map(|(_, r)| *r);
        let Some(cur) = cur_rect else { return current; };
        // 在 dir 方向上找中心距离最近的叶（排除自己）
        let (cx, cy) = rect_center(cur);
        let mut best: Option<(usize, i64)> = None;
        for (id, r) in &layouts {
            if *id == current { continue; }
            let (nx, ny) = rect_center(*r);
            let valid = match dir {
                FocusDir::Left => nx < cx && rects_v_overlap(cur, *r),
                FocusDir::Right => nx > cx && rects_v_overlap(cur, *r),
                FocusDir::Up => ny < cy && rects_h_overlap(cur, *r),
                FocusDir::Down => ny > cy && rects_h_overlap(cur, *r),
            };
            if valid {
                let dist = (nx - cx).pow(2) + (ny - cy).pow(2);
                if best.is_none_or(|(_, d)| dist < d) {
                    best = Some((*id, dist));
                }
            }
        }
        best.map(|(id, _)| id).unwrap_or(current)
    }
}

// ---- rect 辅助（纯函数）----

fn rect_center(r: Rect) -> (i64, i64) {
    ((r.x + r.width / 2) as i64, (r.y + r.height / 2) as i64)
}

fn rects_v_overlap(a: Rect, b: Rect) -> bool {
    a.y < b.y + b.height && a.y + a.height > b.y
}
fn rects_h_overlap(a: Rect, b: Rect) -> bool {
    a.x < b.x + b.width && a.x + a.width > b.x
}

/// 按 dir 和 ratio 把 rect 切成两半。
pub fn split_rect(rect: Rect, dir: SplitDir, ratio: f32) -> (Rect, Rect) {
    let ratio = ratio.clamp(0.1, 0.9);
    match dir {
        SplitDir::Horizontal => {
            // 上下：第一块在上
            let h0 = (rect.height as f32 * ratio).round() as u16;
            let h0 = h0.max(1);
            let h1 = rect.height.saturating_sub(h0);
            let top = Rect { x: rect.x, y: rect.y, width: rect.width, height: h0 };
            let bot = Rect { x: rect.x, y: rect.y + h0, width: rect.width, height: h1 };
            (top, bot)
        }
        SplitDir::Vertical => {
            // 左右：第一块在左
            let w0 = (rect.width as f32 * ratio).round() as u16;
            let w0 = w0.max(1);
            let w1 = rect.width.saturating_sub(w0);
            let left = Rect { x: rect.x, y: rect.y, width: w0, height: rect.height };
            let right = Rect { x: rect.x + w0, y: rect.y, width: w1, height: rect.height };
            (left, right)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_layout() {
        let p = Pane::single(1);
        let r = Rect::new(0, 0, 80, 24);
        let l = p.layout(r);
        assert_eq!(l, vec![(1, r)]);
    }

    #[test]
    fn split_increases_leaves() {
        let p = Pane::single(1).split(1, SplitDir::Vertical);
        assert_eq!(p.leaf_count(), 2);
    }

    #[test]
    fn close_removes_leaf() {
        let p = Pane::single(1).split(1, SplitDir::Vertical);
        let ids: Vec<_> = p.leaves().iter().map(|(id, _)| *id).collect();
        let target = ids[0];
        let p2 = p.close(target);
        assert_eq!(p2.leaf_count(), 1);
    }

    #[test]
    fn close_last_leaf_keeps_it() {
        let p = Pane::single(1);
        let p2 = p.close(1);
        assert_eq!(p2.leaf_count(), 1, "不删最后一个叶");
    }

    #[test]
    fn set_view_changes_leaf() {
        let p = Pane::single(1).set_view(1, PaneView::Files);
        assert_eq!(p.leaves()[0].1, PaneView::Files);
    }

    #[test]
    fn split_rect_vertical() {
        let (l, r) = split_rect(Rect::new(0, 0, 80, 24), SplitDir::Vertical, 0.5);
        assert_eq!(l.width + r.width, 80);
        assert!(l.width >= 1 && r.width >= 1);
        assert_eq!(l.y, r.y);
    }

    #[test]
    fn split_rect_horizontal() {
        let (t, b) = split_rect(Rect::new(0, 0, 80, 24), SplitDir::Horizontal, 0.5);
        assert_eq!(t.height + b.height, 24);
        assert_eq!(t.x, b.x);
    }

    #[test]
    fn split_rect_ratio_clamped() {
        // ratio 0.0 和 1.0 会被 clamp 到 0.1/0.9，两半都 >=1
        let (l, r) = split_rect(Rect::new(0, 0, 80, 24), SplitDir::Vertical, 0.0);
        assert!(l.width >= 1 && r.width >= 1);
        let (l, r) = split_rect(Rect::new(0, 0, 80, 24), SplitDir::Vertical, 1.0);
        assert!(l.width >= 1 && r.width >= 1);
    }

    #[test]
    fn move_focus_right_finds_neighbor() {
        // 左右分屏：split 把新叶(101)放左，原叶(1)放右。
        // 从左叶(101)向右移，应到达右叶(1)。
        let p = Pane::single(1).split(1, SplitDir::Vertical);
        let full = Rect::new(0, 0, 80, 24);
        let next = p.move_focus(101, FocusDir::Right, full);
        assert_eq!(next, 1, "从左叶向右应到右叶 1");
    }

    #[test]
    fn move_focus_down_finds_neighbor() {
        let p = Pane::single(1).split(1, SplitDir::Horizontal);
        let full = Rect::new(0, 0, 80, 24);
        let next = p.move_focus(101, FocusDir::Down, full);
        assert_eq!(next, 1, "从上叶往下应该到原叶 1");
    }

    #[test]
    fn move_focus_no_neighbor_stays() {
        // 单叶，无邻居，不动
        let p = Pane::single(1);
        let full = Rect::new(0, 0, 80, 24);
        assert_eq!(p.move_focus(1, FocusDir::Right, full), 1);
    }

    #[test]
    fn deep_split_layout_covers_all() {
        // 三层分割，所有叶的 rect 面积之和应 <= 总面积
        let p = Pane::single(1)
            .split(1, SplitDir::Vertical)
            .split(101, SplitDir::Horizontal);
        let full = Rect::new(0, 0, 80, 24);
        let layouts = p.layout(full);
        let total: u64 = layouts.iter().map(|(_, r)| (r.width as u64) * (r.height as u64)).sum();
        let full_area = (full.width as u64) * (full.height as u64);
        assert_eq!(total, full_area, "叶面积之和应等于总面积（无重叠无遗漏）");
    }

    #[test]
    fn pane_serializes_and_deserializes() {
        let p = Pane::single(1).split(1, SplitDir::Vertical);
        let json = serde_json::to_string(&p).unwrap();
        let p2: Pane = serde_json::from_str(&json).unwrap();
        assert_eq!(p2.leaf_count(), 2);
    }

    #[test]
    fn pane_view_from_index() {
        assert_eq!(PaneView::from_index(1), Some(PaneView::Console));
        assert_eq!(PaneView::from_index(6), Some(PaneView::Topology));
        assert_eq!(PaneView::from_index(7), None);
    }
}
