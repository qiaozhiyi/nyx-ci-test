//! tmux 式窗格树。
//!
//! 一个可递归分割的布局：叶节点持有一个视图（Console/Files/...），
//! 内节点持有一对子窗格 + 分割方向 + 比例。所有树操作（split/close/
//! move_focus/layout）都是纯函数，与渲染解耦，独立 TDD。

#![allow(dead_code)]

use ratatui::layout::Rect;
use ratatui::widgets::ListState;

/// 每个叶窗格独有的交互状态——输入缓冲、光标、popup、历史游标。
///
/// 历史条目本身（`history`）仍全局共享（命令历史是 cross-session 的元数据），
/// 但每个窗格各自维护一个"当前在历史的哪一行"游标，这样切换窗格时
/// ↑/↓ 导航不会被其他窗格的状态污染。
#[derive(Clone, Debug, Default)]
pub struct PaneState {
    pub input: String,
    pub cursor: usize,
    pub popup_open: bool,
    pub popup_state: ListState,
    pub hist_idx: Option<usize>,
}

// ---- 分割方向 ----

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitDir {
    /// 上下分割（水平分隔线）：区域被分成上下两行。
    Rows,
    /// 左右分割（垂直分隔线）：区域被分成左右两列。
    Columns,
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
    /// 所有视图，按 tab bar 显示顺序。供 render 画 tab + click 反查用。
    pub const ALL: [PaneView; 6] = [
        PaneView::Console,
        PaneView::SessionList,
        PaneView::Files,
        PaneView::Procs,
        PaneView::Creds,
        PaneView::Topology,
    ];

    /// prefix+1..6 对应的视图。
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
        session_id: Option<String>,
        /// 每个叶独有的输入态（输入缓冲、光标、popup、历史游标）。
        /// `#[serde(skip)]`：输入态是临时交互态，跨进程恢复无意义；
        /// 反序列化时退回 `PaneState::default()`，老数据（无此字段）也能读。
        #[serde(default, skip)]
        state: PaneState,
    },
    Split {
        dir: SplitDir,
        /// 第一个子窗格占比（0.0-1.0）。
        #[serde(default = "default_ratio")]
        ratio: f32,
        children: Vec<Pane>, // 恒为 2 个
    },
}

fn default_ratio() -> f32 {
    0.5
}

/// 焦点移动方向。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FocusDir {
    Left,
    Right,
    Up,
    Down,
}

impl Pane {
    /// 创建单叶窗格。
    pub fn single(id: usize) -> Self {
        Pane::Leaf {
            id,
            view: PaneView::Console,
            session_id: None,
            state: PaneState::default(),
        }
    }

    /// 默认工作区布局（启动即双窗格）：左 console 70% · 右 session list 30%。
    /// 焦点在 console（id=1）；session list（id=2）实时显示上线 agent，点击行
    /// 即为该窗格绑定 session。用户手动 split/close 照旧走 [`Self::split`]/[`Self::close`]。
    /// 纯构造，与 split 一样不依赖运行时状态。
    pub fn default_workspace() -> Self {
        Pane::Split {
            dir: SplitDir::Columns,
            ratio: 0.7,
            children: vec![
                Pane::Leaf {
                    id: 1,
                    view: PaneView::Console,
                    session_id: None,
                    state: PaneState::default(),
                },
                Pane::Leaf {
                    id: 2,
                    view: PaneView::SessionList,
                    session_id: None,
                    state: PaneState::default(),
                },
            ],
        }
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

    pub fn get_session_id(&self, target: usize) -> Option<String> {
        match self {
            Pane::Leaf { id, session_id, .. } if *id == target => session_id.clone(),
            Pane::Leaf { .. } => None,
            Pane::Split { children, .. } => children[0]
                .get_session_id(target)
                .or_else(|| children[1].get_session_id(target)),
        }
    }

    pub fn set_session_id(&mut self, target: usize, session: Option<String>) {
        match self {
            Pane::Leaf { id, session_id, .. } if *id == target => {
                *session_id = session;
            }
            Pane::Leaf { .. } => {}
            Pane::Split { children, .. } => {
                children[0].set_session_id(target, session.clone());
                children[1].set_session_id(target, session);
            }
        }
    }

    /// 取 id == target 叶的 PaneState（不可变）。找不到返回 None。
    pub fn leaf_state(&self, target: usize) -> Option<&PaneState> {
        match self {
            Pane::Leaf { id, state, .. } if *id == target => Some(state),
            Pane::Leaf { .. } => None,
            Pane::Split { children, .. } => children[0]
                .leaf_state(target)
                .or_else(|| children[1].leaf_state(target)),
        }
    }

    /// 取 id == target 叶的 PaneState（可变）。找不到返回 None。
    /// TUI 主循环里所有"输入到当前焦点窗格"的修改都走这条路，
    /// 让每个窗格各自有独立的输入缓冲 / 光标 / popup。
    pub fn leaf_state_mut(&mut self, target: usize) -> Option<&mut PaneState> {
        match self {
            Pane::Leaf { id, state, .. } if *id == target => Some(state),
            Pane::Leaf { .. } => None,
            Pane::Split { children, .. } => {
                // split_at_mut 把 children 切成两份独立 &mut，绕开
                // children[0] / children[1] 同时被借用的二阶借用冲突。
                let (left, right) = children.split_at_mut(1);
                left[0]
                    .leaf_state_mut(target)
                    .or_else(|| right[0].leaf_state_mut(target))
            }
        }
    }

    /// 把 id == target 的叶节点一分为二，返回新树。新叶继承视图。
    /// 新叶成为第一个子，原叶内容成为第二个子（焦点会移到新叶）。
    /// **新叶的 PaneState 初始化为空**（输入框干净），原叶保留它的状态。
    /// `new_id` 由调用方通过 [`Self::next_id`] 计算，保证全树唯一。
    pub fn split(self, target: usize, dir: SplitDir, new_id: usize) -> Pane {
        match self {
            Pane::Leaf {
                id,
                view,
                session_id,
                state,
            } if id == target => {
                Pane::Split {
                    dir,
                    ratio: 0.5,
                    children: vec![
                        Pane::Leaf {
                            id: new_id,
                            view,
                            // 分屏隔离：新叶 session_id = None，不继承原叶的 session。
                            // 这样新窗格默认无 beacon，操作员需 /use 显式选择不同 beacon，
                            // 彻底避免两个窗格连同一 session 导致输出重复显示。
                            session_id: None,
                            state: PaneState::default(),
                        },
                        Pane::Leaf {
                            id,
                            view,
                            session_id,
                            state,
                        },
                    ],
                }
            }
            Pane::Leaf { .. } => self,
            Pane::Split {
                dir: d,
                ratio,
                children,
            } => Pane::Split {
                dir: d,
                ratio,
                children: children
                    .into_iter()
                    .map(|c| c.split(target, dir, new_id))
                    .collect(),
            },
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
            Pane::Split {
                children,
                dir,
                ratio,
            } => {
                let a = children[0].clone().close_inner(target);
                let b = children[1].clone().close_inner(target);
                match (a, b) {
                    (Some(a), Some(b)) => Some(Pane::Split {
                        dir,
                        ratio,
                        children: vec![a, b],
                    }),
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
            Pane::Leaf {
                id,
                session_id,
                state,
                ..
            } if id == target => Pane::Leaf {
                id,
                view,
                session_id,
                state,
            },
            Pane::Leaf { .. } => self,
            Pane::Split {
                dir,
                ratio,
                children,
            } => Pane::Split {
                dir,
                ratio,
                children: children
                    .into_iter()
                    .map(|c| c.set_view(target, view))
                    .collect(),
            },
        }
    }

    /// 调整包含 target 叶的最近 Split 节点的 ratio（UX-S2）。
    /// 沿树向下找：如果 target 在某个子树里，就递归进去；到达直接包含 target 的
    /// Split 时调整它的 ratio（clamp 0.1..0.9，与 split_rect 一致）。
    /// `delta` 正值放大第一块（左/上），负值缩小。原地修改，避免 clone 整棵树。
    ///
    /// 返回 true 表示找到了目标 Split 并调整了；false 表示 target 不在树里。
    pub fn adjust_ratio(&mut self, target: usize, delta: f32) -> bool {
        match self {
            Pane::Leaf { .. } => false,
            Pane::Split {
                ratio, children, ..
            } => {
                let in_left = children[0].contains_leaf(target);
                let in_right = children[1].contains_leaf(target);
                if in_left || in_right {
                    // 先递归到更深的 Split（更精确的"最近包含者"），找到就返回。
                    let deeper = if in_left {
                        children[0].adjust_ratio(target, delta)
                    } else {
                        children[1].adjust_ratio(target, delta)
                    };
                    if deeper {
                        return true;
                    }
                    // 自己就是最近的包含 Split → 调 ratio（clamp 与 split_rect 一致）
                    *ratio = (*ratio + delta).clamp(0.1, 0.9);
                    return true;
                }
                false
            }
        }
    }

    /// target 叶是否在这棵子树里。供 adjust_ratio 判断方向用。
    fn contains_leaf(&self, target: usize) -> bool {
        match self {
            Pane::Leaf { id, .. } => *id == target,
            Pane::Split { children, .. } => {
                children[0].contains_leaf(target) || children[1].contains_leaf(target)
            }
        }
    }

    /// 递归布局：给定总 rect，返回每个叶的 (id, rect)。
    pub fn layout(&self, rect: Rect) -> Vec<(usize, Rect)> {
        match self {
            Pane::Leaf { id, .. } => vec![(*id, rect)],
            Pane::Split {
                dir,
                ratio,
                children,
            } => {
                let (r0, r1) = split_rect(rect, *dir, *ratio);
                let mut v = children[0].layout(r0);
                v.extend(children[1].layout(r1));
                v
            }
        }
    }

    /// 一次遍历拿全：每个叶的 (id, rect, view, session_id)。
    /// 供渲染用，避免 render 每帧 clone 整棵树 + O(n²) 二次查找 view（P1-2）。
    /// 与 `layout()` 共用递归骨架，只是叶节点多带出两个字段。
    pub fn layout_full(&self, rect: Rect) -> Vec<(usize, Rect, PaneView, Option<String>)> {
        match self {
            Pane::Leaf {
                id,
                view,
                session_id,
                ..
            } => vec![(*id, rect, *view, session_id.clone())],
            Pane::Split {
                dir,
                ratio,
                children,
            } => {
                let (r0, r1) = split_rect(rect, *dir, *ratio);
                let mut v = children[0].layout_full(r0);
                v.extend(children[1].layout_full(r1));
                v
            }
        }
    }

    /// 焦点移动：从 current_id 出发，按方向找最近的相邻叶。
    /// 用屏幕坐标判断：找到 current 的 rect，然后在该方向上找最近的叶。
    pub fn move_focus(&self, current: usize, dir: FocusDir, full_rect: Rect) -> usize {
        let layouts = self.layout(full_rect);
        let cur_rect = layouts
            .iter()
            .find(|(id, _)| *id == current)
            .map(|(_, r)| *r);
        let Some(cur) = cur_rect else {
            return current;
        };
        // 在 dir 方向上找中心距离最近的叶（排除自己）
        let (cx, cy) = rect_center(cur);
        let mut best: Option<(usize, i64)> = None;
        for (id, r) in &layouts {
            if *id == current {
                continue;
            }
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
        SplitDir::Rows => {
            // 上下：第一块在上
            let h0 = (rect.height as f32 * ratio).round() as u16;
            let h0 = h0.max(1);
            let h1 = rect.height.saturating_sub(h0);
            let top = Rect {
                x: rect.x,
                y: rect.y,
                width: rect.width,
                height: h0,
            };
            let bot = Rect {
                x: rect.x,
                y: rect.y + h0,
                width: rect.width,
                height: h1,
            };
            (top, bot)
        }
        SplitDir::Columns => {
            // 左右：第一块在左
            let w0 = (rect.width as f32 * ratio).round() as u16;
            let w0 = w0.max(1);
            let w1 = rect.width.saturating_sub(w0);
            let left = Rect {
                x: rect.x,
                y: rect.y,
                width: w0,
                height: rect.height,
            };
            let right = Rect {
                x: rect.x + w0,
                y: rect.y,
                width: w1,
                height: rect.height,
            };
            (left, right)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_workspace_is_console_plus_sessions() {
        // 启动默认布局契约：console | sessions 双窗格，70/30，焦点在 console。
        let p = Pane::default_workspace();
        assert_eq!(p.leaf_count(), 2);
        let leaves = p.leaves();
        assert_eq!(leaves[0], (1, PaneView::Console));
        assert_eq!(leaves[1], (2, PaneView::SessionList));
        // 70/30 左右分割验证。
        let full = Rect::new(0, 0, 100, 24);
        let layout = p.layout(full);
        let left = layout.iter().find(|(id, _)| *id == 1).unwrap().1;
        let right = layout.iter().find(|(id, _)| *id == 2).unwrap().1;
        assert_eq!(left.width, 70, "console 应占 70%");
        assert_eq!(right.width, 30, "sessions 应占 30%");
        // 新叶 id 分配不与默认两叶冲突。
        assert_eq!(p.next_id(), 3);
        // 默认双窗格 close 到一叶后仍可 split（用户手动行为不变）。
        let p = p.close(2);
        assert_eq!(p.leaf_count(), 1);
        let nid = p.next_id();
        let p = p.split(1, SplitDir::Rows, nid);
        assert_eq!(p.leaf_count(), 2);
    }

    #[test]
    fn single_leaf_layout() {
        let p = Pane::single(1);
        let r = Rect::new(0, 0, 80, 24);
        let l = p.layout(r);
        assert_eq!(l, vec![(1, r)]);
    }

    #[test]
    fn split_increases_leaves() {
        let p = Pane::single(1);
        let new_id = p.next_id();
        let p = p.split(1, SplitDir::Columns, new_id);
        assert_eq!(p.leaf_count(), 2);
    }

    #[test]
    fn close_removes_leaf() {
        let p = Pane::single(1);
        let new_id = p.next_id();
        let p = p.split(1, SplitDir::Columns, new_id);
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
    fn split_new_id_is_unique() {
        // next_id() 返回当前最大叶 id + 1，split 后新叶应持有该 id。
        let p = Pane::single(1);
        let new_id = p.next_id(); // == 2
        let p2 = p.split(1, SplitDir::Columns, new_id);
        let ids: Vec<usize> = p2.leaves().iter().map(|(id, _)| *id).collect();
        assert!(ids.contains(&2), "new leaf must have id == next_id()");
        assert!(ids.contains(&1), "original leaf must be preserved");
    }

    /// 分屏 session 隔离：split 后新叶 session_id 必须为 None，不继承原叶的 session。
    /// 这是"分屏互不干扰"的核心契约——两个窗格连同一 session 会导致命令输出
    /// 在两个窗格重复显示（render 的 session 过滤会同时命中）。
    #[test]
    fn split_new_leaf_has_no_session_id() {
        let mut p = Pane::single(1);
        p.set_session_id(1, Some("beacon-aaa".into()));
        let new_id = p.next_id(); // == 2
        let p2 = p.split(1, SplitDir::Columns, new_id);
        // 新叶（id=2）应无 session；原叶（id=1）保留原 session。
        assert_eq!(
            p2.get_session_id(2),
            None,
            "新叶必须 session_id=None，彻底隔离"
        );
        assert_eq!(
            p2.get_session_id(1),
            Some("beacon-aaa".into()),
            "原叶保留原 session"
        );
    }

    #[test]
    fn split_rect_vertical() {
        let (l, r) = split_rect(Rect::new(0, 0, 80, 24), SplitDir::Columns, 0.5);
        assert_eq!(l.width + r.width, 80);
        assert!(l.width >= 1 && r.width >= 1);
        assert_eq!(l.y, r.y);
    }

    #[test]
    fn split_rect_horizontal() {
        let (t, b) = split_rect(Rect::new(0, 0, 80, 24), SplitDir::Rows, 0.5);
        assert_eq!(t.height + b.height, 24);
        assert_eq!(t.x, b.x);
    }

    #[test]
    fn split_rect_ratio_clamped() {
        // ratio 0.0 和 1.0 会被 clamp 到 0.1/0.9，两半都 >=1
        let (l, r) = split_rect(Rect::new(0, 0, 80, 24), SplitDir::Columns, 0.0);
        assert!(l.width >= 1 && r.width >= 1);
        let (l, r) = split_rect(Rect::new(0, 0, 80, 24), SplitDir::Columns, 1.0);
        assert!(l.width >= 1 && r.width >= 1);
    }

    /// 深层分割后三叶面积之和恰等于总面积（无重叠无遗漏）——回归 split 签名更改。
    #[test]
    fn split_area_conservation_three_panes() {
        let p = Pane::single(1);
        let nid1 = p.next_id(); // 2
        let p = p.split(1, SplitDir::Columns, nid1);
        let nid2 = p.next_id(); // 3
        let p = p.split(nid1, SplitDir::Rows, nid2);
        let full = Rect::new(0, 0, 80, 24);
        let layouts = p.layout(full);
        assert_eq!(layouts.len(), 3, "三叶");
        let total: u64 = layouts
            .iter()
            .map(|(_, r)| (r.width as u64) * (r.height as u64))
            .sum();
        let full_area = (full.width as u64) * (full.height as u64);
        assert_eq!(total, full_area);
    }

    #[test]
    fn move_focus_right_finds_neighbor() {
        // 左右分屏：split 把新叶(2)放左，原叶(1)放右。
        // 从左叶(2)向右移，应到达右叶(1)。
        let p = Pane::single(1);
        let nid = p.next_id(); // 2
        let p = p.split(1, SplitDir::Columns, nid);
        let full = Rect::new(0, 0, 80, 24);
        let next = p.move_focus(nid, FocusDir::Right, full);
        assert_eq!(next, 1, "从左叶向右应到右叶 1");
    }

    #[test]
    fn move_focus_down_finds_neighbor() {
        let p = Pane::single(1);
        let nid = p.next_id(); // 2
        let p = p.split(1, SplitDir::Rows, nid);
        let full = Rect::new(0, 0, 80, 24);
        let next = p.move_focus(nid, FocusDir::Down, full);
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
        let p = Pane::single(1);
        let nid1 = p.next_id(); // 2
        let p = p.split(1, SplitDir::Columns, nid1);
        let nid2 = p.next_id(); // 3
        let p = p.split(nid1, SplitDir::Rows, nid2);
        let full = Rect::new(0, 0, 80, 24);
        let layouts = p.layout(full);
        let total: u64 = layouts
            .iter()
            .map(|(_, r)| (r.width as u64) * (r.height as u64))
            .sum();
        let full_area = (full.width as u64) * (full.height as u64);
        assert_eq!(total, full_area, "叶面积之和应等于总面积（无重叠无遗漏）");
    }

    #[test]
    fn pane_serializes_and_deserializes() {
        let p = Pane::single(1);
        let nid = p.next_id();
        let p = p.split(1, SplitDir::Columns, nid);
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

    /// UX-S2：adjust_ratio 能改变分屏比例，且 clamp 到 0.1..0.9。
    #[test]
    fn adjust_ratio_changes_split_proportion() {
        let p = Pane::single(1);
        let nid = p.next_id(); // 2
        let mut p = p.split(1, SplitDir::Columns, nid);
        assert!(p.adjust_ratio(nid, 0.2), "应找到包含 target 的 Split");
        // 验证 layout 反映了比例变化：左块应该比之前宽。
        let full = Rect::new(0, 0, 80, 24);
        let layouts = p.layout(full);
        let left = layouts
            .iter()
            .find(|(id, _)| *id == nid)
            .map(|(_, r)| r.width);
        // ratio +0.2 → 0.7，左块占 70% ≈ 56 列（0.5 时是 40）。
        assert!(left.unwrap_or(0) > 45, "左块应变宽");
    }

    /// adjust_ratio 的 clamp：delta 超出范围不会让 ratio 越界。
    #[test]
    fn adjust_ratio_clamps_to_bounds() {
        let p = Pane::single(1);
        let nid = p.next_id();
        let mut p = p.split(1, SplitDir::Columns, nid);
        // 极大 delta → clamp 到 0.9，不 panic，不越界。
        assert!(p.adjust_ratio(nid, 10.0));
        let full = Rect::new(0, 0, 80, 24);
        let layouts = p.layout(full);
        // 两块都应 >= 1（split_rect 的 max(1) 保证）。
        for (_, r) in &layouts {
            assert!(r.width >= 1 && r.height >= 1);
        }
    }

    /// adjust_ratio 对不存在的 target 返回 false。
    #[test]
    fn adjust_ratio_missing_target_returns_false() {
        let mut p = Pane::single(1);
        assert!(!p.adjust_ratio(999, 0.1));
    }
}
