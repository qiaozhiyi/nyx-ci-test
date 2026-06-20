//! 链路拓扑图的布局算法（纯函数，不含渲染）。
//!
//! 输入"beacon 列表 + channel 关系"，输出带二维坐标的拓扑图，供 TUI 用
//! ASCII 画拓扑。算法是简化的分层布局：根节点（无入边）y=0，BFS 逐层加 1，
//! 同层按发现顺序赋 x。外部目标（channel 的 to 不在 sessions 里）作为叶子。

#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};

/// 一个拓扑节点（beacon 或外部目标）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopoNode {
    pub id: String,
    pub label: String,
    pub is_beacon: bool,
    pub x: u32,
    pub y: u32,
}

/// 一条边（pivot channel）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopoEdge {
    pub from: String,
    pub to: String,
    pub label: String,
}

/// 完整拓扑图。
pub struct Topology {
    pub nodes: Vec<TopoNode>,
    pub edges: Vec<TopoEdge>,
}

/// 简化分层布局。纯函数。
///
/// - 根 = 没有入边的 session（+ 孤立 session）
/// - BFS：child.y = parent.y + 1，用 visited 集合防环
/// - 同层按发现顺序赋 x=0,1,2...
/// - 外部目标（to 不在 sessions）作为叶子节点注入
pub fn layout(
    sessions: &[(String, String)],                       // (id, label)
    channels: &[(String, String, String)],               // (from_id, to_id, label)
) -> Topology {
    // 收集所有 beacon id
    let beacon_ids: HashSet<&str> = sessions.iter().map(|(id, _)| id.as_str()).collect();
    let label_of: HashMap<&str, &str> = sessions.iter().map(|(id, l)| (id.as_str(), l.as_str())).collect();

    // 外部目标节点（to 不在 sessions）
    let mut external: Vec<String> = Vec::new();
    for (_, to, _) in channels {
        if !beacon_ids.contains(to.as_str()) && !external.iter().any(|e| e == to) {
            external.push(to.clone());
        }
    }

    // 所有节点 id（beacon + external）
    let mut all_ids: Vec<String> = sessions.iter().map(|(id, _)| id.clone()).collect();
    all_ids.extend(external.iter().cloned());

    // 入度（针对全图）
    let mut in_degree: HashMap<&str, u32> = HashMap::new();
    for id in &all_ids {
        in_degree.insert(id.as_str(), 0);
    }
    for (_, to, _) in channels {
        if in_degree.contains_key(to.as_str()) {
            *in_degree.get_mut(to.as_str()).unwrap() += 1;
        }
    }

    // 邻接表
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for id in &all_ids {
        adj.insert(id.as_str(), Vec::new());
    }
    for (from, to, _) in channels {
        if let Some(list) = adj.get_mut(from.as_str()) {
            list.push(to.as_str());
        }
    }

    // BFS：从入度为 0 的根开始
    let mut y_map: HashMap<&str, u32> = HashMap::new();
    let mut visited: HashSet<&str> = HashSet::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    for id in &all_ids {
        if in_degree[id.as_str()] == 0 {
            queue.push_back(id.as_str());
            y_map.insert(id.as_str(), 0);
        }
    }
    while let Some(cur) = queue.pop_front() {
        if !visited.insert(cur) {
            continue; // 已访问，防环
        }
        let cur_y = *y_map.get(cur).unwrap_or(&0);
        for &nxt in adj.get(cur).unwrap_or(&vec![]) {
            // 只在邻居还没有 y 时赋值（首次发现的层级），已分配的不再改写。
            // 这防止环回边把已访问节点的 y 抬高。
            if !y_map.contains_key(nxt) {
                y_map.insert(nxt, cur_y + 1);
            }
            queue.push_back(nxt);
        }
    }
    // 未被 BFS 访问的节点（纯环无根时 queue 一开始空，全部漏掉）兜底 y=0。
    // 这是退化场景：纯环里的节点无法分层，统一画在第 0 层。
    for id in &all_ids {
        y_map.entry(id.as_str()).or_insert(0);
    }

    // 按 y 分桶，桶内按 all_ids 顺序赋 x
    let mut buckets: HashMap<u32, Vec<&str>> = HashMap::new();
    for id in &all_ids {
        let y = y_map[id.as_str()];
        buckets.entry(y).or_default().push(id.as_str());
    }
    let mut nodes: Vec<TopoNode> = Vec::new();
    // 收集所有 y 层并排序
    let mut ys: Vec<u32> = buckets.keys().copied().collect();
    ys.sort();
    for y in ys {
        let layer = &buckets[&y];
        for (x, id) in layer.iter().enumerate() {
            let is_beacon = beacon_ids.contains(*id);
            let label = if is_beacon {
                label_of.get(id).copied().unwrap_or(id).to_string()
            } else {
                // 外部节点 label 用 id 本身
                id.to_string()
            };
            nodes.push(TopoNode {
                id: id.to_string(),
                label,
                is_beacon,
                x: x as u32,
                y,
            });
        }
    }

    let edges = channels
        .iter()
        .map(|(f, t, l)| TopoEdge { from: f.clone(), to: t.clone(), label: l.clone() })
        .collect();

    Topology { nodes, edges }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_beacon_no_channels() {
        let t = layout(&[("A".into(), "host-a".into())], &[]);
        assert_eq!(t.nodes.len(), 1);
        assert_eq!(t.nodes[0].id, "A");
        assert_eq!(t.nodes[0].y, 0);
        assert!(t.nodes[0].is_beacon);
        assert!(t.edges.is_empty());
    }

    #[test]
    fn a_to_b_two_layers() {
        let t = layout(
            &[("A".into(), "a".into()), ("B".into(), "b".into())],
            &[("A".into(), "B".into(), "pivot".into())],
        );
        let a = t.nodes.iter().find(|n| n.id == "A").unwrap();
        let b = t.nodes.iter().find(|n| n.id == "B").unwrap();
        assert_eq!(a.y, 0);
        assert_eq!(b.y, 1);
    }

    #[test]
    fn a_to_b_and_c_same_layer() {
        let t = layout(
            &[
                ("A".into(), "a".into()),
                ("B".into(), "b".into()),
                ("C".into(), "c".into()),
            ],
            &[
                ("A".into(), "B".into(), "pivot".into()),
                ("A".into(), "C".into(), "pivot".into()),
            ],
        );
        let b = t.nodes.iter().find(|n| n.id == "B").unwrap();
        let c = t.nodes.iter().find(|n| n.id == "C").unwrap();
        assert_eq!(b.y, 1);
        assert_eq!(c.y, 1);
        // x 各异（顺序不保证具体值，但两个不同）
        assert_ne!(b.x, c.x);
    }

    #[test]
    fn three_layer_chain() {
        let t = layout(
            &[
                ("A".into(), "a".into()),
                ("B".into(), "b".into()),
                ("C".into(), "c".into()),
            ],
            &[
                ("A".into(), "B".into(), "pivot".into()),
                ("B".into(), "C".into(), "pivot".into()),
            ],
        );
        assert_eq!(t.nodes.iter().find(|n| n.id == "A").unwrap().y, 0);
        assert_eq!(t.nodes.iter().find(|n| n.id == "B").unwrap().y, 1);
        assert_eq!(t.nodes.iter().find(|n| n.id == "C").unwrap().y, 2);
    }

    #[test]
    fn external_target_is_leaf() {
        let t = layout(
            &[("A".into(), "a".into())],
            &[("A".into(), "ext:10.0.0.1:445".into(), "socks".into())],
        );
        assert_eq!(t.nodes.len(), 2);
        let ext = t.nodes.iter().find(|n| n.id == "ext:10.0.0.1:445").unwrap();
        assert!(!ext.is_beacon);
        assert_eq!(ext.y, 1);
    }

    #[test]
    fn cycle_does_not_infinite_loop() {
        // A→B→A 纯环：两节点都有入边，无根 → BFS queue 空 → 全塌 y=0（兜底）。
        // 这是退化场景，但必须不死循环。
        let t = layout(
            &[("A".into(), "a".into()), ("B".into(), "b".into())],
            &[
                ("A".into(), "B".into(), "pivot".into()),
                ("B".into(), "A".into(), "pivot".into()),
            ],
        );
        assert_eq!(t.nodes.len(), 2, "纯环不丢节点");
        // 退化：无根，两节点都 y=0
        assert!(t.nodes.iter().all(|n| n.y == 0), "纯环退化到 y=0");
    }

    #[test]
    fn rooted_cycle_visited_prevents_revisit() {
        // 有根的环：A(根,y=0) → B(y=1) → C(y=2) → B(回到B，环)。
        // BFS 从 A 出发，B 被访问后 C 回指 B 不应重新分配 y。
        // 这个测试真正触发 visited 防环分支。
        let t = layout(
            &[
                ("A".into(), "a".into()),
                ("B".into(), "b".into()),
                ("C".into(), "c".into()),
            ],
            &[
                ("A".into(), "B".into(), "pivot".into()),
                ("B".into(), "C".into(), "pivot".into()),
                ("C".into(), "B".into(), "pivot".into()), // 环回 B
            ],
        );
        assert_eq!(t.nodes.len(), 3, "不丢节点");
        let a = t.nodes.iter().find(|n| n.id == "A").unwrap();
        let b = t.nodes.iter().find(|n| n.id == "B").unwrap();
        let c = t.nodes.iter().find(|n| n.id == "C").unwrap();
        assert_eq!(a.y, 0, "A 是根");
        assert_eq!(b.y, 1, "B 在第一层");
        assert_eq!(c.y, 2, "C 在第二层");
        // 关键：B 的 y 没被 C 的回环改写（visited 保护）
        assert_eq!(b.y, 1, "visited 防止 B 被重新分配");
    }
}
