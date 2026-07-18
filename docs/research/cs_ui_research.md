# Cobalt Strike UI Redesign Research and Planning

> 📚 **参考文档** — 外部资料/ API 参考/设计探索，与当前代码状态无关。项目实际能力见 [`README.md`](../../README.md) 与 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md)。
> ⚠️ 注意：本文涉及的 Makepad client 已于 commit c5064dc 归档，现用 client-ui-web (Tauri 2)。

This document serves as the research base and redesign plan for refactoring the Nyx operator client UI (`crates/client-ui/`) into a classic, recognizable Cobalt Strike-inspired design.

---

## 1. Classic Cobalt Strike UI Reference & Analysis

Cobalt Strike's original interface was built using Java Swing (often using the standard Look & Feel or a custom light-gray and steel-blue theme). It has a distinct "industrial pro-tool" aesthetic that operator groups are highly accustomed to.

### 1.1 Layout Map

The interface is structured as a single-window application with the following standard layout regions:

```
+--------------------------------------------------------------------------------+
| Menu Bar: Cobalt Strike | View | Attacks | Reporting | Help                     |
+--------------------------------------------------------------------------------+
| Tool Bar: [Plug] [Unplug] [Ear] [Table] [Graph] [🎯] [Key] [Down] [⌨️] [📷] [⚙️]  |
+--------------------------------------------------------------------------------+
|                                                                                |
|  Sessions View Pane (Top)                                                      |
|  Displays Active Beacons (table) OR Session Graph (topological map)            |
|                                                                                |
|================================= Split Pane Divider ===========================|
|                                                                                |
|  Tabbed Console/Data Pane (Bottom)                                             |
|  [Console: 10.0.0.5] [Event Log] [Credentials] [+]                             |
|  +--------------------------------------------------------------------------+  |
|  | beacon> sleep 60                                                         |  |
|  | [*] Tasked beacon to sleep for 60s                                        |  |
|  +--------------------------------------------------------------------------+  |
|                                                                                |
+--------------------------------------------------------------------------------+
| Status Bar: Connected to 127.0.0.1:50050 | Beacons: 2 | Targets: 4             |
+--------------------------------------------------------------------------------+
```

1. **Menu Bar**: Pinned at the very top of the window, providing access to all client configurations, payload generation modules, and reports.
2. **Toolbar**: A horizontal row of quick-action buttons directly below the menu bar, providing fast switching between views and launching listener managers.
3. **Split Pane (Horizontal/Vertical Divider)**:
   - Divides the main window space.
   - **Top Pane**: Focuses on active beacons (the primary list of compromised hosts). This pane typically switches between a tabular list view (Beacons) and a node/graph view (Session Graph / Targets).
   - **Bottom Pane**: A tabbed pane hosting individual interactive shells (beacons), the global Event Log (operator chat), file browsers, credential tables, and screenshots.
4. **Status Bar**: A thin strip at the very bottom showing server status, port, and stats (e.g. number of active beacons/targets).

### 1.2 Color Palette (Classic Gray/Blue Swing Theme)

To recreate the classic Swing Look & Feel, we define a palette utilizing light gray panel surfaces, crisp borders, and dark text, highlighted by steel blue for selections and highlights:

| Element | Description | Hex Code |
| :--- | :--- | :--- |
| **`bg`** | Main window base clear color / deepest surface | `#D0D0D0` |
| **`panel`** | Standard gray panels (ToolBar, MenuBar background) | `#F0F0F0` |
| **`bar`** | Recessed tab bars / secondary headers | `#E0E0E0` |
| **`elev`** | Active fields / table headers / dialog card | `#EAEAEA` |
| **`row`** | Default table row background | `#FFFFFF` |
| **`rowhov`** | Table row hover color | `#E8F0FA` |
| **`rowsel`** | Table row selection background (Steel Blue) | `#3B72AB` |
| **`border`** | Hairline dividers and borders | `#A0A0A0` |
| **`primary`** | Main text color (high contrast against light gray/white) | `#000000` |
| **`second`** | Secondary text color | `#333333` |
| **`muted`** | Disabled / column headers label text | `#666666` |
| **`accent`** | Main accent color (Steel Blue) | `#3B72AB` |
| **`acchov`** | Accent hover state | `#5B9BD5` |
| **`success`** | Active beacon / online text indicator (Dark Green) | `#008000` |
| **`danger`** | Offline beacon / error state indicator (Red) | `#D13438` |
| **`warn`** | Pending actions / credential alert text | `#E38B00` |
| **`info`** | Command syntax highlight / system logs (Dark Blue) | `#005A9C` |

---

## 2. Menu Structure & Toolbar Actions

### 2.1 Detailed Menu Hierarchy

The menu bar must contain the following menu items and typical sub-options:

* **Cobalt Strike**
  * `New Connection` (Connect to a different Team Server)
  * `Preferences` (Configure shortcuts, console colors, interface font size)
  * `Visualization`
    * `Pivot Graph` (Visual session topology graph)
    * `Session Table` (Standard tabular beacons list)
    * `Target List` (Discovered network hosts list)
  * `Close` (Disconnect current active tab connection)
  * `Exit` (Terminate application)
* **View**
  * `Applications` (List browser system profiles detected)
  * `Beacons` (Switch top panel view to Beacons list)
  * `Credentials` (Open credentials database tab)
  * `Downloads` (Open downloaded files table tab)
  * `Event Log` (Open global Team Server operator chat tab)
  * `Keystrokes` (Open keylogger dumps tab)
  * `Proxy Pivots` (Manage active SOCKS/reverse port forwards)
  * `Screenshots` (Open screenshot gallery view tab)
  * `Script Console` (Access script engine logs and terminal)
  * `Targets` (Open target list tab)
  * `Web Log` (Open HTTP traffic log tab for hosted redirectors)
* **Attacks**
  * `Packages`
    * `HTML Application` (Create malicious HTAs)
    * `MS Office Macro` (Generate VBA macro payload)
    * `Payload Generator` (Export payloads in various formats)
    * `USB/CD AutoPlay` (AutoRun payloads creator)
    * `Windows Executable` (Generate classic EXE/DLL payloads)
    * `Windows Executable (Stageless)` (Generate stageless EXE/DLL payloads)
  * `Web Drive-by`
    * `Manage` (List/terminate hosted files/web portals)
    * `Clone Site` (Host a cloned website page)
    * `System Profiler` (Host system profiling script)
    * `Spear Phish` (Configure phisher campaign)
* **Reporting**
  * `Activity Report` (Generate operator commands list PDF)
  * `Hosts Report` (Generate network assets target details PDF)
  * `Indicators of Compromise` (Generate IOC hash list PDF)
  * `Sessions Report` (Generate compromise sessions chronology PDF)
  * `Social Engineering Report` (Generate phishing campaign metrics PDF)
  * `Tactics Report` (MITRE ATT&CK techniques mapped report)
* **Help**
  * `System Information` (Display client machine/JVM environment details)
  * `About Cobalt Strike` (Open dialog with version, copyright, and registration token info)

### 2.2 Toolbar Configuration

The Toolbar should display a series of quick-access icons. In Makepad 2.0, these can use character icon glyphs (or emojis as placeholders) in a horizontal row:

| Action | Proposed Icon/Emoji | Purpose |
| :--- | :--- | :--- |
| **Connect** | `🔌` (or icon equivalent) | Open server connection dialog |
| **Disconnect** | `🚫` (or icon equivalent) | Disconnect current active team server |
| **Listeners** | `🎧` (or icon equivalent) | Open Listener Configuration manager tab |
| **Beacons Table** | `📊` (or icon equivalent) | Set top visualization pane to Sessions table |
| **Session Graph** | `🕸️` (or icon equivalent) | Set top visualization pane to Session Graph view |
| **Targets List** | `🎯` (or icon equivalent) | Open network targets hosts list table |
| **Credentials** | `🔑` (or icon equivalent) | Open credentials database pane in bottom tabs |
| **Downloads** | `📥` (or icon equivalent) | Open downloads file-history pane in bottom tabs |
| **Keystrokes** | `⌨️` (or icon equivalent) | Open keystroke dumps panel in bottom tabs |
| **Screenshots** | `📷` (or icon equivalent) | Open screenshot gallery viewer in bottom tabs |
| **Spear Phish** | `✉️` (or icon equivalent) | Open phisher campaign setup window |
| **Preferences** | `⚙️` (or icon equivalent) | Open preferences customization dialog |
| **Help/About** | `❓` (or icon equivalent) | Open Help / About info box |

---

## 3. Codebase Analysis & Refactoring Plan (`crates/client-ui/src/main.rs`)

### 3.1 Layout Structure (Before vs. Proposed)

* **Current structure in `main.rs` (`script_mod!`)**:
  ```rust
  main_window := Window {
      body +: {
          flow: Down
          connect_view := SolidView { ... }
          main_view := SolidView {
              flow: Down
              conn_bar := SolidView { ... } // Server URL, Connect/Disconnect, Status, Theme button
              main_split := Splitter {
                  axis: Vertical // Splits Top and Bottom
                  a: Splitter { // Top split: Sessions (left) and Event Log (right)
                      axis: Horizontal
                      a: View { left_panel := RoundedView { session_list } }
                      b: View { log_panel := RoundedView { log_list } }
                  }
                  b: View {
                      center_panel := RoundedView {
                          tab_bar := View { console, bof, files, procs, creds, graph }
                          tab_bodies := View { pane_console, pane_bof, pane_files, pane_procs, pane_creds, pane_graph }
                      }
                  }
              }
          }
      }
  }
  ```

* **Proposed Structure for Redesign**:
  ```rust
  main_window := Window {
      body +: {
          flow: Down
          connect_view := SolidView { ... } // Redesigned to use classic Swing light gray styling
          main_view := SolidView {
              flow: Down
              menu_bar := View { ... } // NEW: Horizontal menu bar at top
              tool_bar := View { ... } // NEW: Horizontal toolbar below menu bar
              conn_bar := SolidView { ... } // Redesigned or integrated connection status bar
              
              main_split := Splitter {
                  axis: Vertical
                  align: FromA(350.0) // Gives top pane ~350px height
                  
                  // Top Pane: Session Visualization only
                  a: View {
                      left_panel := RoundedView {
                          sessions_header := View { ... } // Toggle buttons for Table vs Graph
                          // Either session_list (table) or session_graph (graph) depending on state
                          session_list := mod.widgets.SessionList{}
                          session_graph := mod.widgets.SessionGraph{ visible: false } 
                      }
                  }
                  
                  // Bottom Pane: Tabbed Interaction Pane
                  b: View {
                      center_panel := RoundedView {
                          tab_bar := View { 
                              // Tabs: Console, Event Log (MOVED), BOF, Files, Processes, Credentials, Graph (optional, since it is visualization)
                              console_tab, event_log_tab, bof_tab, files_tab, procs_tab, creds_tab
                          }
                          tab_bodies := View {
                              pane_console, pane_event_log, pane_bof, pane_files, pane_procs, pane_creds
                          }
                      }
                  }
              }
              
              status_bar := View { ... } // NEW: Status bar at bottom
          }
      }
  }
  ```

### 3.2 Definition of `MenuBar` and `ToolBar`

In Makepad 2.0, standard custom UI widgets are composed from simpler widgets inside the `script_mod!` DSL:

1. **`MenuBar` Component**:
   Define `MenuBar` as a horizontal `View` at the top of the window frame.
   ```rust
   menu_bar := View {
       width: Fill, height: 26
       flow: Right, spacing: 4.0
       padding: Inset { left: 8.0, right: 8.0 }
       draw_bg.color: Cbar // Light Gray
       
       menu_cobalt_strike := Button { text: "Cobalt Strike", draw_bg.color: #x00000000, draw_text.color: Cprimary, draw_bg.border_size: 0.0 }
       menu_view := Button { text: "View", draw_bg.color: #x00000000, draw_text.color: Cprimary, draw_bg.border_size: 0.0 }
       menu_attacks := Button { text: "Attacks", draw_bg.color: #x00000000, draw_text.color: Cprimary, draw_bg.border_size: 0.0 }
       menu_reporting := Button { text: "Reporting", draw_bg.color: #x00000000, draw_text.color: Cprimary, draw_bg.border_size: 0.0 }
       menu_help := Button { text: "Help", draw_bg.color: #x00000000, draw_text.color: Cprimary, draw_bg.border_size: 0.0 }
   }
   ```
   *Interaction*: Buttons will fire click events. To build actual menu popups, we can either trigger sub-dialog views overlaying the screen, or open popups/drawers using the `View` visibility state in `handle_actions`.

2. **`ToolBar` Component**:
   Define `ToolBar` right below the menu bar, as a horizontal row of icon buttons separated by 1px dividers:
   ```rust
   tool_bar := View {
       width: Fill, height: 32
       flow: Right, spacing: 6.0
       padding: Inset { left: 10.0, right: 10.0 }
       draw_bg.color: Cpanel // Gray
       
       btn_connect := Button { text: "🔌", draw_bg.color: Cbar, width: 26, height: 26 }
       btn_disconnect := Button { text: "🚫", draw_bg.color: Cbar, width: 26, height: 26 }
       div_1 := View { width: 1, height: 18, draw_bg.color: Cborder }
       btn_listeners := Button { text: "🎧", draw_bg.color: Cbar, width: 26, height: 26 }
       btn_table := Button { text: "📊", draw_bg.color: Cbar, width: 26, height: 26 }
       btn_graph := Button { text: "🕸️", draw_bg.color: Cbar, width: 26, height: 26 }
       ...
   }
   ```

### 3.3 Target Modifiable Regions in `main.rs`

To perform the layout migration, the following sections in `crates/client-ui/src/main.rs` must be edited or refactored:

1. **`script_mod!` Colors Ramp** (Lines 58–78):
   Redefine the hex codes to map to the Cobalt Strike light-gray/steel-blue theme. Change colors such as `Cbg`, `Cpanel`, `Cbar`, `Crow`, `Crowsel`, `Caccent`, `Csuccess`, and `Cprimary` to their new values. Note that `IS_DARK` toggle should toggle between the classic Swing theme (Light) and a darker variation of it (or One Dark Pro as a toggle choice, but defaults should be Light Gray).
2. **`main_split` UI layout** (Lines 819–879):
   - Replace the horizontal splitter `a` inside `main_split` with a single `View` containing `left_panel` (the beacon table/graph pane).
   - Clean up the old `log_panel` definition from `a.b` and move it to the tab bodies pane (e.g. `pane_event_log`).
3. **Tab Bar and tab bodies** (Lines 893–1256):
   - Add `event_log_tab` to `tab_bar`.
   - Add `pane_event_log` in tab bodies, linking it to `mod.widgets.LogList{}`.
   - Re-arrange tabs sequence if necessary (Console, Event Log, BOF, Files, Processes, Credentials, Graph).
4. **`App` States and Handlers** (Lines 1266–2246):
   - **`Tab` enum** (Lines 1287–1295): Add `EventLog` variant.
   - **`apply_theme`** (Lines 1519–1812): Re-bind elements to reference the Swing colors.
   - **`set_active_tab`** (Lines 1815–1847): Add visibility rules for the new `pane_event_log` and `line_event_log`.
   - **`handle_actions`** (Lines 1859–2224):
     - Bind listeners for the tab bar click event (`tab_event_log`).
     - Bind actions for new MenuBar and ToolBar buttons.
     - Add logic for toggling visualizations in the top pane (e.g. clicking the Toolbar's Beacons `📊` button sets `session_list` to visible and `session_graph` to hidden; clicking Session Graph `🕸️` does the inverse).

---

## 4. Implementation Strategy

To safely redesign the UI without breaking existing functionality (which compiled successfully on the current main branch):

### Step 1: Theme Reference Updates
Modify `crates/client-ui/src/theme.rs` to set the new default palette. Set the `light()` method palette to return the classic light-gray/steel-blue Swing colors (since it serves as our Cobalt Strike redesign baseline). Optionally, modify `dark()` to be a dark version of the steel-blue theme or keep the existing One Dark Pro. Ensure the `#x` hex variables inside `crates/client-ui/src/main.rs` match the new default palette exactly.

### Step 2: Move Event Log to Tabs & Simplify Top Splitter
In `crates/client-ui/src/main.rs`:
- Remove the inner splitter `a` inside `main_split`.
- Make `main_split.a` a single view for the Session visualizers (tabular list + topological graph).
- Move the `log_panel` declaration to `pane_event_log` inside bottom tabs.
- Add the `Event Log` button to the tab bar.
- Update `Tab` enum, `set_active_tab` logic, and actions in `handle_actions` to support the Event Log tab.

### Step 3: Implement MenuBar and ToolBar Views
- Add the `menu_bar` and `tool_bar` View declarations in `main_view`'s body layout.
- Bind the action hooks in `handle_actions` for the menu and toolbar items.
- Bind toolbar buttons `📊` and `🕸️` to toggle the visibility of `session_list` and `session_graph` inside the top pane.

### Step 4: Verification and Polish
- Compile the code using `cargo check --profile gui -p nyx-client-ui` to verify syntax.
- Ensure the layout sizes and margins look correct in the final render.
