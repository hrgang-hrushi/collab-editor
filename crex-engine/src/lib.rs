pub mod ast_crdt;
pub mod renderer;
pub mod shaders;

use ast_crdt::{AstCrdtEngine, AstMutation};
use renderer::WgpuRenderer;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct CrexEngine {
    renderer: WgpuRenderer,
    crdt: AstCrdtEngine,
    buffer_content: String,
    language: String,
    last_render_time: f64,
    frame_count: u64,
}

#[wasm_bindgen]
impl CrexEngine {
    #[wasm_bindgen(constructor)]
    pub async fn new(width: u32, height: u32, peer_id: u64) -> Result<CrexEngine, JsValue> {
        console_error_panic_hook::set_once();

        let renderer = WgpuRenderer::new_headless(width, height)
            .await
            .map_err(|e| JsValue::from_str(&e))?;

        let mut crdt = AstCrdtEngine::new(peer_id);
        let default_code = "// CRUX BARE-METAL WEBGPU ENGINE [120FPS]\nfn main() {\n    println!(\"CRUX_ONLINE\");\n}\n";
        crdt.parse_and_sync_source(default_code, "rust");

        Ok(CrexEngine {
            renderer,
            crdt,
            buffer_content: default_code.to_string(),
            language: "rust".to_string(),
            last_render_time: 0.0,
            frame_count: 0,
        })
    }

    #[wasm_bindgen]
    pub fn set_buffer(&mut self, content: String, language: String) {
        self.buffer_content = content.clone();
        self.language = language.clone();
        self.crdt.parse_and_sync_source(&content, &language);
    }

    #[wasm_bindgen]
    pub fn handle_key_down(&mut self, key: String, ctrl: bool, meta: bool, shift: bool) -> bool {
        let _ = (ctrl, meta, shift);
        let mut modified = false;

        let mut lines: Vec<String> = self.buffer_content.lines().map(|s| s.to_string()).collect();
        if lines.is_empty() {
            lines.push(String::new());
        }

        let cur_line = self.renderer.cursor_line.min(lines.len().saturating_sub(1));
        let cur_col = self.renderer.cursor_col.min(lines[cur_line].len());

        match key.as_str() {
            "Backspace" => {
                if cur_col > 0 {
                    lines[cur_line].remove(cur_col - 1);
                    self.renderer.cursor_col -= 1;
                    modified = true;
                } else if cur_line > 0 {
                    let prev_len = lines[cur_line - 1].len();
                    let removed = lines.remove(cur_line);
                    lines[cur_line - 1].push_str(&removed);
                    self.renderer.cursor_line -= 1;
                    self.renderer.cursor_col = prev_len;
                    modified = true;
                }
            }
            "Enter" => {
                let rest = lines[cur_line].split_off(cur_col);
                lines.insert(cur_line + 1, rest);
                self.renderer.cursor_line += 1;
                self.renderer.cursor_col = 0;
                modified = true;
            }
            "ArrowLeft" => {
                if self.renderer.cursor_col > 0 {
                    self.renderer.cursor_col -= 1;
                } else if self.renderer.cursor_line > 0 {
                    self.renderer.cursor_line -= 1;
                    self.renderer.cursor_col = lines[self.renderer.cursor_line].len();
                }
            }
            "ArrowRight" => {
                if self.renderer.cursor_col < lines[cur_line].len() {
                    self.renderer.cursor_col += 1;
                } else if self.renderer.cursor_line + 1 < lines.len() {
                    self.renderer.cursor_line += 1;
                    self.renderer.cursor_col = 0;
                }
            }
            "ArrowUp" => {
                if self.renderer.cursor_line > 0 {
                    self.renderer.cursor_line -= 1;
                    self.renderer.cursor_col = self.renderer.cursor_col.min(lines[self.renderer.cursor_line].len());
                }
            }
            "ArrowDown" => {
                if self.renderer.cursor_line + 1 < lines.len() {
                    self.renderer.cursor_line += 1;
                    self.renderer.cursor_col = self.renderer.cursor_col.min(lines[self.renderer.cursor_line].len());
                }
            }
            char_str if char_str.len() == 1 => {
                lines[cur_line].insert_str(cur_col, char_str);
                self.renderer.cursor_col += 1;
                modified = true;
            }
            _ => {}
        }

        if modified {
            self.buffer_content = lines.join("\n");
            self.crdt.parse_and_sync_source(&self.buffer_content, &self.language);
        }

        modified
    }

    #[wasm_bindgen]
    pub fn handle_mouse(&mut self, x: f64, y: f64, _is_down: bool) {
        let char_w = 9.6;
        let line_h = 20.0;
        let gutter_w = 48.0;
        let padding_x = 8.0;

        let col = (((x - gutter_w - padding_x) / char_w).max(0.0)) as usize;
        let line = ((y + self.renderer.scroll_y as f64) / line_h).max(0.0) as usize;

        self.renderer.cursor_line = line;
        self.renderer.cursor_col = col;
    }

    #[wasm_bindgen]
    pub fn handle_wheel(&mut self, delta_y: f64) {
        self.renderer.scroll_y = (self.renderer.scroll_y + delta_y as f32).max(0.0);
    }

    #[wasm_bindgen]
    pub fn render_frame(&mut self, timestamp_ms: f64) {
        self.frame_count += 1;
        self.last_render_time = timestamp_ms;
        self.renderer.update_buffer_layout(&self.buffer_content, timestamp_ms);
    }

    #[wasm_bindgen]
    pub fn get_content(&self) -> String {
        self.buffer_content.clone()
    }

    #[wasm_bindgen]
    pub fn get_cursor_line(&self) -> usize {
        self.renderer.cursor_line
    }

    #[wasm_bindgen]
    pub fn get_cursor_col(&self) -> usize {
        self.renderer.cursor_col
    }

    #[wasm_bindgen]
    pub fn get_ast_json(&self) -> String {
        self.crdt.to_json()
    }

    #[wasm_bindgen]
    pub fn apply_crdt_mutation(&mut self, json_str: String) -> bool {
        if let Ok(mutation) = serde_json::from_str::<AstMutation>(&json_str) {
            let res = self.crdt.apply_mutation(mutation);
            if res {
                self.buffer_content = self.crdt.to_source();
            }
            res
        } else {
            false
        }
    }
}
