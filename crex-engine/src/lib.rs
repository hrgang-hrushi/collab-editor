pub mod shaders;
pub mod renderer;
pub mod ast_crdt;

pub use renderer::{CrexRenderer, RectQuad, CursorPosition, SelectionRange, ViewportState};
pub use ast_crdt::{AstCrdtEngine, AstSyncDelta, AstNode, AstNodeId, AstMutation};

pub struct CrexEngineCore {
    pub renderer: CrexRenderer,
    pub crdt: AstCrdtEngine,
}

impl CrexEngineCore {
    pub fn new(client_id: u64) -> Self {
        Self {
            renderer: CrexRenderer::new(),
            crdt: AstCrdtEngine::new(client_id),
        }
    }

    pub fn get_glyph_shader_code() -> &'static str {
        shaders::GLYPH_SHADER_WGSL
    }

    pub fn get_rect_shader_code() -> &'static str {
        shaders::RECT_SHADER_WGSL
    }

    pub fn render_frame_quads(&self, lines: &[String]) -> Vec<RectQuad> {
        let mut quads = self.renderer.compute_selection_quads(lines);
        if self.renderer.cursor.visible {
            quads.push(self.renderer.compute_cursor_quad());
        }
        quads
    }
}
