use serde::{Deserialize, Serialize};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct GlyphVertex {
    pub x: f32,
    pub y: f32,
    pub u: f32,
    pub v: f32,
    pub r: f32,
    pub g: f32,
    pub b: f32,
    pub a: f32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct RectQuad {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
    pub r: f32,
    pub g: f32,
    pub b: f32,
    pub a: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CursorPosition {
    pub line: usize,
    pub column: usize,
    pub pixel_x: f32,
    pub pixel_y: f32,
    pub visible: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectionRange {
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewportState {
    pub scroll_x: f32,
    pub scroll_y: f32,
    pub width: f32,
    pub height: f32,
    pub char_width: f32,
    pub line_height: f32,
    pub gutter_width: f32,
}

impl Default for ViewportState {
    fn default() -> Self {
        Self {
            scroll_x: 0.0,
            scroll_y: 0.0,
            width: 1920.0,
            height: 1080.0,
            char_width: 8.5,
            line_height: 20.0,
            gutter_width: 48.0,
        }
    }
}

pub struct CrexRenderer {
    pub viewport: ViewportState,
    pub cursor: CursorPosition,
    pub selection: Option<SelectionRange>,
}

impl CrexRenderer {
    pub fn new() -> Self {
        Self {
            viewport: ViewportState::default(),
            cursor: CursorPosition {
                line: 0,
                column: 0,
                pixel_x: 48.0,
                pixel_y: 0.0,
                visible: true,
            },
            selection: None,
        }
    }

    pub fn set_viewport_size(&mut self, width: f32, height: f32) {
        self.viewport.width = width;
        self.viewport.height = height;
    }

    pub fn scroll(&mut self, delta_x: f32, delta_y: f32) {
        self.viewport.scroll_x = (self.viewport.scroll_x + delta_x).max(0.0);
        self.viewport.scroll_y = (self.viewport.scroll_y + delta_y).max(0.0);
    }

    pub fn set_cursor(&mut self, line: usize, column: usize) {
        self.cursor.line = line;
        self.cursor.column = column;
        self.cursor.pixel_x = self.viewport.gutter_width + (column as f32 * self.viewport.char_width) - self.viewport.scroll_x;
        self.cursor.pixel_y = (line as f32 * self.viewport.line_height) - self.viewport.scroll_y;
    }

    /// Generates selection rectangles in screen pixel space
    pub fn compute_selection_quads(&self, lines: &[String]) -> Vec<RectQuad> {
        let mut quads = Vec::new();
        let Some(sel) = &self.selection else { return quads };

        let (start, end) = if (sel.start_line, sel.start_col) <= (sel.end_line, sel.end_col) {
            ((sel.start_line, sel.start_col), (sel.end_line, sel.end_col))
        } else {
            ((sel.end_line, sel.end_col), (sel.start_line, sel.start_col))
        };

        for line_idx in start.0..=end.0 {
            if line_idx >= lines.len() {
                break;
            }
            let line_len = lines[line_idx].chars().count();
            let col_start = if line_idx == start.0 { start.1 } else { 0 };
            let col_end = if line_idx == end.0 { end.1.min(line_len) } else { line_len };

            if col_end > col_start {
                let x = self.viewport.gutter_width + (col_start as f32 * self.viewport.char_width) - self.viewport.scroll_x;
                let y = (line_idx as f32 * self.viewport.line_height) - self.viewport.scroll_y;
                let w = ((col_end - col_start) as f32) * self.viewport.char_width;
                let h = self.viewport.line_height;

                quads.push(RectQuad {
                    x,
                    y,
                    w,
                    h,
                    r: 0.2, // #333333 selection highlight
                    g: 0.2,
                    b: 0.2,
                    a: 0.8,
                });
            }
        }
        quads
    }

    /// Generates cursor quad (1px solid white)
    pub fn compute_cursor_quad(&self) -> RectQuad {
        RectQuad {
            x: self.cursor.pixel_x,
            y: self.cursor.pixel_y,
            w: 1.5,
            h: self.viewport.line_height,
            r: 1.0,
            g: 1.0,
            b: 1.0,
            a: 1.0,
        }
    }
}
