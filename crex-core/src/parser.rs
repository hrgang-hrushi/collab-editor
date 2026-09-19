use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyntaxToken {
    pub kind: String,
    pub start: usize,
    pub length: usize,
    pub color_rgba: [f32; 4],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AstSnapshot {
    pub language: String,
    pub token_count: usize,
    pub tokens: Vec<SyntaxToken>,
}

pub struct CrexSyntaxParser {
    pub language: String,
}

impl CrexSyntaxParser {
    pub fn new(language: &str) -> Self {
        Self {
            language: language.to_string(),
        }
    }

    /// Fast lexical tokenizer producing token ranges and syntax colors
    pub fn parse_tokens(&self, text: &str) -> AstSnapshot {
        let mut tokens = Vec::new();
        let chars: Vec<(usize, char)> = text.char_indices().collect();
        let len = chars.len();
        let mut i = 0;

        let keywords = [
            "fn", "let", "mut", "pub", "struct", "enum", "impl", "use", "mod",
            "if", "else", "match", "return", "class", "func", "import", "var",
            "val", "def", "const", "for", "while", "in", "async", "await",
        ];

        while i < len {
            let (byte_idx, ch) = chars[i];

            // Comments
            if ch == '/' && i + 1 < len && chars[i + 1].1 == '/' {
                let start = byte_idx;
                while i < len && chars[i].1 != '\n' {
                    i += 1;
                }
                let end = if i < len { chars[i].0 } else { text.len() };
                tokens.push(SyntaxToken {
                    kind: "comment".to_string(),
                    start,
                    length: end - start,
                    color_rgba: [0.4, 0.4, 0.4, 1.0], // #666666
                });
                continue;
            }

            // String literals
            if ch == '"' || ch == '\'' {
                let quote = ch;
                let start = byte_idx;
                i += 1;
                while i < len && chars[i].1 != quote {
                    if chars[i].1 == '\\' && i + 1 < len {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if i < len {
                    i += 1;
                }
                let end = if i < len { chars[i].0 } else { text.len() };
                tokens.push(SyntaxToken {
                    kind: "string".to_string(),
                    start,
                    length: end - start,
                    color_rgba: [0.8, 0.8, 0.8, 1.0], // Light gray string
                });
                continue;
            }

            // Identifiers / Keywords
            if ch.is_alphabetic() || ch == '_' {
                let start = byte_idx;
                while i < len && (chars[i].1.is_alphanumeric() || chars[i].1 == '_') {
                    i += 1;
                }
                let end = if i < len { chars[i].0 } else { text.len() };
                let word = &text[start..end];

                let is_kw = keywords.contains(&word);
                tokens.push(SyntaxToken {
                    kind: if is_kw { "keyword".to_string() } else { "identifier".to_string() },
                    start,
                    length: end - start,
                    color_rgba: if is_kw {
                        [1.0, 1.0, 1.0, 1.0] // #FFFFFF keyword
                    } else {
                        [0.7, 0.7, 0.7, 1.0] // #B0B0B0 identifier
                    },
                });
                continue;
            }

            // Numbers
            if ch.is_numeric() {
                let start = byte_idx;
                while i < len && (chars[i].1.is_numeric() || chars[i].1 == '.' || chars[i].1 == '_') {
                    i += 1;
                }
                let end = if i < len { chars[i].0 } else { text.len() };
                tokens.push(SyntaxToken {
                    kind: "number".to_string(),
                    start,
                    length: end - start,
                    color_rgba: [0.9, 0.9, 0.9, 1.0],
                });
                continue;
            }

            i += 1;
        }

        AstSnapshot {
            language: self.language.clone(),
            token_count: tokens.len(),
            tokens,
        }
    }
}
