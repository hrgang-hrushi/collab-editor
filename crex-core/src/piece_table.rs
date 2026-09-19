/// Crex High-Performance Piece Table Buffer
/// Memory-safe, append-only modification buffer for native text editing.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferSource {
    Original,
    Add,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Piece {
    pub source: BufferSource,
    pub start: usize,
    pub length: usize,
}

pub struct PieceTable {
    original: String,
    add: String,
    pieces: Vec<Piece>,
}

impl PieceTable {
    pub fn new(initial_text: &str) -> Self {
        let original = initial_text.to_string();
        let length = original.len();
        let pieces = if length > 0 {
            vec![Piece {
                source: BufferSource::Original,
                start: 0,
                length,
            }]
        } else {
            Vec::new()
        };

        Self {
            original,
            add: String::new(),
            pieces,
        }
    }

    pub fn len(&self) -> usize {
        self.pieces.iter().map(|p| p.length).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn insert(&mut self, offset: usize, text: &str) {
        if text.is_empty() {
            return;
        }

        let add_start = self.add.len();
        self.add.push_str(text);
        let new_piece = Piece {
            source: BufferSource::Add,
            start: add_start,
            length: text.len(),
        };

        if self.pieces.is_empty() {
            self.pieces.push(new_piece);
            return;
        }

        let mut current_offset = 0;
        let mut target_idx = self.pieces.len();
        let mut split_piece: Option<(Piece, Piece)> = None;

        for (idx, piece) in self.pieces.iter().enumerate() {
            let next_offset = current_offset + piece.length;
            if offset == current_offset {
                target_idx = idx;
                break;
            } else if offset > current_offset && offset < next_offset {
                let split_point = offset - current_offset;
                let left = Piece {
                    source: piece.source,
                    start: piece.start,
                    length: split_point,
                };
                let right = Piece {
                    source: piece.source,
                    start: piece.start + split_point,
                    length: piece.length - split_point,
                };
                split_piece = Some((left, right));
                target_idx = idx;
                break;
            }
            current_offset = next_offset;
        }

        if let Some((left, right)) = split_piece {
            self.pieces[target_idx] = left;
            self.pieces.insert(target_idx + 1, new_piece);
            self.pieces.insert(target_idx + 2, right);
        } else {
            self.pieces.insert(target_idx, new_piece);
        }
    }

    pub fn delete(&mut self, offset: usize, length: usize) {
        if length == 0 || self.pieces.is_empty() {
            return;
        }

        let del_end = offset + length;
        let mut current_offset = 0;
        let mut new_pieces = Vec::new();

        for piece in &self.pieces {
            let piece_end = current_offset + piece.length;

            if piece_end <= offset || current_offset >= del_end {
                // Entirely outside delete range
                new_pieces.push(piece.clone());
            } else {
                // Overlaps with delete range
                if current_offset < offset {
                    // Keep head
                    new_pieces.push(Piece {
                        source: piece.source,
                        start: piece.start,
                        length: offset - current_offset,
                    });
                }
                if piece_end > del_end {
                    // Keep tail
                    let cut = del_end - current_offset;
                    new_pieces.push(Piece {
                        source: piece.source,
                        start: piece.start + cut,
                        length: piece.length - cut,
                    });
                }
            }
            current_offset = piece_end;
        }

        self.pieces = new_pieces;
    }

    pub fn get_text(&self) -> String {
        let mut result = String::with_capacity(self.len());
        for piece in &self.pieces {
            let source_str = match piece.source {
                BufferSource::Original => &self.original,
                BufferSource::Add => &self.add,
            };
            result.push_str(&source_str[piece.start..piece.start + piece.length]);
        }
        result
    }

    pub fn line_count(&self) -> usize {
        let text = self.get_text();
        if text.is_empty() {
            1
        } else {
            text.lines().count().max(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_piece_table_basic() {
        let mut pt = PieceTable::new("Hello World");
        assert_eq!(pt.get_text(), "Hello World");

        pt.insert(5, ", Beautiful");
        assert_eq!(pt.get_text(), "Hello, Beautiful World");

        pt.delete(5, 11);
        assert_eq!(pt.get_text(), "Hello World");
    }
}
