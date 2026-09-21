#[derive(Clone, Copy)]
enum State {
    Ground,
    Escape,
    Csi,
    Osc,
    OscEscape,
    String,
    StringEscape,
}

#[must_use]
pub fn strip_ansi(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut state = State::Ground;

    for &byte in input {
        state = match (state, byte) {
            (State::Ground, 0x1b) => State::Escape,
            (State::Ground, 0x9b) => State::Csi,
            (State::Ground, _) => {
                output.push(byte);
                State::Ground
            }
            (State::Escape, b'[') => State::Csi,
            (State::Escape, b']') => State::Osc,
            (State::Escape, b'P' | b'X' | b'^' | b'_') => State::String,
            (State::Escape, 0x30..=0x7e) => State::Ground,
            (State::Escape, _) => State::Escape,
            (State::Csi, 0x40..=0x7e) => State::Ground,
            (State::Csi, _) => State::Csi,
            (State::Osc, 0x07) => State::Ground,
            (State::Osc, 0x1b) => State::OscEscape,
            (State::Osc, _) => State::Osc,
            (State::OscEscape, b'\\') => State::Ground,
            (State::OscEscape, 0x1b) => State::OscEscape,
            (State::OscEscape, _) => State::Osc,
            (State::String, 0x1b) => State::StringEscape,
            (State::String, _) => State::String,
            (State::StringEscape, b'\\') => State::Ground,
            (State::StringEscape, 0x1b) => State::StringEscape,
            (State::StringEscape, _) => State::String,
        };
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_color_cursor_and_osc_sequences() {
        let input = b"\x1b[31mFLAG{test}\x1b[0m\x1b[2K\x1b]0;secret title\x07!";

        assert_eq!(strip_ansi(input), b"FLAG{test}!".to_vec());
    }

    #[test]
    fn preserves_utf8_and_incomplete_text() {
        let input = "result: café 🚩".as_bytes();
        assert_eq!(strip_ansi(input), input);
    }

    #[test]
    fn drops_incomplete_escape_sequence() {
        assert_eq!(strip_ansi(b"visible\x1b[31"), b"visible".to_vec());
    }
}
