//! Byte-level console framing — the pure, host-testable half of the
//! serial console loop (`firmware.rs`). Source of truth for the framing
//! section of docs/serial-host-protocol.md; the behavior is pinned by the
//! `#[cfg(test)]` suite below (`cargo test -p bolty-esp32`).
//!
//! Hostile-line guarantee (issue #148): a line longer than the capacity
//! fails exactly once and is discarded through the next newline — padding
//! can no longer smuggle a trailing command into the dispatcher.

use heapless::String;

/// Console line capacity in bytes. Must match the framing section of
/// docs/serial-host-protocol.md (pinned by the tests below).
pub const MAX_LINE_LEN: usize = 512;

/// Event emitted by [`LineAssembler::feed`] for one input byte.
#[derive(Debug, PartialEq, Eq)]
pub enum LineEvent<'a> {
    /// A complete, non-empty line. The borrow ends at the next `feed`.
    Line(&'a str),
    /// The line exceeded capacity: the caller emits `command too long`
    /// once; the assembler now discards everything up to and including
    /// the next newline.
    Overflow,
}

/// Folds console bytes into lines with the hostile-line guarantee: an
/// overlong line is reported exactly once and swallowed whole, so the
/// next `Line` event always belongs to a line the host sent after it.
pub struct LineAssembler<const N: usize> {
    line: String<N>,
    discarding: bool,
    done: bool,
}

impl<const N: usize> LineAssembler<N> {
    pub fn new() -> Self {
        Self {
            line: String::new(),
            discarding: false,
            done: false,
        }
    }

    /// Feed one console byte. `\r` is ignored; `\n` completes a line.
    /// Empty lines produce no event. The returned borrow of `self` ends
    /// before the next `feed` call.
    pub fn feed(&mut self, byte: u8) -> Option<LineEvent<'_>> {
        if self.done {
            // The previous feed returned Line(&self.line); clear now that
            // the caller's borrow has ended.
            self.line.clear();
            self.done = false;
        }
        match byte {
            b'\r' => None,
            b'\n' => {
                if self.discarding {
                    // End of an overlong line: swallow it whole and
                    // resume normal parsing with the next line.
                    self.discarding = false;
                    return None;
                }
                if self.line.is_empty() {
                    return None;
                }
                self.done = true;
                Some(LineEvent::Line(self.line.as_str()))
            }
            _ => {
                if self.discarding {
                    return None;
                }
                if self.line.push(byte as char).is_err() {
                    self.line.clear();
                    self.discarding = true;
                    return Some(LineEvent::Overflow);
                }
                None
            }
        }
    }
}

impl<const N: usize> Default for LineAssembler<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collect feed results as owned strings so sequences are assertable:
    /// `L:<text>` for lines, `<OVERFLOW>` for the overflow report.
    fn feed_all<const N: usize>(
        assembler: &mut LineAssembler<N>,
        bytes: &[u8],
    ) -> Vec<std::string::String> {
        let mut events = Vec::new();
        for &byte in bytes {
            match assembler.feed(byte) {
                Some(LineEvent::Overflow) => events.push("<OVERFLOW>".to_string()),
                Some(LineEvent::Line(text)) => events.push(format!("L:{text}")),
                None => {}
            }
        }
        events
    }

    #[test]
    fn issue148_hostile_padding_then_command_is_swallowed_whole() {
        // The literal #148 repro at the firmware's real capacity: 513
        // padding bytes + "burn\n" used to fail with "command too long"
        // and then EXECUTE burn. Now the trailing command is discarded
        // with the rest of the overlong line.
        let mut assembler = LineAssembler::<MAX_LINE_LEN>::new();
        let hostile: Vec<u8> = vec![b'x'; MAX_LINE_LEN + 1]
            .into_iter()
            .chain(b"burn\n".iter().copied())
            .collect();
        assert_eq!(feed_all(&mut assembler, &hostile), vec!["<OVERFLOW>"]);
        // The console recovers: the NEXT line parses normally.
        assert_eq!(
            feed_all(&mut assembler, b"ver\n"),
            vec!["L:ver"],
            "first line after an overlong one must parse normally"
        );
    }

    #[test]
    fn overflow_fires_exactly_once_per_overlong_line() {
        let mut assembler = LineAssembler::<8>::new();
        // Far more overflow bytes than capacity — still one report.
        let hostile: Vec<u8> = vec![b'x'; 100];
        assert_eq!(feed_all(&mut assembler, &hostile), vec!["<OVERFLOW>"]);
        assert_eq!(
            feed_all(&mut assembler, b"\n"),
            Vec::<std::string::String>::new()
        );
        assert_eq!(feed_all(&mut assembler, b"ver\n"), vec!["L:ver"]);
    }

    #[test]
    fn exactly_capacity_line_is_valid_not_overflow() {
        let mut assembler = LineAssembler::<8>::new();
        let full = b"abcdefgh";
        assert_eq!(full.len(), 8);
        assert_eq!(
            feed_all(&mut assembler, full),
            Vec::<std::string::String>::new(),
            "8 bytes into an 8-byte buffer must not overflow"
        );
        assert_eq!(feed_all(&mut assembler, b"\n"), vec!["L:abcdefgh"]);
    }

    #[test]
    fn capacity_plus_one_byte_overflows() {
        let mut assembler = LineAssembler::<8>::new();
        assert_eq!(feed_all(&mut assembler, b"abcdefghi"), vec!["<OVERFLOW>"]);
    }

    #[test]
    fn empty_and_carriage_return_lines_produce_no_events() {
        let mut assembler = LineAssembler::<8>::new();
        assert_eq!(
            feed_all(&mut assembler, b"\n\n\r\n"),
            Vec::<std::string::String>::new()
        );
        assert_eq!(feed_all(&mut assembler, b"ver\r\n"), vec!["L:ver"]);
    }

    #[test]
    fn discard_ends_on_newline_and_next_line_lives() {
        let mut assembler = LineAssembler::<4>::new();
        // Overlong line, then CRLF ends it, then a legitimate command.
        let stream = b"abcdefg\r\nburn\n";
        assert_eq!(
            feed_all(&mut assembler, stream),
            vec!["<OVERFLOW>", "L:burn"],
            "the burn INSIDE the overlong line is gone; a separate later line runs"
        );
    }

    #[test]
    fn max_line_len_matches_the_documented_cap() {
        assert_eq!(MAX_LINE_LEN, 512);
        let doc = include_str!("../../../docs/serial-host-protocol.md");
        assert!(
            doc.contains("512"),
            "docs/serial-host-protocol.md must state the line cap"
        );
        assert!(
            doc.contains("console_framing"),
            "the doc must name console_framing.rs as the framing source of truth"
        );
    }
}
