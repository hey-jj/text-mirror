//! A process-wide bridge from anydoc's log facade to a per-conversion
//! capture sink.
//!
//! anydoc reports recovered and skipped content through the `log`
//! facade. This bridge installs one global logger that forwards
//! anydoc warnings to a thread-local sink, so the converter running on
//! this thread collects exactly the messages from its own conversion
//! and promotes them to manifest warnings. A partially extracted
//! document never reads as silently complete.

use std::cell::RefCell;
use std::sync::Once;

thread_local! {
    static CAPTURE: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

struct AnydocLogBridge;

impl log::Log for AnydocLogBridge {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record) {
        if record.level() > log::Level::Warn || !record.target().starts_with("anydoc") {
            return;
        }
        CAPTURE.with(|capture| {
            if let Some(sink) = capture.borrow_mut().as_mut() {
                sink.push(record.args().to_string());
            }
        });
    }

    fn flush(&self) {}
}

static BRIDGE: AnydocLogBridge = AnydocLogBridge;
static INSTALL: Once = Once::new();

fn install_bridge() {
    INSTALL.call_once(|| {
        if log::set_logger(&BRIDGE).is_ok() {
            log::set_max_level(log::LevelFilter::Warn);
        }
    });
}

/// Runs `work` with the capture sink active on this thread and
/// returns its result beside the captured anydoc messages.
pub fn capture_anydoc<T>(work: impl FnOnce() -> T) -> (T, Vec<String>) {
    install_bridge();
    CAPTURE.with(|capture| *capture.borrow_mut() = Some(Vec::new()));
    let result = work();
    let captured = CAPTURE
        .with(|capture| capture.borrow_mut().take())
        .unwrap_or_default();
    (result, captured)
}
