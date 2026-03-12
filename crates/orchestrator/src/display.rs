// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt::Display,
    io::stdout,
    sync::Mutex,
    time::{Duration, Instant},
};

use crossterm::{
    cursor::{RestorePosition, SavePosition},
    style::{Print, PrintStyledContent, Stylize},
    terminal::{Clear, ClearType},
};
use prettytable::{
    Table,
    format::{self},
    row,
};

struct StepRecord {
    name: String,
    duration: Duration,
}

static TIMELINE: Mutex<Vec<StepRecord>> = Mutex::new(Vec::new());
static CURRENT_ACTION: Mutex<Option<(String, Instant)>> = Mutex::new(None);

pub fn header<S: Display>(message: S) {
    if cfg!(not(test)) {
        crossterm::execute!(
            stdout(),
            PrintStyledContent(format!("\n{message}\n").green().bold()),
        )
        .unwrap();
    }
}

pub fn error<S: Display>(message: S) {
    if cfg!(not(test)) {
        crossterm::execute!(
            stdout(),
            PrintStyledContent(format!("\n{message}\n").red().bold()),
        )
        .unwrap();
    }
}

pub fn warn<S: Display>(message: S) {
    if cfg!(not(test)) {
        crossterm::execute!(
            stdout(),
            PrintStyledContent(format!("\n{message}\n").bold()),
        )
        .unwrap();
    }
}

pub fn config<N: Display, V: Display>(name: N, value: V) {
    if cfg!(not(test)) {
        crossterm::execute!(
            stdout(),
            PrintStyledContent(format!("{name}: ").bold()),
            Print(format!("{value}\n"))
        )
        .unwrap();
    }
}

pub fn action<S: Display>(message: S) {
    let name = message.to_string();
    *CURRENT_ACTION.lock().unwrap() = Some((name.clone(), Instant::now()));
    if cfg!(not(test)) {
        crossterm::execute!(stdout(), Print(format!("{name} ... ")), SavePosition).unwrap();
    }
}

pub fn status<S: Display>(status: S) {
    if cfg!(not(test)) {
        crossterm::execute!(
            stdout(),
            RestorePosition,
            SavePosition,
            Clear(ClearType::UntilNewLine),
            Print(format!("[{status}]"))
        )
        .unwrap();
    }
}

pub fn done() {
    let record = CURRENT_ACTION.lock().unwrap().take();
    if let Some((name, start)) = record {
        let elapsed = start.elapsed();
        TIMELINE.lock().unwrap().push(StepRecord {
            name,
            duration: elapsed,
        });
        if cfg!(not(test)) {
            crossterm::execute!(
                stdout(),
                RestorePosition,
                Clear(ClearType::UntilNewLine),
                Print(format!("[{} {}]\n", "Ok".green(), format_duration(elapsed)))
            )
            .unwrap();
        }
    } else if cfg!(not(test)) {
        crossterm::execute!(
            stdout(),
            RestorePosition,
            Clear(ClearType::UntilNewLine),
            Print(format!("[{}]\n", "Ok".green()))
        )
        .unwrap();
    }
}

pub fn newline() {
    if cfg!(not(test)) {
        crossterm::execute!(stdout(), Print("\n")).unwrap();
    }
}

/// Default style for tables printed to stdout.
pub fn default_table_format() -> format::TableFormat {
    format::FormatBuilder::new()
        .separators(
            &[
                format::LinePosition::Top,
                format::LinePosition::Bottom,
                format::LinePosition::Title,
            ],
            format::LineSeparator::new('-', '-', '-', '-'),
        )
        .padding(1, 1)
        .build()
}

/// Format a duration as a human-readable string.
pub fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    if total_secs >= 60 {
        let mins = total_secs / 60;
        let secs = total_secs % 60;
        format!("{mins}m {secs:02}s")
    } else if total_secs > 0 {
        format!("{total_secs}s")
    } else {
        format!("{}ms", d.as_millis())
    }
}

/// Print an elapsed-time summary table for all recorded steps.
pub fn print_timeline() {
    if cfg!(test) {
        return;
    }
    let steps = TIMELINE.lock().unwrap();
    if steps.is_empty() {
        return;
    }

    let total: Duration = steps.iter().map(|s| s.duration).sum();
    let total_secs = total.as_secs_f64();

    let mut table = Table::new();
    table.set_format(default_table_format());
    table.set_titles(row![bH3->"Step Timeline"]);
    table.add_row(row![b->"Step", b->"Duration", b->"%"]);

    for step in steps.iter() {
        let pct = if total_secs > 0.0 {
            step.duration.as_secs_f64() / total_secs * 100.0
        } else {
            0.0
        };
        table.add_row(row![
            step.name,
            format_duration(step.duration),
            format!("{pct:.1}%")
        ]);
    }

    table.add_row(row![bH3->""]);
    table.add_row(row![b->"Total", b->format_duration(total), b->"100.0%"]);
    table.printstd();
}

/// Reset the timeline state. Call at the start of each benchmark suite.
pub fn clear_timeline() {
    TIMELINE.lock().unwrap().clear();
    *CURRENT_ACTION.lock().unwrap() = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_millis(0)), "0ms");
        assert_eq!(format_duration(Duration::from_millis(42)), "42ms");
        assert_eq!(format_duration(Duration::from_millis(999)), "999ms");
        assert_eq!(format_duration(Duration::from_secs(1)), "1s");
        assert_eq!(format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(format_duration(Duration::from_secs(60)), "1m 00s");
        assert_eq!(format_duration(Duration::from_secs(75)), "1m 15s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "61m 01s");
    }
}
