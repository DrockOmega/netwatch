use std::io::{Read, Write};
use std::sync::Mutex;

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use tauri::ipc::{Channel, InvokeResponseBody};

/// The console's only secret: the gateway bearer token, read from the gateway's config dir.
#[tauri::command]
fn gateway_token() -> Result<String, String> {
    let home = std::env::var("HOME").map_err(|e| e.to_string())?;
    std::fs::read_to_string(format!("{home}/.config/netwatch-gateway/ui.token"))
        .map(|token| token.trim().to_string())
        .map_err(|e| format!("gateway token unreadable: {e}"))
}

/// The bottom terminal panel: one PTY running a fixed command. The webview can type into it
/// and resize it, never choose what it runs.
struct Terminal {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn Child + Send + Sync>,
}

#[derive(Default)]
struct TerminalSlot(Mutex<Option<Terminal>>);

const TERMINAL_COMMAND: &str = "exec claude";

fn pty_size(cols: u16, rows: u16) -> PtySize {
    PtySize { rows, cols, pixel_width: 0, pixel_height: 0 }
}

/// Starts (or restarts) the terminal; output streams to `output`, and an empty message marks exit.
#[tauri::command]
fn terminal_start(
    slot: tauri::State<TerminalSlot>,
    cols: u16,
    rows: u16,
    output: Channel<InvokeResponseBody>,
) -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|e| e.to_string())?;
    let pair = native_pty_system().openpty(pty_size(cols, rows)).map_err(|e| e.to_string())?;
    let mut command = CommandBuilder::new("bash");
    command.args(["-lc", TERMINAL_COMMAND]);
    command.cwd(format!("{home}/dev"));
    command.env("TERM", "xterm-256color");
    let child = pair.slave.spawn_command(command).map_err(|e| e.to_string())?;
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let writer = pair.master.take_writer().map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 || output.send(InvokeResponseBody::Raw(buf[..n].to_vec())).is_err() {
                break;
            }
        }
        let _ = output.send(InvokeResponseBody::Raw(Vec::new()));
    });
    let previous = slot.0.lock().unwrap().replace(Terminal { master: pair.master, writer, child });
    if let Some(mut old) = previous {
        let _ = old.child.kill();
    }
    Ok(())
}

#[tauri::command]
fn terminal_write(slot: tauri::State<TerminalSlot>, data: String) -> Result<(), String> {
    match slot.0.lock().unwrap().as_mut() {
        Some(term) => term.writer.write_all(data.as_bytes()).map_err(|e| e.to_string()),
        None => Err("terminal not started".into()),
    }
}

#[tauri::command]
fn terminal_resize(slot: tauri::State<TerminalSlot>, cols: u16, rows: u16) -> Result<(), String> {
    match slot.0.lock().unwrap().as_ref() {
        Some(term) => term.master.resize(pty_size(cols, rows)).map_err(|e| e.to_string()),
        None => Ok(()),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(TerminalSlot::default())
        .invoke_handler(tauri::generate_handler![
            gateway_token,
            terminal_start,
            terminal_write,
            terminal_resize
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
