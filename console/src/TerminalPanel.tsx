import { Channel, invoke } from "@tauri-apps/api/core";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { PointerEvent, useEffect, useRef, useState } from "react";

/** Bottom terminal running Claude Code (the command is fixed on the Rust side). */
export function TerminalPanel({ open }: { open: boolean }) {
  const host = useRef<HTMLDivElement>(null);
  const fit = useRef<FitAddon | null>(null);
  const [height, setHeight] = useState(
    () => Number(localStorage.getItem("terminal-height")) || Math.round(window.innerHeight * 0.34),
  );

  const drag = (down: PointerEvent<HTMLDivElement>) => {
    const handle = down.currentTarget;
    const startY = down.clientY;
    const startHeight = height;
    handle.setPointerCapture(down.pointerId);
    const move = (event: globalThis.PointerEvent) =>
      setHeight(Math.max(120, Math.min(window.innerHeight - 160, startHeight + startY - event.clientY)));
    const up = () => {
      handle.removeEventListener("pointermove", move);
      handle.removeEventListener("pointerup", up);
      setHeight((h) => (localStorage.setItem("terminal-height", String(h)), h));
    };
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", up);
  };

  useEffect(() => {
    const term = new Terminal({
      fontFamily: "monospace",
      fontSize: 13,
      cursorBlink: true,
      theme: { background: "#0b0f14" },
    });
    const fitter = new FitAddon();
    term.loadAddon(fitter);
    term.attachCustomKeyEventHandler((event) => !(event.ctrlKey && event.key === "`")); // the panel toggle, not a keystroke
    term.open(host.current!);
    fitter.fit();
    fit.current = fitter;

    let ended = false;
    const start = () => {
      ended = false;
      const output = new Channel<ArrayBuffer>();
      output.onmessage = (chunk) => {
        if (chunk.byteLength > 0) return term.write(new Uint8Array(chunk));
        ended = true;
        term.write("\r\n\x1b[2m[session ended: press Enter to start a new one]\x1b[0m\r\n");
      };
      invoke("terminal_start", { cols: term.cols, rows: term.rows, output }).catch((error) =>
        term.write(`\r\n\x1b[31m${String(error)}\x1b[0m\r\n`),
      );
    };
    const input = term.onData((data) => {
      if (!ended) return void invoke("terminal_write", { data });
      if (data === "\r") start();
    });
    const resize = term.onResize(({ cols, rows }) => void invoke("terminal_resize", { cols, rows }));
    const observer = new ResizeObserver(() => host.current?.offsetParent && fitter.fit());
    observer.observe(host.current!);
    start();
    return () => {
      observer.disconnect();
      input.dispose();
      resize.dispose();
      term.dispose();
    };
  }, []);

  useEffect(() => {
    if (open) fit.current?.fit();
  }, [open]);

  return (
    <section className="terminal-panel" hidden={!open} style={{ height }}>
      <div className="terminal-resize" onPointerDown={drag} title="Drag to resize" />
      <div ref={host} className="terminal-host" />
    </section>
  );
}
