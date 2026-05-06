from __future__ import annotations

import contextlib
import io
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import product_terminal


class IDSProductGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("IDS Sentinel Terminal")
        self.root.geometry("1180x760")
        self.root.minsize(920, 620)
        self.output_queue: queue.Queue[str] = queue.Queue()

        self.command_var = tk.StringVar(value="status")
        self.scan_path_var = tk.StringVar(value="kddtest.csv")
        self.scan_limit_var = tk.StringVar(value="5000")
        self.hunt_var = tk.StringVar(value="dos_flood")
        self.host_var = tk.StringVar(value="127.0.0.1")
        self.ports_var = tk.StringVar(value="common")
        self.file_path_var = tk.StringVar(value="terminal.cmd")

        self._build_layout()
        self.root.after(100, self._drain_output)
        self.run_command(["status"])

    def _build_layout(self) -> None:
        self.root.columnconfigure(0, weight=0)
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        sidebar = ttk.Frame(self.root, padding=12)
        sidebar.grid(row=0, column=0, sticky="ns")

        main = ttk.Frame(self.root, padding=(0, 12, 12, 12))
        main.grid(row=0, column=1, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(1, weight=1)

        ttk.Label(sidebar, text="IDS Sentinel", font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(0, 12))
        for label, command in [
            ("Status", ["status"]),
            ("Traffic", ["traffic"]),
            ("Attacks", ["attacks"]),
            ("Malware Signals", ["malware", "--limit", "5000"]),
            ("Datasets", ["datasets"]),
            ("Reports", ["reports", "--limit", "20"]),
            ("Cache", ["cache", "--limit", "20"]),
            ("Local Ports", ["ports", "--limit", "25"]),
            ("Processes", ["ps", "--limit", "25"]),
        ]:
            ttk.Button(sidebar, text=label, command=lambda cmd=command: self.run_command(cmd)).pack(fill="x", pady=3)

        ttk.Separator(sidebar).pack(fill="x", pady=12)
        ttk.Button(sidebar, text="Learn Model", command=lambda: self.run_command(["learn"])).pack(fill="x", pady=3)
        ttk.Button(sidebar, text="Clear Output", command=self.clear_output).pack(fill="x", pady=3)

        controls = ttk.Notebook(main)
        controls.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        self._build_command_tab(controls)
        self._build_scan_tab(controls)
        self._build_hunt_tab(controls)
        self._build_network_tab(controls)
        self._build_file_tab(controls)

        self.output = tk.Text(main, wrap="none", font=("Consolas", 10), undo=False)
        self.output.grid(row=1, column=0, sticky="nsew")

        y_scroll = ttk.Scrollbar(main, orient="vertical", command=self.output.yview)
        y_scroll.grid(row=1, column=1, sticky="ns")
        self.output.configure(yscrollcommand=y_scroll.set)

        x_scroll = ttk.Scrollbar(main, orient="horizontal", command=self.output.xview)
        x_scroll.grid(row=2, column=0, sticky="ew")
        self.output.configure(xscrollcommand=x_scroll.set)

    def _build_command_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=8)
        tab.columnconfigure(1, weight=1)
        notebook.add(tab, text="Command")
        ttk.Label(tab, text="Command").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(tab, textvariable=self.command_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(tab, text="Run", command=self.run_freeform_command).grid(row=0, column=2, padx=(8, 0))

    def _build_scan_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=8)
        tab.columnconfigure(1, weight=1)
        notebook.add(tab, text="Scan")
        ttk.Label(tab, text="CSV").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(tab, textvariable=self.scan_path_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(tab, text="Browse", command=self.choose_scan_file).grid(row=0, column=2, padx=(8, 0))
        ttk.Label(tab, text="Limit").grid(row=0, column=3, sticky="w", padx=(12, 8))
        ttk.Entry(tab, width=10, textvariable=self.scan_limit_var).grid(row=0, column=4, sticky="w")
        ttk.Button(tab, text="Scan", command=self.run_scan).grid(row=0, column=5, padx=(8, 0))

    def _build_hunt_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=8)
        tab.columnconfigure(1, weight=1)
        notebook.add(tab, text="Hunt")
        ttk.Label(tab, text="Term").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(tab, textvariable=self.hunt_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(tab, text="Hunt", command=lambda: self.run_command(["hunt", self.hunt_var.get(), "--limit", "20"])).grid(row=0, column=2, padx=(8, 0))

    def _build_network_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=8)
        tab.columnconfigure(1, weight=1)
        notebook.add(tab, text="Network")
        ttk.Label(tab, text="Host").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(tab, textvariable=self.host_var).grid(row=0, column=1, sticky="ew")
        ttk.Label(tab, text="Ports").grid(row=0, column=2, sticky="w", padx=(12, 8))
        ttk.Entry(tab, width=18, textvariable=self.ports_var).grid(row=0, column=3, sticky="w")
        ttk.Button(tab, text="Probe", command=lambda: self.run_command(["probe", self.host_var.get(), self.ports_var.get()])).grid(row=0, column=4, padx=(8, 0))
        ttk.Button(tab, text="DNS", command=lambda: self.run_command(["dns", self.host_var.get()])).grid(row=0, column=5, padx=(8, 0))

    def _build_file_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=8)
        tab.columnconfigure(1, weight=1)
        notebook.add(tab, text="File")
        ttk.Label(tab, text="File").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(tab, textvariable=self.file_path_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(tab, text="Browse", command=self.choose_file).grid(row=0, column=2, padx=(8, 0))
        ttk.Button(tab, text="Hash", command=lambda: self.run_command(["hash", self.file_path_var.get()])).grid(row=0, column=3, padx=(8, 0))
        ttk.Button(tab, text="Scan", command=lambda: self.run_command(["filescan", self.file_path_var.get()])).grid(row=0, column=4, padx=(8, 0))

    def choose_scan_file(self) -> None:
        path = filedialog.askopenfilename(title="Choose traffic CSV", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if path:
            self.scan_path_var.set(self._display_path(path))

    def choose_file(self) -> None:
        path = filedialog.askopenfilename(title="Choose file")
        if path:
            self.file_path_var.set(self._display_path(path))

    def _display_path(self, path: str) -> str:
        try:
            return str(Path(path).resolve().relative_to(product_terminal.ROOT_DIR))
        except ValueError:
            return path

    def run_freeform_command(self) -> None:
        try:
            args = product_terminal.split_shell_command(self.command_var.get())
        except ValueError as exc:
            messagebox.showerror("Command parse error", str(exc))
            return
        self.run_command(args)

    def run_scan(self) -> None:
        args = ["scan", self.scan_path_var.get()]
        limit = self.scan_limit_var.get().strip()
        if limit.lower() == "all":
            args.append("--all")
        elif limit:
            args.extend(["--limit", limit])
        self.run_command(args)

    def run_command(self, args: list[str]) -> None:
        self._append(f"\n$ ids-sentinel-terminal {' '.join(args)}\n")
        thread = threading.Thread(target=self._run_command_worker, args=(args,), daemon=True)
        thread.start()

    def _run_command_worker(self, args: list[str]) -> None:
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            code = product_terminal.main(args)
        text = stream.getvalue()
        if code:
            text += f"\nCommand exited with code {code}\n"
        self.output_queue.put(text)

    def _drain_output(self) -> None:
        try:
            while True:
                self._append(self.output_queue.get_nowait())
        except queue.Empty:
            pass
        self.root.after(100, self._drain_output)

    def _append(self, text: str) -> None:
        self.output.insert("end", text)
        self.output.see("end")

    def clear_output(self) -> None:
        self.output.delete("1.0", "end")


def main(argv: list[str] | None = None) -> int:
    del argv
    root = tk.Tk()
    IDSProductGUI(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
