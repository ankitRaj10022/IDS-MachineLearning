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
        self.palette = {
            "bg": "#0c1222",
            "sidebar": "#101a31",
            "panel": "#151f38",
            "panel_alt": "#1a2747",
            "text": "#e6edf9",
            "muted": "#9eaed0",
            "accent": "#2f81f7",
            "accent_hover": "#4d95ff",
            "accent_pressed": "#1e6fe3",
            "button": "#1f2d4f",
            "button_hover": "#2b3d67",
            "button_pressed": "#1a2948",
            "border": "#2d3f66",
            "output_bg": "#0d162e",
            "output_text": "#dde7fd",
            "success": "#56d39f",
            "warning": "#f2c26b",
            "danger": "#ff7b72",
        }

        self.command_var = tk.StringVar(value="status")
        self.scan_path_var = tk.StringVar(value="kddtest.csv")
        self.scan_limit_var = tk.StringVar(value="5000")
        self.hunt_var = tk.StringVar(value="dos_flood")
        self.host_var = tk.StringVar(value="127.0.0.1")
        self.ports_var = tk.StringVar(value="common")
        self.file_path_var = tk.StringVar(value="automation/product/self_learning_model.json")

        self._configure_theme()
        self._build_layout()
        self.root.after(100, self._drain_output)
        self.run_command(["status"])

    def _configure_theme(self) -> None:
        style = ttk.Style(self.root)
        with contextlib.suppress(tk.TclError):
            style.theme_use("clam")

        p = self.palette
        self.root.configure(bg=p["bg"])
        style.configure(".", background=p["bg"], foreground=p["text"], font=("Segoe UI", 10))
        style.configure("Sidebar.TFrame", background=p["sidebar"])
        style.configure("Main.TFrame", background=p["bg"])
        style.configure("Tab.TFrame", background=p["panel"])

        style.configure("SidebarTitle.TLabel", background=p["sidebar"], foreground=p["text"], font=("Segoe UI Semibold", 18))
        style.configure("SidebarSub.TLabel", background=p["sidebar"], foreground=p["muted"], font=("Segoe UI", 9))
        style.configure("Sidebar.TLabel", background=p["sidebar"], foreground=p["text"])
        style.configure("Panel.TLabel", background=p["panel"], foreground=p["text"])
        style.configure("TSeparator", background=p["border"])

        style.configure("Sidebar.TButton", padding=(12, 7), background=p["button"], foreground=p["text"], borderwidth=0, relief="flat")
        style.map(
            "Sidebar.TButton",
            background=[("pressed", p["button_pressed"]), ("active", p["button_hover"])],
            foreground=[("disabled", p["muted"])],
        )

        style.configure("Primary.TButton", padding=(12, 7), background=p["accent"], foreground=p["text"], borderwidth=0, relief="flat")
        style.map(
            "Primary.TButton",
            background=[("pressed", p["accent_pressed"]), ("active", p["accent_hover"])],
            foreground=[("disabled", p["muted"])],
        )

        style.configure("Tool.TButton", padding=(10, 6), background=p["button"], foreground=p["text"], borderwidth=0, relief="flat")
        style.map(
            "Tool.TButton",
            background=[("pressed", p["button_pressed"]), ("active", p["button_hover"])],
            foreground=[("disabled", p["muted"])],
        )

        style.configure(
            "TEntry",
            fieldbackground=p["panel_alt"],
            foreground=p["text"],
            bordercolor=p["border"],
            lightcolor=p["border"],
            darkcolor=p["border"],
            insertcolor=p["text"],
            padding=6,
        )
        style.map("TEntry", fieldbackground=[("readonly", p["panel_alt"])])

        style.configure("App.TNotebook", background=p["bg"], borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", background=p["panel"], foreground=p["muted"], padding=(14, 7), borderwidth=0)
        style.map(
            "TNotebook.Tab",
            background=[("selected", p["accent"]), ("active", p["panel_alt"])],
            foreground=[("selected", p["text"]), ("active", p["text"])],
        )

        style.configure(
            "Vertical.TScrollbar",
            background=p["panel_alt"],
            troughcolor=p["panel"],
            bordercolor=p["border"],
            arrowcolor=p["muted"],
        )
        style.configure(
            "Horizontal.TScrollbar",
            background=p["panel_alt"],
            troughcolor=p["panel"],
            bordercolor=p["border"],
            arrowcolor=p["muted"],
        )

    def _build_layout(self) -> None:
        self.root.columnconfigure(0, weight=0)
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        sidebar = ttk.Frame(self.root, padding=14, style="Sidebar.TFrame")
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.configure(width=248)

        main = ttk.Frame(self.root, padding=(0, 12, 12, 12), style="Main.TFrame")
        main.grid(row=0, column=1, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(1, weight=1)

        ttk.Label(sidebar, text="IDS Sentinel Terminal", style="SidebarTitle.TLabel").pack(anchor="w", pady=(4, 2))
        ttk.Label(sidebar, text="Traffic and Threat Intelligence", style="SidebarSub.TLabel").pack(anchor="w", pady=(0, 14))
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
            ttk.Button(sidebar, text=label, style="Sidebar.TButton", command=lambda cmd=command: self.run_command(cmd)).pack(fill="x", pady=4)

        ttk.Separator(sidebar).pack(fill="x", pady=12)
        ttk.Button(sidebar, text="Learn Model", style="Primary.TButton", command=lambda: self.run_command(["learn"])).pack(fill="x", pady=4)
        ttk.Button(sidebar, text="Clear Output", style="Sidebar.TButton", command=self.clear_output).pack(fill="x", pady=4)
        ttk.Label(sidebar, text="Theme: Dark Ops UI", style="SidebarSub.TLabel").pack(anchor="w", pady=(12, 0))

        controls = ttk.Notebook(main, style="App.TNotebook")
        controls.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        self._build_command_tab(controls)
        self._build_scan_tab(controls)
        self._build_hunt_tab(controls)
        self._build_network_tab(controls)
        self._build_file_tab(controls)

        self.output = tk.Text(
            main,
            wrap="none",
            font=("Consolas", 10),
            undo=False,
            bg=self.palette["output_bg"],
            fg=self.palette["output_text"],
            insertbackground=self.palette["text"],
            selectbackground=self.palette["accent"],
            selectforeground=self.palette["text"],
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=self.palette["border"],
            highlightcolor=self.palette["accent"],
            padx=10,
            pady=10,
        )
        self.output.grid(row=1, column=0, sticky="nsew")
        self.output.tag_configure("command", foreground=self.palette["accent"])
        self.output.tag_configure("success", foreground=self.palette["success"])
        self.output.tag_configure("warning", foreground=self.palette["warning"])
        self.output.tag_configure("danger", foreground=self.palette["danger"])

        y_scroll = ttk.Scrollbar(main, orient="vertical", command=self.output.yview, style="Vertical.TScrollbar")
        y_scroll.grid(row=1, column=1, sticky="ns")
        self.output.configure(yscrollcommand=y_scroll.set)

        x_scroll = ttk.Scrollbar(main, orient="horizontal", command=self.output.xview, style="Horizontal.TScrollbar")
        x_scroll.grid(row=2, column=0, sticky="ew")
        self.output.configure(xscrollcommand=x_scroll.set)

    def _build_command_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=10, style="Tab.TFrame")
        tab.columnconfigure(1, weight=1)
        notebook.add(tab, text="Command")
        ttk.Label(tab, text="Command", style="Panel.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(tab, textvariable=self.command_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(tab, text="Run", style="Primary.TButton", command=self.run_freeform_command).grid(row=0, column=2, padx=(8, 0))

    def _build_scan_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=10, style="Tab.TFrame")
        tab.columnconfigure(1, weight=1)
        notebook.add(tab, text="Scan")
        ttk.Label(tab, text="CSV", style="Panel.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(tab, textvariable=self.scan_path_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(tab, text="Browse", style="Tool.TButton", command=self.choose_scan_file).grid(row=0, column=2, padx=(8, 0))
        ttk.Label(tab, text="Limit", style="Panel.TLabel").grid(row=0, column=3, sticky="w", padx=(12, 8))
        ttk.Entry(tab, width=10, textvariable=self.scan_limit_var).grid(row=0, column=4, sticky="w")
        ttk.Button(tab, text="Scan", style="Primary.TButton", command=self.run_scan).grid(row=0, column=5, padx=(8, 0))

    def _build_hunt_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=10, style="Tab.TFrame")
        tab.columnconfigure(1, weight=1)
        notebook.add(tab, text="Hunt")
        ttk.Label(tab, text="Term", style="Panel.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(tab, textvariable=self.hunt_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(
            tab,
            text="Hunt",
            style="Primary.TButton",
            command=lambda: self.run_command(["hunt", self.hunt_var.get(), "--limit", "20"]),
        ).grid(row=0, column=2, padx=(8, 0))

    def _build_network_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=10, style="Tab.TFrame")
        tab.columnconfigure(1, weight=1)
        notebook.add(tab, text="Network")
        ttk.Label(tab, text="Host", style="Panel.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(tab, textvariable=self.host_var).grid(row=0, column=1, sticky="ew")
        ttk.Label(tab, text="Ports", style="Panel.TLabel").grid(row=0, column=2, sticky="w", padx=(12, 8))
        ttk.Entry(tab, width=18, textvariable=self.ports_var).grid(row=0, column=3, sticky="w")
        ttk.Button(
            tab,
            text="Probe",
            style="Primary.TButton",
            command=lambda: self.run_command(["probe", self.host_var.get(), self.ports_var.get()]),
        ).grid(row=0, column=4, padx=(8, 0))
        ttk.Button(tab, text="DNS", style="Tool.TButton", command=lambda: self.run_command(["dns", self.host_var.get()])).grid(row=0, column=5, padx=(8, 0))

    def _build_file_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=10, style="Tab.TFrame")
        tab.columnconfigure(1, weight=1)
        notebook.add(tab, text="File")
        ttk.Label(tab, text="File", style="Panel.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(tab, textvariable=self.file_path_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(tab, text="Browse", style="Tool.TButton", command=self.choose_file).grid(row=0, column=2, padx=(8, 0))
        ttk.Button(tab, text="Hash", style="Tool.TButton", command=lambda: self.run_command(["hash", self.file_path_var.get()])).grid(row=0, column=3, padx=(8, 0))
        ttk.Button(tab, text="Scan", style="Primary.TButton", command=lambda: self.run_command(["filescan", self.file_path_var.get()])).grid(row=0, column=4, padx=(8, 0))

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
        for line in text.splitlines(keepends=True):
            tag = None
            normalized = line.lower()
            if line.lstrip().startswith("$ ids-sentinel-terminal"):
                tag = "command"
            elif any(token in normalized for token in ("error", "exception", "traceback", "not recognized", "failed", "exited with code")):
                tag = "danger"
            elif any(token in normalized for token in ("critical", "high", "warning", "suspicious")):
                tag = "warning"
            elif any(token in normalized for token in ("healthy", "no threats", "completed", "success")):
                tag = "success"
            if tag:
                self.output.insert("end", line, tag)
            else:
                self.output.insert("end", line)
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
