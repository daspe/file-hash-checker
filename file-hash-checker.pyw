import tkinter as tk
from tkinter import ttk, filedialog, StringVar
import hashlib, time
import os.path

# Constants ====================================================================
# Text
DEFAULT_STATUS_TEXT = "---"
DEFAULT_STATUS_BAR_TEXT = "Dan Spencer (2024)"
DEFAULT_STATUS_BAR_TIMER_TEXT = "0.000s"

# Colors
STATUS_BAR_BG_COLOR = "#DDD"
NEUTRAL_COLOR = "#777" # Gray
SUCCESS_COLOR = "#43A047" # Green
ERROR_COLOR = "#E53935" # Red

# Other
DEFAULT_FILE_HASH_TYPE = "sha1" # "md5", "sha1", or "sha256"
HASH_TYPES = ["md5", "sha1", "sha256"]


# Functionality ================================================================
def open_file():
    file_path_entry.delete(0, tk.END)
    file = filedialog.askopenfilename()
    file_path_entry.insert(0, file)


def reset_ui(delete_entries=True, reset_file_hash_lbl=True):
    if delete_entries:
        for entry in [file_path_entry, md5_entry, sha1_entry, sha256_entry]:
            entry.delete(0, tk.END)

    if reset_file_hash_lbl:
        file_hash_lbl.config(
            text=DEFAULT_STATUS_TEXT,
            foreground=NEUTRAL_COLOR,
        )

    for status_lbl in [md5_status_lbl, sha1_status_lbl, sha256_status_lbl]:
        status_lbl.config(
            text=DEFAULT_STATUS_TEXT,
            foreground=NEUTRAL_COLOR,
            background=""
        )

    status_bar_lbl.config(
        text=DEFAULT_STATUS_BAR_TEXT,
        foreground=NEUTRAL_COLOR,
    )
    status_bar_timer_lbl.config(text=DEFAULT_STATUS_BAR_TIMER_TEXT)


def update_status_label(status_lbl, success=True):
    if success:
        status_lbl.config(
            text="Good!",
            foreground="#FFF",
            background=SUCCESS_COLOR
        )
    else:
        status_lbl.config(
            text="Bad!",
            foreground="#FFF",
            background=ERROR_COLOR
        )


def is_valid_file():
    file_path = file_path_entry.get()

    if not file_path:
        status_bar_lbl.config(
            text="File path is not present",
            foreground=ERROR_COLOR
        )
        return False
    elif not os.path.isfile(file_path):
        status_bar_lbl.config(
            text="File does not exist",
            foreground=ERROR_COLOR
        )
        return False
    
    return True


def is_valid_hash_input():
    md5_text = md5_entry.get()
    sha1_text = sha1_entry.get()
    sha256_text = sha256_entry.get()

    if not (md5_text or sha1_text or sha256_text):
        status_bar_lbl.config(
            text="No hashes to compare against file",
            foreground=ERROR_COLOR
        )
        return False
    
    return True


def compute_hash(type: str):
    file_path = file_path_entry.get()

    match type:
        case "md5":
            hash = hashlib.md5()
        case "sha1":
            hash = hashlib.sha1()
        case "sha256":
            hash = hashlib.sha256()
        case _:
            print("Internal Error: unknown hash type")
            return

    with open(file_path, 'rb') as f:
        while True:
            data = f.read()
            if not data:
                break
            hash.update(data)

    return str(hash.hexdigest())


def compare_hashes():
    reset_ui(delete_entries=False, reset_file_hash_lbl=False)

    if not is_valid_file() or not is_valid_hash_input():
        return
    
    start_time = time.time()

    matches = []

    md5_text = md5_entry.get().lower()
    if md5_text:
        md5_hash = compute_hash("md5")
        if md5_text == md5_hash:
            update_status_label(md5_status_lbl, True)
            matches.append("md5")
        else:
            update_status_label(md5_status_lbl, False)

    sha1_text = sha1_entry.get().lower()
    if sha1_text:
        sha1_hash = compute_hash("sha1")
        if sha1_text == sha1_hash:
            update_status_label(sha1_status_lbl, True)
            matches.append("sha1")
        else:
            update_status_label(sha1_status_lbl, False)

    sha256_text = sha256_entry.get().lower()
    if sha256_text:
        sha256_hash = compute_hash("sha256")
        if sha256_text == sha256_hash:
            update_status_label(sha256_status_lbl, True)
            matches.append("sha256")
        else:
            update_status_label(sha256_status_lbl, False)

    end_time = time.time()
    run_time = float(end_time - start_time)

    if len(matches) > 0:
        status_bar_lbl.config(
            text=f"Match found for: {", ".join(i.upper() for i in matches)}",
            foreground=SUCCESS_COLOR
        )
    else:
        status_bar_lbl.config(text="No matches found :(", foreground=ERROR_COLOR)

    status_bar_timer_lbl.config(text=f"{run_time:.3f}s")


def on_compute_file_hash_btn_clicked():
    if not is_valid_file():
        return
    
    hash_type = file_hash_type.get()
    file_hash = compute_hash(hash_type)
    file_hash_lbl.config(text=file_hash, foreground=NEUTRAL_COLOR)
    status_bar_lbl.config(text=f"{hash_type.upper()} hash computed!", foreground=SUCCESS_COLOR)

    update_status_label


# Context Menu Functions
def create_context_menu(event):
    context_menu = tk.Menu(root, tearoff=0)

    context_menu.add_command(label="Cut", command=lambda: on_context_menu_cut_clicked(event.widget))
    context_menu.add_command(label="Copy", command=lambda: on_context_menu_copy_clicked(event.widget))
    context_menu.add_command(label="Paste", command=lambda: on_context_menu_paste_clicked(event.widget))

    context_menu.tk_popup(event.x_root, event.y_root)


def on_context_menu_cut_clicked(widget):
    try:
        selection = widget.selection_get()
        if selection:
            root.clipboard_clear()
            root.clipboard_append(selection)
            widget.delete("sel.first", "sel.last")
    except Exception as e:
        print(repr(e))


def on_context_menu_copy_clicked(widget):
    try:
        selection = widget.selection_get()
        if selection:
            root.clipboard_clear()
            root.clipboard_append(selection)
    except Exception as e:
        print(repr(e))


def on_context_menu_paste_clicked(widget):
    try:
        clipboard = root.clipboard_get()
        if clipboard:
            widget.delete(0, tk.END)
            widget.insert(0, clipboard)
    except Exception as e:
        print(repr(e))


# Tkinter Root =================================================================
root = tk.Tk()
root.title("File Hash Checker")
root.iconbitmap("app-icon.ico")
root.resizable(width=False, height=False)

root.columnconfigure(0, weight=1)
root.columnconfigure(0, weight=1)

file_hash_type = StringVar(root)
file_hash_type.set(HASH_TYPES[1])


# File Select Frame ============================================================
file_frame = ttk.Frame(root)
file_frame.grid(row=0, column=0, sticky="NESW", padx=10, pady=10)

file_frame.columnconfigure(1, minsize=400, weight=1)

# File Select Widgets
file_path_lbl = ttk.Label(file_frame, text="File Path:")
file_path_lbl.grid(row=0, column=0, sticky="E")

file_path_entry = ttk.Entry(file_frame)
file_path_entry.grid(row=0, column=1, sticky="EW", padx=5, pady=(0, 5))

file_path_entry.bind("<Button-3>", create_context_menu)

file_open_btn = ttk.Button(file_frame, text="Select File", command=open_file)
file_open_btn.grid(row=0, column=2, pady=(0, 5))

file_hash_lbl = ttk.Label(file_frame, text=DEFAULT_STATUS_TEXT, foreground=NEUTRAL_COLOR, anchor="center")
file_hash_lbl.grid(row=1, column=0, columnspan=3, sticky="EW")

file_hash_btn = ttk.Button(file_frame, text="Compute File Hash", command=on_compute_file_hash_btn_clicked)
file_hash_btn.grid(row=2, column=0, columnspan=2, sticky="EW")

file_hash_type_list = tk.OptionMenu(file_frame, file_hash_type, *HASH_TYPES)
file_hash_type_list.grid(row=2, column=2, sticky="EW")


# Hash Frame ===================================================================
hash_frame = ttk.LabelFrame(root, text="Known Hashes")
hash_frame.grid(row=1, column=0, sticky="NESW", padx=10, pady=0)

hash_frame.columnconfigure(1, weight=1)
hash_frame.columnconfigure(2, minsize=60)

# MD5 Widgets
md5_lbl = ttk.Label(hash_frame, text="MD5:")
md5_lbl.grid(row=0, column=0, sticky="E")

md5_entry = ttk.Entry(hash_frame)
md5_entry.grid(row=0, column=1, sticky="EW", padx=5, pady=5)

md5_entry.bind("<Return>", lambda event: compare_hashes())
md5_entry.bind("<Button-3>", create_context_menu)

md5_status_lbl = ttk.Label(
    hash_frame,
    text=DEFAULT_STATUS_TEXT,
    foreground=NEUTRAL_COLOR,
    anchor="center"
)
md5_status_lbl.grid(row=0, column=2, sticky="EW", padx=(0, 5))

# SHA1 Widgets
sha1_lbl = ttk.Label(hash_frame, text="SHA1:")
sha1_lbl.grid(row=1, column=0, sticky="E")

sha1_entry = ttk.Entry(hash_frame)
sha1_entry.grid(row=1, column=1, sticky="EW", padx=5, pady=5)

sha1_entry.bind("<Return>", lambda event: compare_hashes())
sha1_entry.bind("<Button-3>", create_context_menu)

sha1_status_lbl = ttk.Label(
    hash_frame,
    text=DEFAULT_STATUS_TEXT,
    foreground=NEUTRAL_COLOR,
    anchor="center"
)
sha1_status_lbl.grid(row=1, column=2, sticky="EW", padx=(0, 5))

# SHA256 Widgets
sha256_lbl = ttk.Label(hash_frame, text="SHA256:")
sha256_lbl.grid(row=2, column=0, sticky="E")

sha256_entry = ttk.Entry(hash_frame)
sha256_entry.grid(row=2, column=1, sticky="EW", padx=5, pady=5)

sha256_entry.bind("<Return>", lambda event: compare_hashes())
sha256_entry.bind("<Button-3>", create_context_menu)

sha256_status_lbl = ttk.Label(
    hash_frame,
    text=DEFAULT_STATUS_TEXT,
    foreground=NEUTRAL_COLOR,
    anchor="center"
)
sha256_status_lbl.grid(row=2, column=2, sticky="EW", padx=(0, 5))


# Compare Frame ================================================================
compare_frame = ttk.Frame(root)
compare_frame.grid(row=2, column=0, sticky="NESW", padx=10, pady=10)

compare_frame.columnconfigure(0, weight=1)

# Compare Button
compare_btn = ttk.Button(compare_frame, text="Compare", command=compare_hashes)
compare_btn.grid(row=0, column=0, sticky="EW", padx=(0, 5))

# Reset Button
reset_btn = ttk.Button(compare_frame, text="Reset", command=reset_ui)
reset_btn.grid(row=0, column=1)

# Status Bar Frame =============================================================
ttk.Style().configure("Statusbar.TFrame", background=STATUS_BAR_BG_COLOR)
status_bar = ttk.Frame(root, style="Statusbar.TFrame")
status_bar.grid(row=3, column=0, sticky="NESW")

status_bar.columnconfigure(0, weight=3)
status_bar.columnconfigure(1, weight=1)
status_bar.rowconfigure(1, weight=1, minsize=20)

ttk.Separator(status_bar).grid(row=0, column=0, columnspan=10, sticky="EW")
status_bar_lbl = ttk.Label(
    status_bar,
    text=DEFAULT_STATUS_BAR_TEXT,
    foreground=NEUTRAL_COLOR,
    background=STATUS_BAR_BG_COLOR
)
status_bar_lbl.grid(column=0, row=1, sticky="W", padx=(5, 0))

status_bar_timer_lbl = ttk.Label(
    status_bar,
    text=DEFAULT_STATUS_BAR_TIMER_TEXT,
    foreground=NEUTRAL_COLOR,
    background=STATUS_BAR_BG_COLOR
)
status_bar_timer_lbl.grid(column=1, row=1, sticky="E", padx=5)

# Call the mainloop of Tk
root.mainloop()
