import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import hashlib
import os.path

# Constants ====================================================================
# Text
DEFAULT_STATUS_TEXT = "---"
DEFAULT_STATUS_BAR_MESSAGE = "Dan Spencer (2024)"

# Colors
STATUS_BAR_BG_COLOR = "#DDD"
NEUTRAL_COLOR = "#777" # Gray
SUCCESS_COLOR = "#43A047" # Green
ERROR_COLOR = "#E53935" # Red


# Functionality ================================================================
def open_file():
    file_path_entry.delete(0, tk.END)
    file = filedialog.askopenfilename()
    file_path_entry.insert(0, file)


def reset_ui(delete_entries=True):
    if delete_entries:
        for entry in [file_path_entry, md5_entry, sha1_entry, sha256_entry]:
            entry.delete(0, tk.END)

    for status_lbl in [md5_status_lbl, sha1_status_lbl, sha256_status_lbl]:
        status_lbl.config(
            text=DEFAULT_STATUS_TEXT,
            foreground=NEUTRAL_COLOR,
            background=""
        )

    status_bar_lbl.config(
        text=DEFAULT_STATUS_BAR_MESSAGE,
        foreground=NEUTRAL_COLOR,
    )


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


def is_valid_input():
    file_path = file_path_entry.get()
    md5_text = md5_entry.get()
    sha1_text = sha1_entry.get()
    sha256_text = sha256_entry.get()

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
    elif not (md5_text or sha1_text or sha256_text):
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
    if not is_valid_input():
        return
    
    reset_ui(delete_entries=False)

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

    if len(matches) > 0:
        status_bar_lbl.config(
            text=f"Match found for: {", ".join(i.upper() for i in matches)}",
            foreground=SUCCESS_COLOR
        )
    else:
        status_bar_lbl.config(text="No Matches Found :(", foreground=ERROR_COLOR)


# Tkinter Root =================================================================
root = tk.Tk()
root.title("File Hash Checker")
root.iconbitmap("app-icon.ico")
root.resizable(width=False, height=False)

root.columnconfigure(0, weight=1)
root.columnconfigure(0, weight=1)


# File Select Frame ============================================================
file_frame = ttk.Frame(root)
file_frame.grid(row=0, column=0, sticky="NESW", padx=10, pady=10)

file_frame.columnconfigure(1, minsize=400, weight=1)

# File Select Widgets
file_path_lbl = ttk.Label(file_frame, text="File Path:")
file_path_lbl.grid(row=0, column=0, sticky="E")

file_path_entry = ttk.Entry(file_frame)
file_path_entry.grid(row=0, column=1, sticky="EW", padx=5, pady=(0, 5))

file_open_btn = ttk.Button(file_frame, text="Select File", command=open_file)
file_open_btn.grid(row=0, column=2, pady=(0, 5))


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

status_bar.columnconfigure(1, weight=1)
status_bar.rowconfigure(1, weight=1, minsize=20)

ttk.Separator(status_bar).grid(row=0, column=0, columnspan=10, sticky="EW")
status_bar_lbl = ttk.Label(
    status_bar,
    text=DEFAULT_STATUS_BAR_MESSAGE,
    foreground=NEUTRAL_COLOR,
    background=STATUS_BAR_BG_COLOR
)
status_bar_lbl.grid(column=0, row=1, sticky="W", padx=(5, 0))

root.mainloop()
