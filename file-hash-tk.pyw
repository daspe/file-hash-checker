import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import hashlib
import os.path

# Tkinter Root =================================================================
root = tk.Tk()
root.title("File Hash")
root.resizable(width=False, height=False)

root.columnconfigure(0, weight=1)
root.columnconfigure(0, weight=1)


# Constants ====================================================================
DEFAULT_BUFFER_SIZE = 65536 # 65536 = 64kb

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


def reset_ui(status_only=False):
    if not status_only:
        file_path_entry.delete(0, tk.END)
        sha1_entry.delete(0, tk.END)
        md5_entry.delete(0, tk.END)

    sha1_status_lbl.config(text=DEFAULT_STATUS_TEXT, foreground=NEUTRAL_COLOR)
    md5_status_lbl.config(text=DEFAULT_STATUS_TEXT, foreground=NEUTRAL_COLOR)
    status_bar_lbl.config(text=DEFAULT_STATUS_BAR_MESSAGE, foreground=NEUTRAL_COLOR)


def is_valid_input():
    file_path = file_path_entry.get()
    md5_text = md5_entry.get()
    sha1_text = sha1_entry.get()

    if not file_path:
        status_bar_lbl.config(text="File path is not present", foreground=ERROR_COLOR)
        return False
    elif not os.path.isfile(file_path):
        status_bar_lbl.config(text="File does not exist", foreground=ERROR_COLOR)
        return False
    elif not (md5_text or sha1_text):
        status_bar_lbl.config(text="No hashes to compare against file", foreground=ERROR_COLOR)
        return False
    
    return True


def compute_hashes():
    file_path = file_path_entry.get()

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    with open(file_path, 'rb') as f:
        while True:
            data = f.read(DEFAULT_BUFFER_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)

    return {"md5": str(md5.hexdigest()), "sha1": str(sha1.hexdigest())}


def compare_hashes():
    if not is_valid_input():
        return
    
    reset_ui(status_only=True)

    hashes = compute_hashes()
    matches = []

    md5_text = md5_entry.get().lower()
    if md5_text:
        if md5_text == hashes["md5"]:
            md5_status_lbl.config(text="Good!", foreground=SUCCESS_COLOR)
            matches.append("MD5")
        else:
            md5_status_lbl.config(text="Bad!", foreground=ERROR_COLOR)

    sha1_text = sha1_entry.get().lower()
    print(sha1_text)
    if sha1_text:
        if sha1_text == hashes["sha1"]:
            sha1_status_lbl.config(text="Good!", foreground=SUCCESS_COLOR)
            matches.append("SHA1")
        else:
            sha1_status_lbl.config(text="Bad!", foreground=ERROR_COLOR)

    if len(matches) > 0:
        status_bar_lbl.config(text=f"Match found for: {", ".join(matches)}", foreground=SUCCESS_COLOR)
    else:
        status_bar_lbl.config(text="No Matches Found :(", foreground=ERROR_COLOR)


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
md5_entry.grid(row=0, column=1, sticky="EW", padx=(5, 0), pady=5)

md5_entry.bind("<Return>", lambda event: compare_hashes())

md5_status_lbl = ttk.Label(
    hash_frame,
    text=DEFAULT_STATUS_TEXT,
    foreground=NEUTRAL_COLOR
)
md5_status_lbl.config()
md5_status_lbl.grid(row=0, column=2)

# SHA1 Widgets
sha1_lbl = ttk.Label(hash_frame, text="SHA1:")
sha1_lbl.grid(row=1, column=0, sticky="E")

sha1_entry = ttk.Entry(hash_frame)
sha1_entry.grid(row=1, column=1, sticky="EW", padx=(5, 0), pady=(0, 10))

sha1_entry.bind("<Return>", lambda event: compare_hashes())

sha1_status_lbl = ttk.Label(
    hash_frame,
    text=DEFAULT_STATUS_TEXT,
    foreground=NEUTRAL_COLOR
)
sha1_status_lbl.grid(row=1, column=2)


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
