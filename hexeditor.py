import tkinter as tk
from tkinter import filedialog, messagebox
import re

# Number of bytes per line to display
BYTES_PER_LINE = 16

# Global variables for file data and state flags
file_bytes = bytearray()
current_file = None
updating_views = False
updating_conversion = False


def refresh_views():
    """Rebuild the hex and ASCII views from the file_bytes."""
    global updating_views
    updating_views = True
    # Enable and clear the offsets view (read-only)
    offsets_text.config(state=tk.NORMAL)
    offsets_text.delete("1.0", tk.END)
    hex_text.delete("1.0", tk.END)
    ascii_text.delete("1.0", tk.END)

    num_bytes = len(file_bytes)
    for i in range(0, num_bytes, BYTES_PER_LINE):
        line_bytes = file_bytes[i:i + BYTES_PER_LINE]
        # Build offset string (e.g. "0000")
        offset_str = f"{i:04X}\n"
        offsets_text.insert(tk.END, offset_str)
        # Build hex view string: each byte as a two-digit hex, space-separated
        hex_pairs = " ".join(f"{b:02X}" for b in line_bytes)
        hex_text.insert(tk.END, hex_pairs + "\n")
        # Build ASCII view string: printable chars or '.' for nonprintable bytes
        ascii_line = "".join(chr(b) if 32 <= b < 127 else "." for b in line_bytes)
        ascii_text.insert(tk.END, ascii_line + "\n")
    offsets_text.config(state=tk.DISABLED)
    updating_views = False


def load_file():
    """Open a file and load its bytes into memory."""
    global file_bytes, current_file
    filename = filedialog.askopenfilename()
    if filename:
        try:
            with open(filename, "rb") as f:
                file_bytes = bytearray(f.read())
            current_file = filename
            refresh_views()
        except Exception as e:
            messagebox.showerror("Error", f"Could not open file:\n{e}")


def save_file():
    """Save changes back to the current file (or trigger Save As if needed)."""
    global current_file
    if current_file:
        try:
            with open(current_file, "wb") as f:
                f.write(file_bytes)
            messagebox.showinfo("Save", "File saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save file:\n{e}")
    else:
        save_as_file()


def save_as_file():
    """Prompt for a file name and save the file."""
    global current_file
    filename = filedialog.asksaveasfilename(defaultextension=".bin")
    if filename:
        current_file = filename
        save_file()


def on_hex_edit(event):
    """
    When the user edits the hex text, try to re-parse the entire widget
    and update the underlying file_bytes. Only update if all hex pairs are valid.
    """
    global updating_views, file_bytes
    if updating_views:
        return
    content = hex_text.get("1.0", tk.END).strip()
    new_bytes = bytearray()
    valid = True
    for line in content.splitlines():
        parts = line.split()
        for part in parts:
            # Each hex token must be exactly two valid hex digits.
            if len(part) != 2 or not re.fullmatch(r"[0-9A-Fa-f]{2}", part):
                valid = False
                break
            try:
                new_bytes.append(int(part, 16))
            except Exception:
                valid = False
                break
        if not valid:
            break
    if valid:
        # Update only if the new content is different
        if new_bytes != file_bytes:
            file_bytes = new_bytes
            refresh_views()


def on_ascii_edit(event):
    """
    When the ASCII view is edited, update file_bytes based on the text.
    (Each character’s ordinal value becomes one byte.)
    """
    global updating_views, file_bytes
    if updating_views:
        return
    content = ascii_text.get("1.0", tk.END).rstrip("\n")
    new_bytes = bytearray()
    for line in content.splitlines():
        for char in line:
            new_bytes.append(ord(char))
    if new_bytes != file_bytes:
        file_bytes = new_bytes
        refresh_views()


def perform_search():
    """Search for a hex (or binary) signature in the file and highlight it."""
    # Remove any previous highlight tags
    hex_text.tag_remove("search", "1.0", tk.END)
    ascii_text.tag_remove("search", "1.0", tk.END)

    # Get the search query (remove spaces and uppercase it)
    query = search_entry.get().strip().replace(" ", "").upper()
    if not query:
        return
    use_wildcard = wildcard_var.get()  # 0 = exact, 1 = wildcard

    # Create a continuous hex string from file_bytes (without spaces)
    full_hex = "".join(f"{b:02X}" for b in file_bytes)
    match = None
    if not use_wildcard:
        idx = full_hex.find(query)
        if idx == -1:
            messagebox.showinfo("Search", "No match found.")
            return
        match = (idx, idx + len(query))
    else:
        # Convert the wildcard query: ? -> . and * -> .*
        regex_pattern = re.escape(query)
        regex_pattern = regex_pattern.replace(r"\?", ".").replace(r"\*", ".*")
        m = re.search(regex_pattern, full_hex)
        if not m:
            messagebox.showinfo("Search", "No match found.")
            return
        match = (m.start(), m.end())

    # Convert hex-digit indices to byte indices (2 hex digits per byte)
    start_byte = match[0] // 2
    end_byte = match[1] // 2
    highlight_bytes(start_byte, end_byte)


def highlight_bytes(start_byte, end_byte):
    """
    Given a start and end byte index, highlight the corresponding regions in
    both the hex view and the ASCII view.
    """
    # Compute line and column for the hex view:
    start_line = start_byte // BYTES_PER_LINE
    start_col_byte = start_byte % BYTES_PER_LINE
    end_line = (end_byte - 1) // BYTES_PER_LINE
    end_col_byte = (end_byte - 1) % BYTES_PER_LINE

    # In the hex view each byte is formatted as "XX" and then a space (3 characters per byte)
    hex_start_index = f"{start_line + 1}.{start_col_byte * 3}"
    hex_end_index = f"{end_line + 1}.{end_col_byte * 3 + 2}"
    hex_text.tag_add("search", hex_start_index, hex_end_index)
    hex_text.tag_config("search", background="yellow")

    # In the ASCII view, each line has BYTES_PER_LINE characters
    ascii_start_index = f"{start_line + 1}.{start_col_byte}"
    ascii_end_index = f"{end_line + 1}.{end_col_byte + 1}"
    ascii_text.tag_add("search", ascii_start_index, ascii_end_index)
    ascii_text.tag_config("search", background="yellow")


def parse_offset(text: str) -> int:
    """Parse decimal (e.g. 419) or 0x-prefixed hex (e.g. 0x1A3) into an int."""
    s = (text or "").strip()
    if not s:
        raise ValueError("Please enter an offset.")

    # Minimum required: decimal or 0x hex
    if s.lower().startswith("0x"):
        if len(s) == 2:
            raise ValueError("Invalid hex offset.")
        try:
            return int(s, 16)
        except Exception:
            raise ValueError("Invalid hex offset.")

    if re.fullmatch(r"\d+", s):
        try:
            return int(s, 10)
        except Exception:
            raise ValueError("Invalid decimal offset.")

    # Optional plain-hex support is not enabled by default to avoid ambiguity.
    raise ValueError("Offset must be decimal (e.g., 419) or hex with 0x prefix (e.g., 0x1A3).")


def _byte_to_indices(byte_index: int):
    """Return (hex_start, hex_end, ascii_start, ascii_end) indices for a single byte."""
    line = byte_index // BYTES_PER_LINE
    col = byte_index % BYTES_PER_LINE

    hex_start_index = f"{line + 1}.{col * 3}"
    hex_end_index = f"{line + 1}.{col * 3 + 2}"

    ascii_start_index = f"{line + 1}.{col}"
    ascii_end_index = f"{line + 1}.{col + 1}"

    return hex_start_index, hex_end_index, ascii_start_index, ascii_end_index


def go_to_offset(event=None):
    """Jump to an absolute byte offset, highlight it, and scroll it into view."""
    if not file_bytes:
        messagebox.showerror("Go to offset", "No file is loaded.")
        return

    try:
        offset = parse_offset(goto_entry.get())
    except ValueError as e:
        messagebox.showerror("Go to offset", str(e))
        return

    if offset < 0 or offset >= len(file_bytes):
        messagebox.showerror(
            "Go to offset",
            f"Offset out of range. Valid range: 0 to {len(file_bytes) - 1} (decimal).",
        )
        return

    # Clear previous goto highlight but keep search highlights intact
    hex_text.tag_remove("goto", "1.0", tk.END)
    ascii_text.tag_remove("goto", "1.0", tk.END)

    hex_start, hex_end, ascii_start, ascii_end = _byte_to_indices(offset)

    hex_text.tag_add("goto", hex_start, hex_end)
    ascii_text.tag_add("goto", ascii_start, ascii_end)

    # Ensure tag config exists
    hex_text.tag_config("goto", background="#7FDBFF")
    ascii_text.tag_config("goto", background="#7FDBFF")

    # Move cursor/focus to the target (hex view)
    hex_text.mark_set("insert", hex_start)
    hex_text.focus_set()

    # Scroll all views so the byte is visible
    offsets_text.see(f"{(offset // BYTES_PER_LINE) + 1}.0")
    hex_text.see(hex_start)
    ascii_text.see(ascii_start)

    return "break"


def on_conversion_alpha(event):
    if updating_conversion:
        return
    update_conversion(from_field="alpha")


def on_conversion_ascii(event):
    if updating_conversion:
        return
    update_conversion(from_field="ascii")


def on_conversion_hex(event):
    if updating_conversion:
        return
    update_conversion(from_field="hex")


def on_conversion_binary(event):
    if updating_conversion:
        return
    update_conversion(from_field="binary")


def update_conversion(from_field):
    """
    When one of the conversion utility fields is edited, convert its value and
    update the other fields. (Supports up to 4 characters/bytes.)
    """
    global updating_conversion
    updating_conversion = True
    try:
        if from_field == "alpha":
            val = conversion_alpha.get()[:4]
            # Convert each character to its ordinal representations.
            ascii_vals = " ".join(str(ord(c)) for c in val)
            hex_vals = " ".join(f"{ord(c):02X}" for c in val)
            binary_vals = " ".join(f"{ord(c):08b}" for c in val)
            conversion_ascii.delete(0, tk.END)
            conversion_ascii.insert(0, ascii_vals)
            conversion_hex.delete(0, tk.END)
            conversion_hex.insert(0, hex_vals)
            conversion_binary.delete(0, tk.END)
            conversion_binary.insert(0, binary_vals)
        elif from_field == "ascii":
            val = conversion_ascii.get()
            parts = val.split()[:4]
            bytes_list = []
            for p in parts:
                if not re.fullmatch(r"\d+", p):
                    raise ValueError("Invalid ASCII decimal input.")
                n = int(p, 10)
                if n < 0 or n > 255:
                    raise ValueError("ASCII values must be 0-255.")
                bytes_list.append(n)
            s = "".join(chr(b) for b in bytes_list)
            conversion_alpha.delete(0, tk.END)
            conversion_alpha.insert(0, s)
            conversion_hex.delete(0, tk.END)
            conversion_hex.insert(0, " ".join(f"{b:02X}" for b in bytes_list))
            conversion_binary.delete(0, tk.END)
            conversion_binary.insert(0, " ".join(f"{b:08b}" for b in bytes_list))
        elif from_field == "hex":
            val = conversion_hex.get().strip()
            if not val:
                bytes_list = []
            else:
                parts = val.split()[:4]
                bytes_list = []
                for p in parts:
                    if not re.fullmatch(r"[0-9A-Fa-f]{2}", p):
                        raise ValueError("HEX must be space-separated 2-digit bytes.")
                    bytes_list.append(int(p, 16))
            s = "".join(chr(b) for b in bytes_list)
            conversion_alpha.delete(0, tk.END)
            conversion_alpha.insert(0, s)
            conversion_ascii.delete(0, tk.END)
            conversion_ascii.insert(0, " ".join(str(b) for b in bytes_list))
            conversion_binary.delete(0, tk.END)
            conversion_binary.insert(0, " ".join(f"{b:08b}" for b in bytes_list))
        elif from_field == "binary":
            val = conversion_binary.get().strip()
            if not val:
                bytes_list = []
            else:
                parts = val.split()[:4]
                bytes_list = []
                for p in parts:
                    if not re.fullmatch(r"[01]{8}", p):
                        raise ValueError("Binary must be space-separated 8-bit values.")
                    bytes_list.append(int(p, 2))
            s = "".join(chr(b) for b in bytes_list)
            conversion_alpha.delete(0, tk.END)
            conversion_alpha.insert(0, s)
            conversion_ascii.delete(0, tk.END)
            conversion_ascii.insert(0, " ".join(str(b) for b in bytes_list))
            conversion_hex.delete(0, tk.END)
            conversion_hex.insert(0, " ".join(f"{b:02X}" for b in bytes_list))
    except Exception:
        # Keep the UX permissive: do not hard-error on conversion utility typing.
        # Just leave other fields unchanged when input is invalid.
        pass
    finally:
        updating_conversion = False


# ---------------------
# UI setup
# ---------------------
root = tk.Tk()
root.title("Hex Editor")

# Row 1: navigation controls
nav_frame = tk.Frame(root)
nav_frame.pack(fill=tk.X, padx=5, pady=5)

open_btn = tk.Button(nav_frame, text="Open", command=load_file)
open_btn.pack(side=tk.LEFT, padx=(0, 5))

save_btn = tk.Button(nav_frame, text="Save", command=save_file)
save_btn.pack(side=tk.LEFT, padx=(0, 5))

save_as_btn = tk.Button(nav_frame, text="Save As", command=save_as_file)
save_as_btn.pack(side=tk.LEFT, padx=(0, 10))

# Search controls
search_label = tk.Label(nav_frame, text="Search:")
search_label.pack(side=tk.LEFT)

search_entry = tk.Entry(nav_frame, width=25)
search_entry.pack(side=tk.LEFT, padx=(5, 5))

wildcard_var = tk.IntVar(value=0)
wildcard_check = tk.Checkbutton(nav_frame, text="Wildcard", variable=wildcard_var)
wildcard_check.pack(side=tk.LEFT, padx=(0, 5))

search_btn = tk.Button(nav_frame, text="Find", command=perform_search)
search_btn.pack(side=tk.LEFT, padx=(0, 15))

# Go-to-offset controls (small addition; preserve layout)
goto_label = tk.Label(nav_frame, text="Go to:")
goto_label.pack(side=tk.LEFT)

goto_entry = tk.Entry(nav_frame, width=12)
goto_entry.pack(side=tk.LEFT, padx=(5, 5))
goto_entry.bind("<Return>", go_to_offset)

goto_btn = tk.Button(nav_frame, text="Go", command=go_to_offset)
goto_btn.pack(side=tk.LEFT)

# Row 2: main editing area
edit_frame = tk.Frame(root)
edit_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

# Shared scrollbar for the three text widgets
scrollbar = tk.Scrollbar(edit_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Left: offsets (read-only)
offsets_text = tk.Text(edit_frame, width=8, wrap=tk.NONE, state=tk.DISABLED)
offsets_text.pack(side=tk.LEFT, fill=tk.Y)

# Middle: hex
a = tk.Frame(edit_frame)
a.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
hex_text = tk.Text(a, wrap=tk.NONE, undo=True)
hex_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

# Right: ascii
b = tk.Frame(edit_frame)
b.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
ascii_text = tk.Text(b, wrap=tk.NONE, undo=True)
ascii_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

# Scrollbar hookup

def _yview(*args):
    offsets_text.yview(*args)
    hex_text.yview(*args)
    ascii_text.yview(*args)


def _yscrollcommand(first, last):
    scrollbar.set(first, last)


offsets_text.configure(yscrollcommand=_yscrollcommand)
hex_text.configure(yscrollcommand=_yscrollcommand)
ascii_text.configure(yscrollcommand=_yscrollcommand)
scrollbar.configure(command=_yview)

# Bind edits
hex_text.bind("<KeyRelease>", on_hex_edit)
ascii_text.bind("<KeyRelease>", on_ascii_edit)

# Row 3: conversion utility
conv_frame = tk.Frame(root)
conv_frame.pack(fill=tk.X, padx=5, pady=5)

alpha_label = tk.Label(conv_frame, text="Alpha:")
alpha_label.grid(row=0, column=0, sticky="e")
conversion_alpha = tk.Entry(conv_frame, width=30)
conversion_alpha.grid(row=0, column=1, padx=5, pady=2, sticky="we")

ascii_label = tk.Label(conv_frame, text="ASCII:")
ascii_label.grid(row=1, column=0, sticky="e")
conversion_ascii = tk.Entry(conv_frame, width=30)
conversion_ascii.grid(row=1, column=1, padx=5, pady=2, sticky="we")

hex_label = tk.Label(conv_frame, text="HEX:")
hex_label.grid(row=2, column=0, sticky="e")
conversion_hex = tk.Entry(conv_frame, width=30)
conversion_hex.grid(row=2, column=1, padx=5, pady=2, sticky="we")

binary_label = tk.Label(conv_frame, text="Binary:")
binary_label.grid(row=3, column=0, sticky="e")
conversion_binary = tk.Entry(conv_frame, width=30)
conversion_binary.grid(row=3, column=1, padx=5, pady=2, sticky="we")

conv_frame.columnconfigure(1, weight=1)

conversion_alpha.bind("<KeyRelease>", on_conversion_alpha)
conversion_ascii.bind("<KeyRelease>", on_conversion_ascii)
conversion_hex.bind("<KeyRelease>", on_conversion_hex)
conversion_binary.bind("<KeyRelease>", on_conversion_binary)

root.mainloop()
