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
        line_bytes = file_bytes[i:i+BYTES_PER_LINE]
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
    hex_start_index = f"{start_line+1}.{start_col_byte * 3}"
    hex_end_index = f"{end_line+1}.{end_col_byte * 3 + 2}"
    hex_text.tag_add("search", hex_start_index, hex_end_index)
    hex_text.tag_config("search", background="yellow")
    
    # In the ASCII view, each line has BYTES_PER_LINE characters
    ascii_start_index = f"{start_line+1}.{start_col_byte}"
    ascii_end_index = f"{end_line+1}.{end_col_byte+1}"
    ascii_text.tag_add("search", ascii_start_index, ascii_end_index)
    ascii_text.tag_config("search", background="yellow")

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
            # Expect space-separated decimal numbers.
            parts = val.split()
            try:
                chars = [chr(int(x)) for x in parts][:4]
            except Exception:
                chars = []
            alpha_val = "".join(chars)
            hex_vals = " ".join(f"{ord(c):02X}" for c in alpha_val)
            binary_vals = " ".join(f"{ord(c):08b}" for c in alpha_val)
            conversion_alpha.delete(0, tk.END)
            conversion_alpha.insert(0, alpha_val)
            conversion_hex.delete(0, tk.END)
            conversion_hex.insert(0, hex_vals)
            conversion_binary.delete(0, tk.END)
            conversion_binary.insert(0, binary_vals)
        elif from_field == "hex":
            val = conversion_hex.get().replace(" ", "")[:8]  # up to 4 bytes (8 hex digits)
            if len(val) % 2 != 0:
                # Incomplete hex pair; do nothing
                pass
            else:
                try:
                    bytes_vals = [val[i:i+2] for i in range(0, len(val), 2)]
                    chars = [chr(int(x, 16)) for x in bytes_vals]
                except Exception:
                    chars = []
                alpha_val = "".join(chars)
                ascii_vals = " ".join(str(ord(c)) for c in alpha_val)
                binary_vals = " ".join(f"{ord(c):08b}" for c in alpha_val)
                conversion_alpha.delete(0, tk.END)
                conversion_alpha.insert(0, alpha_val)
                conversion_ascii.delete(0, tk.END)
                conversion_ascii.insert(0, ascii_vals)
                conversion_binary.delete(0, tk.END)
                conversion_binary.insert(0, binary_vals)
        elif from_field == "binary":
            val = conversion_binary.get().replace(" ", "")[:32]  # up to 4 bytes (4*8 bits)
            if len(val) % 8 != 0:
                pass
            else:
                try:
                    bytes_vals = [val[i:i+8] for i in range(0, len(val), 8)]
                    chars = [chr(int(x, 2)) for x in bytes_vals]
                except Exception:
                    chars = []
                alpha_val = "".join(chars)
                ascii_vals = " ".join(str(ord(c)) for c in alpha_val)
                hex_vals = " ".join(f"{ord(c):02X}" for c in alpha_val)
                conversion_alpha.delete(0, tk.END)
                conversion_alpha.insert(0, alpha_val)
                conversion_ascii.delete(0, tk.END)
                conversion_ascii.insert(0, ascii_vals)
                conversion_hex.delete(0, tk.END)
                conversion_hex.insert(0, hex_vals)
    finally:
        updating_conversion = False

# ---------------------- Build the GUI ----------------------

root = tk.Tk()
root.title("Hex Editor POC")

# -- Top Navigation Frame --
nav_frame = tk.Frame(root)
nav_frame.pack(fill=tk.X, padx=5, pady=5)

tk.Button(nav_frame, text="Open", command=load_file).pack(side=tk.LEFT, padx=2)
tk.Button(nav_frame, text="Save", command=save_file).pack(side=tk.LEFT, padx=2)
tk.Button(nav_frame, text="Save As", command=save_as_file).pack(side=tk.LEFT, padx=2)

tk.Label(nav_frame, text="Search:").pack(side=tk.LEFT, padx=(10,2))
search_entry = tk.Entry(nav_frame, width=20)
search_entry.pack(side=tk.LEFT, padx=2)

wildcard_var = tk.IntVar()
tk.Checkbutton(nav_frame, text="Wildcard", variable=wildcard_var).pack(side=tk.LEFT, padx=2)
tk.Button(nav_frame, text="Search", command=perform_search).pack(side=tk.LEFT, padx=2)

# -- Main Editing Area --
main_frame = tk.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

# Left side: Hex view (with offset and hex digits)
hex_frame = tk.Frame(main_frame)
hex_frame.pack(side=tk.LEFT, fill=tk.Y)

# Offsets widget (read-only)
offsets_text = tk.Text(hex_frame, width=6, height=20, bg="lightgrey")
offsets_text.pack(side=tk.LEFT, fill=tk.Y)
offsets_text.config(state=tk.DISABLED)

# Hex digits widget (editable)
hex_text = tk.Text(hex_frame, width=53, height=20)
hex_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
hex_text.bind("<KeyRelease>", on_hex_edit)

# Right side: ASCII view (editable)
ascii_text = tk.Text(main_frame, width=20, height=20)
ascii_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
ascii_text.bind("<KeyRelease>", on_ascii_edit)

# A single vertical scrollbar shared by all three text widgets
scrollbar = tk.Scrollbar(main_frame, orient=tk.VERTICAL)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

def yview(*args):
    hex_text.yview(*args)
    ascii_text.yview(*args)
    offsets_text.yview(*args)

hex_text.config(yscrollcommand=scrollbar.set)
ascii_text.config(yscrollcommand=scrollbar.set)
offsets_text.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=yview)

# -- Conversion Utility Frame (Bottom) --
conv_frame = tk.Frame(root)
conv_frame.pack(fill=tk.X, padx=5, pady=5)

tk.Label(conv_frame, text="Alpha:").grid(row=0, column=0, padx=2)
conversion_alpha = tk.Entry(conv_frame, width=20)
conversion_alpha.grid(row=0, column=1, padx=2)
conversion_alpha.bind("<KeyRelease>", on_conversion_alpha)

tk.Label(conv_frame, text="ASCII:").grid(row=0, column=2, padx=2)
conversion_ascii = tk.Entry(conv_frame, width=20)
conversion_ascii.grid(row=0, column=3, padx=2)
conversion_ascii.bind("<KeyRelease>", on_conversion_ascii)

tk.Label(conv_frame, text="HEX:").grid(row=0, column=4, padx=2)
conversion_hex = tk.Entry(conv_frame, width=20)
conversion_hex.grid(row=0, column=5, padx=2)
conversion_hex.bind("<KeyRelease>", on_conversion_hex)

tk.Label(conv_frame, text="Binary:").grid(row=0, column=6, padx=2)
conversion_binary = tk.Entry(conv_frame, width=20)
conversion_binary.grid(row=0, column=7, padx=2)
conversion_binary.bind("<KeyRelease>", on_conversion_binary)

# Start the application
root.mainloop()
