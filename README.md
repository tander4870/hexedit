# Hex Editor POC

A simple hex editor implemented in Python using Tkinter. This project demonstrates a dual-pane editable hex editor with synchronized hex and ASCII views, a conversion utility for Alpha, ASCII, HEX, and Binary, and integrated search functionality supporting exact and wildcard searches.

## Features

- **File Operations:** Open, Save, and Save As functions.
- **Dual-Pane View:**  
  - **Left Pane:** Hex view with offsets for readability (editable with validation).  
  - **Right Pane:** ASCII view reflecting the file’s content.
- **Real-Time Synchronization:** Immediate updates between hex and ASCII views.
- **Conversion Utility:** Convert between Alpha, ASCII, HEX, and Binary (supports up to 4 characters/bytes).
- **Integrated Search:** Supports exact matches and wildcard pattern searches.

## Requirements

- Python 3.x
- Tkinter (usually bundled with Python)

## Usage

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/hex-editor.git

Run the application:

    python hexedit.py

Use the navigation controls to open, edit, and save files.
The conversion utility and search functionalities are available in the main window.

Directory Structure
-------------------
hexedit/
├── .gitignore
├── CHANGELOG.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── hex_editor.py
└── prompt
    ├── user_input.txt
    └── ai_output.txt
Prompts
The prompt directory contains two files:

    user_input.txt: Contains the original detailed requirements as provided by the user.
    ai_output.txt: Contains the AI-generated detailed design and requirements.

Credits
-------
This project includes code generated with the assistance of AI (ChatGPT). Full credit is given for its contributions.

License
-------
This project is licensed under the MIT License. See the LICENSE file for details.