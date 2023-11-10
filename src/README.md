# Windows api set imports resolver
# Introduction
Windows API Set Imports Resolver is a tool designed to resolve API set imports from PE (Portable Executable) files. It helps in understanding how Windows API set libraries are utilized by different modules in a PE file.

# Features
Open and map PE files

Extract import information from PE files

Resolve API set libraries to their host counterparts

Provide detailed information about each import, whether by name or ordinal
# Prerequisites
Rust Programming Language
Basic understanding of Windows API and PE file structure
# Usage
**Open a PE File**: The program opens a PE file (in this case, "Pengu.dll", you can specify path to any PE file of your choice) using the FileMap struct.
# Error Handling
The program includes basic error handling for file opening and parsing operations.

# Safety
The tool uses unsafe code to use native winapi and ntapi functions.

Proper error handling and safety checks are implemented where possible.
# Limitations
Currently designed for PE files on Windows.

Requires an understanding of the internal workings of Windows PE files and API sets.
# Future Work
Support for more PE file variations.

Enhanced error handling and safety features.

Also resolve origin of forward imports.
# License
Program is licensed under **The Don't Ask Me About It License**