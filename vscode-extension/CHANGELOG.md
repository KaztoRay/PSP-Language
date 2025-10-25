# Changelog

All notable changes to the PSP Language Support extension will be documented in this file.

## [1.0.0] - 2024-10-25

### Added
- Initial release of PSP Language Support for VS Code
- Full syntax highlighting for PSP (.pspp) files
- IntelliSense support with function signatures and documentation
- Code completion for all built-in PSP functions
- Comprehensive code snippets for security testing scenarios
- PSP Dark and Light themes with function category-specific coloring
- Command integration for running PSP files and interactive mode
- Hover documentation for built-in functions
- Language configuration with auto-closing pairs and brackets
- Support for PSP-specific syntax elements:
  - String interpolation with `${variable}`
  - Raw strings with `r"string"`
  - Multi-line strings with `"""`
  - Block comments with `/* */`
  - Line comments with `#`

### Features
- **Syntax Highlighting**
  - Keywords: function, class, if, else, for, while, etc.
  - Built-in functions categorized by type:
    - Network functions (orange highlighting)
    - Cryptography functions (cyan highlighting)
    - Exploit functions (red highlighting)
    - System functions (purple highlighting)
    - Web functions (green highlighting)
  - String literals with escape sequence support
  - Numeric literals (decimal, hex, binary, octal)
  - Comments and documentation

- **Code Completion**
  - All PSP built-in functions with parameter hints
  - Function documentation on hover
  - Keyword completion
  - Snippet-based completion with placeholders

- **Code Snippets**
  - `hello` - Hello World template
  - `portscan` - Basic port scanner
  - `scanrange` - Network range scanner
  - `hash` - Password hashing examples
  - `payload` - Payload generation template
  - `webtest` - Web vulnerability testing
  - `sysinfo` - System information collection
  - `bufferoverflow` - Buffer overflow exploit template
  - `fileops` - File operations template
  - `main` - Main function with program structure

- **Commands**
  - `PSP: Run PSP File` - Execute current PSP file
  - `PSP: Start PSP Interactive Mode` - Launch interactive PSP session

- **Themes**
  - PSP Dark - Dark theme optimized for security work
  - PSP Light - Light theme for daytime coding

- **Configuration Options**
  - `psp.interpreterPath` - Python interpreter path
  - `psp.scriptPath` - PSP interpreter script path
  - `psp.enableLinting` - Enable/disable linting
  - `psp.debugMode` - Debug mode toggle

### Technical Details
- Language ID: `psp`
- File extensions: `.pspp`
- Scope name: `source.psp`
- VS Code engine compatibility: `^1.60.0`

### Built-in Function Support
The extension provides IntelliSense for the following function categories:

#### Network Functions (45 functions)
- Port scanning and service detection
- Network connection testing
- Banner grabbing and service enumeration

#### Cryptography Functions (25 functions)
- Hash functions (MD5, SHA1, SHA256, etc.)
- Encoding/decoding (Base64, URL, etc.)
- Encryption and key management

#### Exploit Functions (30 functions)
- Payload generation for various exploit types
- Buffer overflow pattern generation
- Shellcode creation and manipulation

#### System Functions (35 functions)
- Process and service enumeration
- Registry manipulation
- System information gathering

#### File System Functions (20 functions)
- File and directory operations
- Path manipulation
- File system monitoring

#### Web Security Functions (40 functions)
- HTTP request handling
- Web vulnerability testing
- Payload generation for web attacks

### Known Limitations
- Requires external PSP interpreter for execution
- Terminal-based execution only
- No built-in debugger (planned for future release)

## [Unreleased]

### Planned Features
- Built-in PSP debugger integration
- Advanced linting and error checking
- Code formatting support
- Project template generation
- Unit testing framework integration
- Performance profiling tools
- Extended snippet library
- Auto-documentation generation
