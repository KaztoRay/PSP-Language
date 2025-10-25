# PSP (PowerShellPlus) Language Support for VS Code

[![Visual Studio Marketplace Version](https://img.shields.io/visual-studio-marketplace/v/psp-team.psp-language-support.svg)](https://marketplace.visualstudio.com/items?itemName=psp-team.psp-language-support)
[![Visual Studio Marketplace Downloads](https://img.shields.io/visual-studio-marketplace/d/psp-team.psp-language-support.svg)](https://marketplace.visualstudio.com/items?itemName=psp-team.psp-language-support)

VS Code extension providing language support for PSP (PowerShellPlus) - A programming language designed for white hat hackers and cybersecurity professionals.

## Features

### Syntax Highlighting
- Full syntax highlighting for PSP language
- Support for all PSP keywords, functions, and operators
- Special highlighting for security-related functions

### Code Completion
- IntelliSense support for built-in functions
- Function signatures and documentation
- Keyword completion

### Code Snippets
- Ready-to-use code templates for common security testing scenarios
- Port scanning, vulnerability testing, payload generation snippets
- File operations, system information gathering templates

### Themes
- PSP Dark theme optimized for security work
- PSP Light theme for daytime coding
- Function category-specific color coding

### Command Integration
- Run PSP files directly from VS Code (F5)
- Start PSP interactive mode
- Execute scripts with custom interpreter settings

## Installation

### From VS Code Marketplace
1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "PSP Language Support"
4. Click Install

### Manual Installation
1. Download the latest `.vsix` file from releases
2. Open VS Code
3. Run command `Extensions: Install from VSIX...`
4. Select the downloaded file

## Configuration

Configure the extension through VS Code settings:

```json
{
  "psp.interpreterPath": "python3",
  "psp.scriptPath": "/path/to/psp_interpreter.py",
  "psp.enableLinting": true,
  "psp.debugMode": false
}
```

### Settings Description

- `psp.interpreterPath`: Path to Python interpreter (default: "python3")
- `psp.scriptPath`: Path to PSP interpreter script
- `psp.enableLinting`: Enable PSP linting (default: true)
- `psp.debugMode`: Enable debug mode for PSP execution (default: false)

## Usage

### Creating PSP Files
1. Create a new file with `.pspp` extension
2. Start coding with full syntax highlighting and IntelliSense

### Running PSP Code
- **F5**: Run current PSP file
- **Ctrl+Shift+P** → "PSP: Run PSP File"
- **Ctrl+Shift+P** → "PSP: Start PSP Interactive Mode"

### Code Snippets
Type these prefixes and press Tab:

- `hello` - Hello World template
- `portscan` - Port scanner template
- `scanrange` - Network range scanner
- `hash` - Password hashing example
- `payload` - Payload generation template
- `webtest` - Web vulnerability testing
- `sysinfo` - System information collection
- `bufferoverflow` - Buffer overflow exploit template

## Language Features

### Built-in Functions with IntelliSense

#### Network Functions
- `scan_port(host, port)` - TCP port scanning
- `scan_range(host, start_port, end_port)` - Port range scanning
- `connect(host, port)` - TCP connection testing
- `send(host, port, data)` - Data transmission
- `recv(host, port, size)` - Data reception

#### Cryptography Functions
- `md5(data)` - MD5 hashing
- `sha1(data)` - SHA1 hashing
- `sha256(data)` - SHA256 hashing
- `base64_encode(data)` - Base64 encoding
- `base64_decode(data)` - Base64 decoding

#### Exploit Functions
- `create_payload(type, target)` - Payload generation
- `buffer_overflow(size, pattern)` - Buffer overflow patterns
- `shellcode(arch)` - Shellcode generation

#### System Functions
- `enum_processes()` - Process enumeration
- `enum_services()` - Service enumeration
- `registry_read(key, value)` - Registry reading
- `registry_write(key, value, data)` - Registry writing

## Example Code

```psp
#!/usr/bin/env psp
# Network Security Scanner

target = "192.168.1.100"
ports = [21, 22, 80, 443, 3389]

print("Security scan starting...")

# Port scanning
for port in ports {
    if scan_port(target, port) {
        banner = recv(target, port, 1024)
        printf("Port %d: OPEN - %s", port, banner)
        
        # Service-specific checks
        if port == 21 {
            # FTP anonymous check
            if "220" in banner && "FTP" in banner {
                log("FTP service detected", "INFO")
            }
        }
    } else {
        printf("Port %d: CLOSED", port)
    }
}

# Generate report
report = "Scan completed for " + target
file_write("scan_report.txt", report)
log("Scan complete - report saved", "SUCCESS")
```

## Keyboard Shortcuts

- **F5** - Run PSP File
- **Ctrl+Shift+P** - Command Palette (search for PSP commands)

## Requirements

- Visual Studio Code 1.60.0 or higher
- Python 3.6+ for running PSP interpreter
- PSP interpreter (`psp_interpreter.py`)

## Known Issues

- Large file syntax highlighting may be slow
- Interactive mode requires terminal support

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This extension is licensed under the MIT License. See LICENSE file for details.

## Support

- [GitHub Issues](https://github.com/psp-team/PSP-Language/issues)
- [Documentation](https://github.com/psp-team/PSP-Language/docs)
- [Discord Community](https://discord.gg/psp-lang)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

**Enjoy secure coding with PSP! 🔐**
