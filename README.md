# 🛡️ EQUALIZER v2

**Security Object Scanner** — A specialized Python tool designed to hunt for dangerous primitives, exposed secrets, and security misconfigurations across files and directories.

---

## 📖 Overview

**EQUALIZER** is a Static Application Security Testing (SAST) utility that uses YAML-based signatures to scan source code and configuration files. It identifies vulnerabilities categorized by severity (**Critical, High, Medium, Low**) across multiple environments such as Active Directory, Docker, Node.js, PHP, and Windows.

---

## 🚀 Installation

1. **Clone the repository:**
```bash
git clone https://github.com/your-user/equalizer.git
cd equalizer

```


2. **Install dependencies:**
```bash
pip install PyYAML

```


3. **Folder Structure:**
Ensure your rule templates are located in the `templates/` directory:
```text
.
├── equalizer.py
└── templates/
    ├── ad.yaml
    ├── php.yaml
    ├── node.yaml
    ├── docker.yaml
    └── windows.yaml

```



---

## 🛠️ Usage

The tool is flexible, allowing you to scan individual files, entire directories, or even raw strings.

### Core Arguments

| Flag | Description |
| --- | --- |
| `-f`, `--file` | Target a specific file for analysis. |
| `-d`, `--dir` | Recursively analyze all files within a directory. |
| `-s`, `--string` | Search for a specific term/string directly via CLI. |
| `-r`, `--rules` | **(Required)** Define rule categories (e.g., `ad`, `php`, `windows`). |

---

## 💡 Usage Examples

**1. Scan a specific PHP file for dangerous functions:**

```bash
python3 equalizer.py -f index.php -r php

```

**2. Scan an entire directory using Docker and Node.js rules:**

```bash
python3 equalizer.py -d ./my-project -r docker node

```

**3. Analyze a specific string directly:**

```bash
python3 equalizer.py -s "eval(base64_decode(...))" -r php

```

---

## 📋 Rule Format (Templates)

Rules are stored in `.yaml` files inside the `templates/` folder. Here is a sample structure:

```yaml
- id: "PHP-EVAL"
  name: "Dangerous Eval Function"
  severity: "CRITICAL"
  pattern: "eval\\s*\\("
  extensions: [".php", ".inc"]
  description: "Detects the use of eval(), which can lead to Remote Code Execution (RCE)."
  reference: "https://www.php.net/manual/en/function.eval.php"

```

---

## 📊 Scan Summary

After every execution, **EQUALIZER** generates a consolidated report including:

* Vulnerability count grouped by severity.
* Total matches found.
* File paths and reference links for remediation.

---

## ⚖️ Disclaimer

This tool was developed for educational purposes and defensive security auditing. Unauthorized use against systems without prior consent is illegal and strictly discouraged.

---

**Developed by [jwsly12]**

---

Would you like me to help you draft some initial rules for the `ad.yaml` or `windows.yaml` templates to get you started?
