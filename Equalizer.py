import os
import argparse
import re
import yaml

# Cores e Formatação
GREEN = "\033[1;32m"
RED = "\033[1;31m"
CYAN = "\033[1;36m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m" 
RESET = "\033[0m"
BOLD = "\033[1m"

# Contador Global para o Sumário
stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

def banner():
    name = "EQUALIZER"
    banner = f"""
      {CYAN}________________{RESET}
     {CYAN}|   {BOLD}{RED}{name}{RESET}{CYAN} v2 |{RESET}
     {CYAN}|________________|{RESET}{YELLOW}___,___{RESET}
     {GREEN}jwsly12        {RESET}{YELLOW}/ __.==--+"{RESET}
     {YELLOW}               /#(-'{RESET}
     {YELLOW}               `-'{RESET}
    {BOLD}[ Security Object Scanner ]{RESET}
"""
    print(banner)

def flags():
    parser = argparse.ArgumentParser(
        description="EQUALIZER: Find dangerous primitives and security misconfigurations.", 
        add_help=True
    )
    parser.add_argument("-f", "--file", metavar="FILE", help="Target file to be analyzed")
    parser.add_argument("-d", "--dir", metavar="DIR", help="Analyze all files in a directory")
    parser.add_argument("-s", "--string", metavar="TEXT", help="Search for a specific term directly")
    parser.add_argument("-r", "--rules", metavar="CATEGORY", nargs='+', help="Rule categories (ad, php, node, docker , windows)", required=True)
    return parser.parse_args()

def display_vuln(path, vuln):
    sev = vuln['severity'].upper()
    # Atualiza estatísticas
    if sev in stats:
        stats[sev] += 1
    
    if "CRITICAL" in sev:
        sev_label = f"{RED}[{sev}]{RESET}"
    elif "HIGH" in sev:
        sev_label = f"{YELLOW}[{sev}]{RESET}"
    elif "MEDIUM" in sev:
        sev_label = f"{BLUE}[{sev}]{RESET}"
    else:
        sev_label = f"[{sev}]"

    print(f"\n{RED}[!] MATCH FOUND IN: {path}{RESET}")
    print(f"    {YELLOW}>>{RESET} ID: {vuln.get('id', 'N/A')}")
    print(f"       Rule: {BOLD}{vuln['name']}{RESET} {sev_label}")
    print(f"       Description: {vuln.get('description', 'N/A')}")
    if 'reference' in vuln:
        print(f"       More info: {CYAN}{vuln['reference']}{RESET}")

def load_rules(rules_input):
    rules = []
    for category in rules_input:
        rules_path = f"templates/{category}.yaml" 
        if os.path.exists(rules_path):
            with open(rules_path, "r") as file:
                 data = yaml.safe_load(file) 
                 if data:
                     rules.extend(data)
        else:
            print(f"{YELLOW}[!] Warning: Template {rules_path} not found.{RESET}")
    return rules

def templates_run(target, rules, is_string=False):
    if is_string:
        found = False
        for r in rules:
            if re.search(r['pattern'], target, re.IGNORECASE | re.MULTILINE):
                display_vuln("Manual Input", r)
                found = True
        if not found:
            print(f"{GREEN}[+] No vulnerabilities found for the provided term.{RESET}")
        return

    files_analyse = []
    if os.path.isdir(target):
        for root, dirs, files in os.walk(target):
            for name_files in files:
                files_analyse.append(os.path.join(root, name_files))
    else:
        files_analyse.append(target)

    for path in files_analyse: 
        filename = os.path.basename(path).lower() # Normaliza nome do arquivo
        _, ext = os.path.splitext(path)
        ext = ext.lower() # Normaliza extensão
        
        try:
            with open(path, "r", errors='ignore') as f:
                 content = f.read() 
                 for r in rules:
                     allowed_exts = [e.lower() for e in r.get('extensions', [])]
                     
                     # Lógica de compatibilidade (Case Insensitive)
                     should_analyze = (not allowed_exts or 
                                      ext in allowed_exts or 
                                      filename in allowed_exts)
                     
                     if should_analyze:     
                         if re.search(r['pattern'], content, re.IGNORECASE | re.MULTILINE):
                             display_vuln(path, r)
        except Exception as e:
            print(f"{RED}[-] Error reading {path}: {e}{RESET}")

def show_summary():
    total = sum(stats.values())
    print(f"\n{CYAN}{'='*45}{RESET}")
    print(f"{BOLD}              SCAN SUMMARY{RESET}")
    print(f"{CYAN}{'='*45}{RESET}")
    print(f"  {RED}CRITICAL{RESET} : {stats['CRITICAL']}")
    print(f"  {YELLOW}HIGH{RESET}     : {stats['HIGH']}")
    print(f"  {BLUE}MEDIUM{RESET}   : {stats['MEDIUM']}")
    print(f"  LOW      : {stats['LOW']}")
    print(f"{CYAN}{'-'*45}{RESET}")
    print(f"  {BOLD}TOTAL VULNERABILITIES: {total}{RESET}")
    print(f"{CYAN}{'='*45}{RESET}")

def main():
    banner()
    args = flags()
    
    rules = load_rules(args.rules)
    print(f"{CYAN}[*]{RESET} Rules loaded: {len(rules)}")

    if args.string:
        print(f"{GREEN}[*]{RESET} Analyzing string: {BOLD}{args.string}{RESET}...")
        templates_run(args.string, rules, is_string=True)
    elif args.file or args.dir:
        target = args.file if args.file else args.dir
        print(f"{GREEN}[*]{RESET} Scanning target: {target}...")
        templates_run(target, rules)
    else:
        print(f"{RED}[-] Error: Please specify a target (-f, -d) or a string (-s).{RESET}")

    show_summary()
    print(f"\n{GREEN}[+] Scan finished.{RESET}")

if __name__ == "__main__":
    main()