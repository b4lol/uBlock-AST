import re

def parse_rule(line):
    """
    Parses a uBlock Origin filter rule line and extracts domains, modifiers, and targets.
    Categorizes the rule into one of five categories:
    - Scriptlet Injection
    - Cosmetic Hiding
    - Parameter Clean
    - Redirect / Mock Resource
    - Network Blocking
    """
    line = line.strip()
    if not line or line.startswith('!') or line.startswith('#'):
        return None

    is_exception = line.startswith('@@')
    clean_line = line[2:] if is_exception else line

    category = "Unknown"
    details = {}

    if "##+js(" in clean_line:
        category = "Scriptlet Injection"
        parts = clean_line.split("##+js(")
        domains = parts[0].split(",") if parts[0] else ["Global"]
        scriptlet_content = parts[1][:-1]
        scriptlet_parts = [p.strip() for p in scriptlet_content.split(",")]
        scriptlet_name = scriptlet_parts[0]
        scriptlet_args = scriptlet_parts[1:]
        details = {
            "domains": domains,
            "scriptlet_name": scriptlet_name,
            "scriptlet_args": scriptlet_args
        }
    elif "##" in clean_line:
        category = "Cosmetic Hiding"
        parts = clean_line.split("##")
        domains = parts[0].split(",") if parts[0] else ["Global"]
        selector = parts[1]
        
        is_style = ":style(" in selector
        style_declaration = ""
        if is_style:
            style_match = re.search(r':style\((.*?)\)', selector)
            if style_match:
                style_declaration = style_match.group(1)
                selector = selector.split(":style")[0]

        details = {
            "domains": domains,
            "selector": selector,
            "is_style": is_style,
            "style_declaration": style_declaration
        }
    elif "removeparam" in clean_line:
        category = "Parameter Clean"
        parts = clean_line.split("$")
        pattern = parts[0]
        modifiers = parts[1].split(",") if len(parts) > 1 else []
        param_val = ""
        for m in modifiers:
            if m.startswith("removeparam="):
                param_val = m.split("=")[1]
            elif m == "removeparam":
                param_val = "All"
        details = {
            "pattern": pattern,
            "parameter": param_val,
            "modifiers": modifiers
        }
    elif "redirect=" in clean_line:
        category = "Redirect / Mock Resource"
        parts = clean_line.split("$")
        pattern = parts[0]
        modifiers = parts[1].split(",") if len(parts) > 1 else []
        redirect_val = ""
        domains = ["Global"]
        for m in modifiers:
            if m.startswith("redirect="):
                redirect_val = m.split("=")[1]
            elif m.startswith("domain="):
                domains = m.split("=")[1].split("|")
        details = {
            "pattern": pattern,
            "redirect_target": redirect_val,
            "domains": domains,
            "modifiers": modifiers
        }
    else:
        parts = clean_line.split("$")
        pattern = parts[0]
        modifiers = parts[1].split(",") if len(parts) > 1 else []
        domains = ["Global"]
        types = []
        for m in modifiers:
            if m.startswith("domain="):
                domains = m.split("=")[1].split("|")
            elif m in ["script", "image", "xhr", "fetch", "stylesheet", "font", "websocket", "media", "ping", "document", "popup"]:
                types.append(m)
        
        category = "Network Blocking"
        details = {
            "pattern": pattern,
            "domains": domains,
            "types": types,
            "modifiers": modifiers
        }

    return {
        "raw_rule": line,
        "is_exception": is_exception,
        "category": category,
        "details": details
    }

def generate_explanation(parsed):
    """
    Generates a human-readable English explanation for a parsed rule.
    """
    cat = parsed["category"]
    det = parsed["details"]
    exc_prefix = "Exception Rule: " if parsed["is_exception"] else ""
    
    if cat == "Scriptlet Injection":
        domains_str = ", ".join(det["domains"])
        args_str = ", ".join([f"'{a}'" for a in det["scriptlet_args"]]) if det["scriptlet_args"] else "none"
        return f"{exc_prefix}This rule executes the scriptlet `{det['scriptlet_name']}` with arguments `{args_str}` on domains `{domains_str}`. Used to spoof Javascript APIs or auto-bypass consent overlays."
    elif cat == "Cosmetic Hiding":
        domains_str = ", ".join(det["domains"])
        if det["is_style"]:
            return f"{exc_prefix}This rule overrides the style of elements matching `{det['selector']}` on domains `{domains_str}` to `{det['style_declaration']}`. Used to bypass scroll-blocking consent overlays."
        else:
            return f"{exc_prefix}This rule hides elements matching CSS selector `{det['selector']}` on domains `{domains_str}` by injecting display: none !important. Cleans ad layouts and banner spaces."
    elif cat == "Parameter Clean":
        pat = det["pattern"] if det["pattern"] else "All URLs"
        return f"{exc_prefix}This rule removes the tracking/session parameter `{det['parameter']}` from URL queries matching `{pat}`. Prevents cross-site tracking."
    elif cat == "Redirect / Mock Resource":
        domains_str = ", ".join(det["domains"])
        return f"{exc_prefix}This rule blocks external requests matching `{det['pattern']}` on domains `{domains_str}` and redirects them to a safe, local mock resource `{det['redirect_target']}` to avoid script errors."
    elif cat == "Network Blocking":
        domains_str = ", ".join(det["domains"])
        types_str = ", ".join(det["types"]) if det["types"] else "any type"
        action_verb = "permits (whitelists)" if parsed["is_exception"] else "blocks"
        return f"{exc_prefix}This rule {action_verb} `{types_str}` requests to `{det['pattern']}` on domains `{domains_str}`. Used to block ad/tracking servers or restore broken services."
    return "Unknown filter rule."
