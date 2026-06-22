# uBlock-AST: uBlock Origin Rules AST Parser & Dataset

`uBlock-AST` is a modular rule parser and dataset generator for uBlock Origin (`uAssets`) filter lists. It transforms raw network blocking rules, cosmetic element hiding scripts, and scriptlet injections into an Abstract Syntax Tree (AST)-like structured JSON format. 

This repository also hosts a complete, pre-generated dataset containing **40,000+ unique parsed rules** for direct use in machine learning, threat analysis, or ruleset research.

---

## 🚀 Features

- **AST Parsing:** Automatically splits and categorizes filters into domain lists, CSS selectors, scriptlet names, parameters, tracking keys, and redirect targets.
- **Deep Categorization:** Organizes rules into 5 main categories:
  - Network Blocking
  - Cosmetic Hiding
  - Scriptlet Injection
  - Parameter Clean
  - Redirect / Mock Resource
- **Massive Dataset:** Contains over 40,000 unique rules parsed from official uAssets files.
- **AI/ML Ready:** Every rule has a human-readable English explanation and a machine-readable JSON AST representation, perfect for LLM fine-tuning and natural language rule interpretation models.

---

## 📊 Dataset Structure Example

Each parsed entry is formatted in markdown with a JSON metadata block:

### Raw Rule:
`www.google.*##+js(trusted-click-element, button#W0wltc, , 500)`

### AST JSON Representation:
```json
{
  "category": "Scriptlet Injection",
  "raw_rule": "www.google.*##+js(trusted-click-element, button#W0wltc, , 500)",
  "is_exception": false,
  "details": {
    "domains": [
      "www.google.*"
    ],
    "scriptlet_name": "trusted-click-element",
    "scriptlet_args": [
      "button#W0wltc",
      "",
      "500"
    ]
  }
}
```

---

## 🛠️ Usage

### 1. Generating the Dataset
To clone the latest `uBlockOrigin/uAssets` repository and compile the dataset from scratch:

```bash
python generate_dataset.py
```
This will download the filters and output the complete parsed dataset to `datasets/ublock_filter_rules_dataset.md`.

### 2. Standalone Parser Module
You can import the parser module directly in your Python code:

```python
from parser import parse_rule, generate_explanation

rule = "||amazon-adsystem.com/aax2/amzn_ads.js$script,redirect=noopjs"
parsed = parse_rule(rule)
explanation = generate_explanation(parsed)

print(parsed)
# Output: {'raw_rule': '||amazon-adsystem.com/aax2/amzn_ads.js$script,redirect=noopjs', ...}
print(explanation)
# Output: "This rule blocks script requests to amazon-adsystem.com... and redirects them to a safe, local mock resource noopjs."
```

---

## 📄 License
This project is licensed under the GPL-3.0 License.
