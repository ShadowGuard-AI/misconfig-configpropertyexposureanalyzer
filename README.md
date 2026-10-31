![Banner](banner.png)

# misconfig-ConfigPropertyExposureAnalyzer
Identifies configuration properties that are unintentionally exposed through APIs, logs, or other interfaces, potentially leading to sensitive information disclosure. Property (key) names are the primary signal: a key whose name matches a sensitive keyword is reported whatever its value, including a numeric value. Keyword text inside a string value is reported as a second signal and is labelled `matched_on: value` in the finding, while a key name match is labelled `matched_on: key`. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

Findings report the file, the key path, the keyword, and which side matched. Findings never contain the matched value, in the console output or in a report file. A file that cannot be read or parsed is an error, not a clean result: the run names each failed file and exits 1 while still reporting findings from the files that did load. A run with findings exits 1 and a completed clean analysis exits 0. Custom keywords given with `-k` extend the built-in default keyword list, they do not replace it.

## Install
`git clone https://github.com/ShadowGuardAI/misconfig-configpropertyexposureanalyzer`
`pip install -r requirements.txt`

## Usage
`python3 main.py config_files [-k KEYWORDS ...] [-r REDACT_PATTERNS ...] [-o OUTPUT]`

The `-o` output path may not name one of the input files. If the resolved output path is the same as a resolved input path, the tool refuses and exits 1 before writing, and the input file is left unchanged.

## Parameters
- `config_files`: Path(s) to the configuration file(s) (required positional, one or more).
- `-h, --help`: Show help message and exit
- `-k, --keywords`: Custom keywords to search for (space-separated). Custom keywords extend the built-in defaults.
- `-r, --redact_patterns`: Custom regex patterns for redacting sensitive data (space-separated).
- `-o, --output`: Output file for report (JSON format). If not provided, prints to stdout. May not be one of the input files.

## License
Copyright (c) ShadowGuardAI
