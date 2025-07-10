#!/usr/bin/env python3

import argparse
import logging
import os
import json
import yaml
import re
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ConfigPropertyExposureAnalyzer:
    """
    Analyzes configuration files for potential sensitive property exposure.
    """

    def __init__(self, config_files, keywords=None, redact_patterns=None):
        """
        Initializes the analyzer.

        Args:
            config_files (list): A list of configuration file paths.
            keywords (list): A list of keywords to search for. Defaults to None (using built-in defaults).
            redact_patterns (list): A list of regex patterns for redacting sensitive data. Defaults to None (using built-in defaults).
        """
        self.config_files = config_files
        # Default keywords for sensitive information
        self.keywords = keywords if keywords else ['password', 'secret', 'api_key', 'token', 'private_key', 'credential', 'auth_token', 'db_password']
        # Default regex patterns for redacting potentially exposed information
        self.redact_patterns = redact_patterns if redact_patterns else [r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', r'\b\d{3}-\d{2}-\d{4}\b', r'\b(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b']
        self.findings = []

    def load_config_file(self, config_file):
        """
        Loads a configuration file based on its extension.

        Args:
            config_file (str): The path to the configuration file.

        Returns:
            dict: The configuration data as a dictionary.
        
        Raises:
            ValueError: If the file type is not supported.
            FileNotFoundError: If the file is not found.
            Exception: If any other error occurs during file loading.
        """
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith('.json'):
                    return json.load(f)
                elif config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    return yaml.safe_load(f)  # Use safe_load for security
                else:
                    raise ValueError(f"Unsupported file type: {config_file}")
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {config_file}")
        except json.JSONDecodeError as e:
            raise Exception(f"Error decoding JSON in {config_file}: {e}")
        except yaml.YAMLError as e:
            raise Exception(f"Error decoding YAML in {config_file}: {e}")
        except Exception as e:
            raise Exception(f"Error loading file {config_file}: {e}")

    def search_for_keywords(self, data, file_path, parent_key=None):
        """
        Recursively searches for keywords in the configuration data.

        Args:
            data (dict or list or str): The configuration data to search.
            file_path (str): The path to the configuration file.
            parent_key (str): The key of the parent element (used for nested structures).
        """
        if isinstance(data, dict):
            for key, value in data.items():
                current_key = f"{parent_key}.{key}" if parent_key else key
                self.search_for_keywords(value, file_path, current_key)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_key = f"{parent_key}[{i}]" if parent_key else f"[{i}]"
                self.search_for_keywords(item, file_path, current_key)
        elif isinstance(data, str):
            for keyword in self.keywords:
                if keyword.lower() in str(data).lower():  # Case-insensitive comparison
                    self.findings.append({
                        'file': file_path,
                        'key': parent_key,
                        'value': self.redact_sensitive_data(data),
                        'keyword': keyword
                    })

    def redact_sensitive_data(self, data):
        """
        Redacts sensitive data using regular expressions.

        Args:
            data (str): The data to redact.

        Returns:
            str: The redacted data.
        """
        redacted_data = str(data)  # Ensure it's a string
        for pattern in self.redact_patterns:
            redacted_data = re.sub(pattern, 'REDACTED', redacted_data)
        return redacted_data

    def analyze_config_files(self):
        """
        Analyzes the specified configuration files.
        """
        for config_file in self.config_files:
            try:
                logging.info(f"Analyzing file: {config_file}")
                config_data = self.load_config_file(config_file)
                self.search_for_keywords(config_data, config_file)
            except FileNotFoundError as e:
                logging.error(str(e))
            except ValueError as e:
                logging.error(str(e))
            except Exception as e:
                logging.error(f"Error analyzing {config_file}: {e}")

    def generate_report(self):
        """
        Generates a report of the findings.

        Returns:
            list: A list of findings.
        """
        return self.findings


def setup_argparse():
    """
    Sets up the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description="Analyze configuration files for potential sensitive property exposure.")
    parser.add_argument("config_files", nargs='+', help="Path(s) to the configuration file(s).")
    parser.add_argument("-k", "--keywords", nargs='+', help="Custom keywords to search for (comma-separated).", default=None)
    parser.add_argument("-r", "--redact_patterns", nargs='+', help="Custom regex patterns for redacting sensitive data (comma-separated).", default=None)
    parser.add_argument("-o", "--output", help="Output file for report (JSON format). If not provided, prints to stdout.", default=None)
    return parser


def main():
    """
    Main function to execute the configuration property exposure analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation: Check if config files exist
    for file_path in args.config_files:
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found.")
            sys.exit(1)
        
    # Process keywords and redact patterns
    keywords = args.keywords
    redact_patterns = args.redact_patterns

    analyzer = ConfigPropertyExposureAnalyzer(args.config_files, keywords, redact_patterns)
    analyzer.analyze_config_files()
    findings = analyzer.generate_report()

    if args.output:
        try:
            with open(args.output, 'w') as outfile:
                json.dump(findings, outfile, indent=4)
            logging.info(f"Report saved to {args.output}")
        except Exception as e:
            logging.error(f"Error writing to output file: {e}")
            sys.exit(1)
    else:
        if findings:
            print(json.dumps(findings, indent=4))
        else:
            print("No sensitive information found.")


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Analyze a single JSON config file:
#    python misconfig-ConfigPropertyExposureAnalyzer.py config.json

# 2. Analyze multiple config files (JSON and YAML):
#    python misconfig-ConfigPropertyExposureAnalyzer.py config.json config.yaml

# 3. Analyze with custom keywords:
#    python misconfig-ConfigPropertyExposureAnalyzer.py config.json -k password api_secret

# 4. Analyze with custom redact patterns:
#    python misconfig-ConfigPropertyExposureAnalyzer.py config.json -r "\d{4}-\d{2}-\d{2}"

# 5. Output report to a file:
#    python misconfig-ConfigPropertyExposureAnalyzer.py config.json -o report.json

# 6. Analyze multiple config files with custom keywords and redact patterns output report to file
#    python misconfig-ConfigPropertyExposureAnalyzer.py config1.json config2.yaml -k secret token -r "regex1" "regex2" -o report.json