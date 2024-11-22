import os
import xml.etree.ElementTree as ET
import base64
import csv
from pathlib import Path

# Directories
INPUT_DIR = "input"
CONTROL_DIR = "control"
OUTPUT_DIR = "output"

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def parse_dump_file(dump_file):
    tree = ET.parse(dump_file)
    root = tree.getroot()

    # Extract system info
    system_info = {
        "hostname": root.findtext("./HostInfo/CheckedHost"),
        "timestamp": root.findtext("./HostInfo/ExportDate"),
        "os": root.findtext("./HostInfo/OS"),
        "uptime": root.findtext("./HostInfo/Uptime"),
        "current_user": root.findtext("./HostInfo/CurrentUser"),
        "sudo_used": root.findtext("./HostInfo/SudoUsed"),
    }

    # Extract file information
    files = {}
    for file_element in root.findall("./Files/File"):
        file_path = file_element.findtext("Path")
        files[file_path] = {
            "permissions": file_element.findtext("Permissions"),
            "owner": file_element.findtext("Owner"),
            "md5": file_element.findtext("MD5"),
            "sha1": file_element.findtext("SHA1"),
            "content": file_element.findtext("Content"),
            "error": file_element.findtext("Error"),
        }

    return system_info, files

def parse_control_file(control_file):
    tree = ET.parse(control_file)
    root = tree.getroot()

    controls = []
    for control_element in root.findall("control"):
        controls.append({
            "id": control_element.findtext("id"),
            "domain": control_element.findtext("domain"),
            "description": control_element.findtext("description"),
            "file": control_element.findtext("file"),
            "expected_permission": control_element.findtext("expected_permission"),
            "rule": control_element.findtext("rule"),
            "mandatory": control_element.findtext("mandatory") == "true",
        })

    return controls

def decode_base64(content):
    try:
        return base64.b64decode(content).decode('utf-8')
    except Exception:
        return ""

def evaluate_control(control, file_info):
    compliance_status = "PASS"
    details = []

    # Check if the file exists in file_info
    if not file_info:
        compliance_status = "FAIL"
        details.append(f"File '{control['file']}' not found in the system dump.")
        return compliance_status, " ".join(details)

    # Check permissions
    if control.get("expected_permission"):
        if file_info.get("permissions") != control["expected_permission"]:
            compliance_status = "FAIL"
            details.append(f"Expected permissions {control['expected_permission']}, found {file_info.get('permissions')}.")

    # Check rules
    if control.get("rule"):
        content_decoded = decode_base64(file_info.get("content", ""))
        rule_key, *rule_value = control["rule"].split(maxsplit=1)

        if rule_key == "MaxSessions":
            # Check for MaxSessions in sshd_config
            expected_value = rule_value[0] if rule_value else ""
            if not any(line.startswith("MaxSessions") and line.split()[1] == expected_value for line in content_decoded.splitlines()):
                compliance_status = "FAIL"
                details.append(f"MaxSessions is not configured to {expected_value}.")
        elif rule_key == "IgnoreRhosts":
            # Check for IgnoreRhosts in sshd_config
            expected_value = rule_value[0] if rule_value else ""
            if not any(line.startswith("IgnoreRhosts") and line.split()[1] == expected_value for line in content_decoded.splitlines()):
                compliance_status = "FAIL"
                details.append(f"IgnoreRhosts is not configured to {expected_value}.")
        elif rule_key == "PermitEmptyPasswords":
            # Check for PermitEmptyPasswords in sshd_config
            expected_value = rule_value[0] if rule_value else ""
            if not any(line.startswith("PermitEmptyPasswords") and line.split()[1] == expected_value for line in content_decoded.splitlines()):
                compliance_status = "FAIL"
                details.append(f"PermitEmptyPasswords is not configured to {expected_value}.")
        elif rule_key == "HostbasedAuthentication":
            # Check for HostbasedAuthentication in sshd_config
            expected_value = rule_value[0] if rule_value else ""
            if not any(line.startswith("HostbasedAuthentication") and line.split()[1] == expected_value for line in content_decoded.splitlines()):
                compliance_status = "FAIL"
                details.append(f"HostbasedAuthentication is not configured to {expected_value}.")
        elif rule_key == "AccessConfigured":
            # Check SSH access-related configurations in sshd_config
            required_configurations = [
                "AllowUsers",
                "AllowGroups",
                "DenyUsers",
                "DenyGroups"
            ]
            missing_configs = [
                config for config in required_configurations
                if not any(line.startswith(config) for line in content_decoded.splitlines())
            ]
            if missing_configs:
                compliance_status = "FAIL"
                details.append(f"Missing SSH access configurations: {', '.join(missing_configs)}.")

    return compliance_status, " ".join(details)

def generate_report(system_info, files, controls, control_filename, dump_filename):
    base_name = f"{Path(control_filename).stem}_{Path(dump_filename).stem}"
    output_html = os.path.join(OUTPUT_DIR, f"{base_name}_report.html")
    output_csv = os.path.join(OUTPUT_DIR, f"{base_name}_report.csv")

    with open(output_html, "w") as html_file:
        html_file.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th {{ border: 1px solid #ddd; padding: 8px; text-align: center; background-color: #f4f4f4; }}
        td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        td.status {{ text-align: center; }}
        .pass {{ color: green; font-weight: bold; }}
        .fail {{ color: red; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Compliance Report</h1>
    <h2>System Information</h2>
    <ul>
        <li><strong>Timestamp:</strong> {system_info["timestamp"]}</li>
        <li><strong>Hostname:</strong> {system_info["hostname"]}</li>
        <li><strong>OS:</strong> {system_info["os"]}</li>
        <li><strong>Uptime:</strong> {system_info["uptime"]}</li>
        <li><strong>Current User:</strong> {system_info["current_user"]}</li>
        <li><strong>Sudo Used:</strong> {system_info["sudo_used"]}</li>
    </ul>
    <table>
        <tr>
            <th>Control ID</th>
            <th>Domain</th>
            <th>Description</th>
            <th>File</th>
            <th>Status</th>
            <th>Details</th>
        </tr>
""")
        # Prepare CSV file
        with open(output_csv, "w", newline="") as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(["Control ID", "Domain", "Description", "File", "Status", "Details", "Mandatory"])

            # Evaluate each control
            for control in controls:
                file_info = files.get(control["file"], {})
                compliance_status, details = evaluate_control(control, file_info)

                # Generate HTML row
                status_class = "pass" if compliance_status == "PASS" else "fail"
                html_file.write(f"""<tr>
    <td>{control["id"]}</td>
    <td>{control["domain"]}</td>
    <td>{control["description"]}</td>
    <td>{control["file"]}</td>
    <td class="status {status_class}"><b>{compliance_status}</b></td>
    <td>{details}</td>
</tr>
""")
                # Write to CSV
                csv_writer.writerow([control["id"], control["domain"], control["description"], control["file"], compliance_status, details, control["mandatory"]])

        # Close HTML file
        html_file.write("""
    </table>
</body>
</html>
""")

    print(f"Report generated: {output_html}")
    print(f"CSV generated: {output_csv}")

def main():
    control_files = [os.path.join(CONTROL_DIR, f) for f in os.listdir(CONTROL_DIR) if f.endswith(".xml")]
    dump_files = [os.path.join(INPUT_DIR, f) for f in os.listdir(INPUT_DIR) if f.endswith(".xml")]

    if not control_files:
        print(f"No control files found in {CONTROL_DIR}.")
        return

    if not dump_files:
        print(f"No dump files found in {INPUT_DIR}.")
        return

    for control_file in control_files:
        controls = parse_control_file(control_file)
        for dump_file in dump_files:
            system_info, files = parse_dump_file(dump_file)
            generate_report(system_info, files, controls, control_file, dump_file)

if __name__ == "__main__":
    main()
