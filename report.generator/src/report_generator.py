import os
import csv
from pathlib import Path
from src.evaluator import evaluate_control

# Configurable variables for report generation
REPORT_TITLE = "Compliance Report"
HTML_STYLE = """
    body { font-family: Arial, sans-serif; margin: 20px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; font-family: Arial, sans-serif; }
    th { text-align: center; background-color: #f4f4f4; }
    td.status { text-align: center; font-weight: bold; }
    td.profile { text-align: center; font-weight: bold; }
    td.path { text-align: left; font-family: Arial, sans-serif; }
    .pass { color: green; }
    .fail { color: red; }
"""
TABLE_HEADERS = ["Control ID", "Domain", "Profile", "Description", "Status", "Path/Module", "Details"]

def create_html_header(html_file, system_info):
    html_file.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{REPORT_TITLE}</title>
    <style>{HTML_STYLE}</style>
</head>
<body>
    <h1>{REPORT_TITLE}</h1>
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
""")
    # Write table headers
    for header in TABLE_HEADERS:
        html_file.write(f"<th>{header}</th>")
    html_file.write("</tr>\n")

def create_html_row(html_file, control, compliance_status, path_or_module, details):
    status_class = "pass" if compliance_status == "PASS" else "fail"
    html_file.write(f"""<tr>
    <td>{control["id"]}</td>
    <td>{control["domain"]}</td>
    <td class="profile">{control["profile"]}</td>
    <td>{control["description"]}</td>
    <td class="status {status_class}">{compliance_status}</td>
    <td class="path">{path_or_module}</td>
    <td>{details}</td>
</tr>
""")

def create_html_footer(html_file):
    html_file.write("""
    </table>
</body>
</html>
""")

def create_csv_row(csv_writer, control, compliance_status, path_or_module, details):
    csv_writer.writerow(
        [
            control["id"],
            control["domain"],
            control["profile"],
            control["description"],
            compliance_status,
            path_or_module,
            details,
        ]
    )

def generate_report(system_info, files, modules, controls, control_filename, dump_filename):
    base_name = f"{Path(control_filename).stem}_{Path(dump_filename).stem}"
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)

    output_html = os.path.join(output_dir, f"{base_name}_report.html")
    output_csv = os.path.join(output_dir, f"{base_name}_report.csv")

    with open(output_html, "w") as html_file:
        with open(output_csv, "w", newline="") as csv_file:
            # Create CSV writer
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(TABLE_HEADERS)

            # Write HTML header
            create_html_header(html_file, system_info)

            # Process each control
            for control in controls:
                # Get file or module information
                file_info = files.get(control.get("file")) if "file" in control else None
                module_name = control["module"]["name"] if "module" in control else None

                # Evaluate the control
                compliance_status, details = evaluate_control(control, file_info, modules if module_name else None)

                # Determine path/module for the report
                path_or_module = control.get("file") if file_info else module_name or "N/A"

                # Write rows to HTML and CSV
                create_html_row(html_file, control, compliance_status, path_or_module, details)
                create_csv_row(csv_writer, control, compliance_status, path_or_module, details)

            # Write HTML footer
            create_html_footer(html_file)

    # print(f"HTML report generated: {output_html}")
    # print(f"CSV report generated: {output_csv}")
