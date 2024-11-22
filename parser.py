import xml.etree.ElementTree as ET
import csv
import os
import pandas as pd

def parse_host_info(root):
    host_info = root.find('HostInfo')
    if host_info is not None:
        return {
            'TestedHost': host_info.find('TestedHost').text,
            'OS': host_info.find('OS').text,
            'Uptime': host_info.find('Uptime').text,
            'ExportDate': host_info.find('ExportDate').text,
        }
    return {}

def parse_xml_to_dict(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        host_info = parse_host_info(root)

        controls = []
        for control in root.findall('Control'):
            control_data = {
                'ControlID': control.find('ControlID').text,
                'Domain': control.find('Domain').text,
                'ControlName': control.find('ControlName').text,
                'Status': control.find('Status').text.upper()
            }
            controls.append(control_data)

        return host_info, controls
    except Exception as e:
        print(f"Error parsing XML: {e}")
        return {}, []

def lookup_recommended_config(template_csv, controls):
    try:
        template_data = pd.read_csv(template_csv, encoding='ISO-8859-1')
        template_data = template_data.set_index("Control ID")

        for control in controls:
            control_id = control['ControlID']
            if control_id in template_data.index:
                control['RecommendedConfiguration'] = template_data.loc[control_id, "Recommended Configuration"]
            else:
                control['RecommendedConfiguration'] = "N/A"

        return controls
    except Exception as e:
        print(f"Error reading template CSV: {e}")
        return controls

def calculate_summary(data):
    summary = {"PASS": 0, "FAIL": 0}
    for control in data:
        status = control['Status']
        if status == "PASS":
            summary["PASS"] += 1
        elif status == "FAIL":
            summary["FAIL"] += 1
    return summary

def generate_csv(host_info, data, output_file):
    try:
        with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)

            # Write host information
            writer.writerow(["Hostname", host_info.get('TestedHost', '')])
            writer.writerow(["OS", host_info.get('OS', '')])
            writer.writerow(["Uptime", host_info.get('Uptime', '')])
            writer.writerow(["Date of Export", host_info.get('ExportDate', '')])
            writer.writerow([])

            # Write control data
            writer.writerow(['Control ID', 'Domain', 'Control Name', 'Status', 'Recommended Configuration'])
            for row in data:
                writer.writerow([
                    row['ControlID'],
                    row['Domain'],
                    row['ControlName'],
                    row['Status'],
                    row['RecommendedConfiguration']
                ])

    except Exception as e:
        print(f"Error writing CSV {output_file}: {e}")

def generate_html(host_info, data, output_file):
    """
    Generates an HTML file from the control data, including host information, summary, and recommended configurations.
    """
    try:
        summary = calculate_summary(data)

        with open(output_file, mode='w', encoding='utf-8') as htmlfile:
            htmlfile.write("<html><head><title>Compliance Check Report</title></head><body>\n")
            htmlfile.write("<h1>Compliance Check Report</h1>\n")

            # Write host information
            htmlfile.write("<h2>Host Details</h2>\n")
            htmlfile.write("<ul>\n")
            htmlfile.write(f"<li><strong>Tested Host:</strong> {host_info.get('TestedHost', '')}</li>\n")
            htmlfile.write(f"<li><strong>OS:</strong> {host_info.get('OS', '')}</li>\n")
            htmlfile.write(f"<li><strong>Uptime:</strong> {host_info.get('Uptime', '')}</li>\n")
            htmlfile.write(f"<li><strong>Date of Export:</strong> {host_info.get('ExportDate', '')}</li>\n")
            htmlfile.write("</ul>\n")

            # Write summary
            htmlfile.write("<h2>Summary</h2>\n")
            htmlfile.write("<ul>\n")
            htmlfile.write(f"<li><strong>Total PASS:</strong> {summary['PASS']}</li>\n")
            htmlfile.write(f"<li><strong>Total FAIL:</strong> {summary['FAIL']}</li>\n")
            htmlfile.write("</ul>\n")

            # Write control data
            htmlfile.write("<h2>Control Data</h2>\n")
            htmlfile.write("<table border='1' style='border-collapse: collapse; width: 100%;'>\n")
            htmlfile.write("<tr style='background-color: #f2f2f2;'>"
                           "<th>Control ID</th><th>Domain</th><th>Control Name</th><th>Status</th><th>Recommended Configuration</th></tr>\n")

            for item in data:
                # Format status with colors, bold text, and center alignment
                status_color = "green" if item['Status'] == "PASS" else "red"
                status_html = f"<strong style='color: {status_color}; text-align: center; display: block;'>{item['Status']}</strong>"

                htmlfile.write(f"<tr>"
                               f"<td>{item['ControlID']}</td>"
                               f"<td>{item['Domain']}</td>"
                               f"<td>{item['ControlName']}</td>"
                               f"<td style='text-align: center;'>{status_html}</td>"
                               f"<td>{item['RecommendedConfiguration']}</td>"
                               f"</tr>\n")

            htmlfile.write("</table>\n</body></html>")
    except Exception as e:
        print(f"Error writing HTML {output_file}: {e}")

def process_all_xml_files(input_dir, template_csv):
    if not os.path.exists(input_dir):
        print(f"Input directory '{input_dir}' does not exist!")
        return

    # Create output directory if not exists
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)

    # Process each XML file in the input directory
    for file_name in os.listdir(input_dir):
        if file_name.endswith(".xml"):
            input_file_path = os.path.join(input_dir, file_name)
            base_name = os.path.splitext(file_name)[0]
            csv_file = os.path.join(output_dir, f"{base_name}.csv")
            html_file = os.path.join(output_dir, f"{base_name}.html")

            print(f"Processing file: {input_file_path}")

            # Parse XML and generate outputs
            host_info, control_data = parse_xml_to_dict(input_file_path)
            control_data = lookup_recommended_config(template_csv, control_data)

            if control_data:
                generate_csv(host_info, control_data, csv_file)
                generate_html(host_info, control_data, html_file)
            else:
                print(f"No valid data found in {input_file_path}")

def main():
    # Input directory for XML files
    input_dir = "input"

    # Template CSV file for control recommendations
    template_csv = "template/template.csv"

    # Process all XML files in the input directory
    process_all_xml_files(input_dir, template_csv)

if __name__ == "__main__":
    main()
