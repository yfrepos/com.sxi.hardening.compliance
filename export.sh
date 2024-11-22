#!/bin/bash

# Generate dynamic XML file name using hostname and timestamp
HOSTNAME=$(hostname)
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="${HOSTNAME}_${TIMESTAMP}.xml"

# Function to get system information
gather_system_info() {
    local host_name
    local os_info
    local uptime_info
    local export_date

    host_name=$(hostname)
    os_info=$(uname -a)
    uptime_info=$(uptime)
    export_date=$(date)

    echo "  <HostInfo>" >> "$OUTPUT_FILE"
    echo "    <TestedHost>${host_name}</TestedHost>" >> "$OUTPUT_FILE"
    echo "    <OS>${os_info}</OS>" >> "$OUTPUT_FILE"
    echo "    <Uptime>${uptime_info}</Uptime>" >> "$OUTPUT_FILE"
    echo "    <ExportDate>${export_date}</ExportDate>" >> "$OUTPUT_FILE"
    echo "  </HostInfo>" >> "$OUTPUT_FILE"
}

# Initialize XML structure
initialize_xml() {
    echo '<?xml version="1.0" encoding="UTF-8"?>' > "$OUTPUT_FILE"
    echo "<ComplianceCheck>" >> "$OUTPUT_FILE"
}

# Finalize XML structure
finalize_xml() {
    echo "</ComplianceCheck>" >> "$OUTPUT_FILE"
}

# Function to add a control result to the XML
add_result_to_xml() {
    local control_id="$1"
    local domain="$2"
    local control_name="$3"
    local status="$4"

    echo "  <Control>" >> "$OUTPUT_FILE"
    echo "    <ControlID>${control_id}</ControlID>" >> "$OUTPUT_FILE"
    echo "    <Domain>${domain}</Domain>" >> "$OUTPUT_FILE"
    echo "    <ControlName>${control_name}</ControlName>" >> "$OUTPUT_FILE"
    echo "    <Status>${status}</Status>" >> "$OUTPUT_FILE"
    echo "  </Control>" >> "$OUTPUT_FILE"
}

check_cramfs_kernel_module() {
    local control_id="RHEL7-001"
    local domain="System"
    local control_name="cramfs kernel module is not available"

    if lsmod | grep -q cramfs; then
        add_result_to_xml "$control_id" "$domain" "$control_name" "Fail"
    else
        add_result_to_xml "$control_id" "$domain" "$control_name" "Pass"
    fi
}

check_freevxfs_kernel_module() {
    local control_id="RHEL7-002"
    local domain="System"
    local control_name="freevxfs kernel module is not available"

    if lsmod | grep -q freevxfs; then
        add_result_to_xml "$control_id" "$domain" "$control_name" "Fail"
    else
        add_result_to_xml "$control_id" "$domain" "$control_name" "Pass"
    fi
}

check_tmp_separate_partition() {
    local control_id="RHEL7-003"
    local domain="System"
    local control_name="/tmp is a separate partition"

    if mount | grep -q "/tmp"; then
        add_result_to_xml "$control_id" "$domain" "$control_name" "Pass"
    else
        add_result_to_xml "$control_id" "$domain" "$control_name" "Fail"
    fi
}

# Main function
main() {
    initialize_xml

    # Add system information
    gather_system_info

    # Call each control function
    check_cramfs_kernel_module
    check_freevxfs_kernel_module
    check_tmp_separate_partition

    finalize_xml

    echo "Compliance check completed. Results saved in $OUTPUT_FILE"
}

# Execute main function
main
