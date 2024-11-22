#!/bin/bash

HOSTNAME=$(hostname)
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="${HOSTNAME}_${TIMESTAMP}.xml"

# List of files to dump
FILES_TO_DUMP=(
    "/etc/passwd"
    "/etc/group"
    "/etc/ssh/sshd_config"
    "/etc/fstab"
    "/etc/motd"
    "/etc/crontab"
)

gather_system_info() {
    local host_name os_info uptime_info export_date current_user sudo_used

    host_name=$(hostname)
    os_info=$(uname -a)
    uptime_info=$(uptime)
    export_date=$(date)
    current_user=$(whoami)

    if [ -n "$SUDO_USER" ]; then
        sudo_used="Yes"
    else
        sudo_used="No"
    fi

    echo "  <HostInfo>" >> "$OUTPUT_FILE"
    echo "    <CheckedHost>${host_name}</CheckedHost>" >> "$OUTPUT_FILE"
    echo "    <OS>${os_info}</OS>" >> "$OUTPUT_FILE"
    echo "    <Uptime>${uptime_info}</Uptime>" >> "$OUTPUT_FILE"
    echo "    <ExportDate>${export_date}</ExportDate>" >> "$OUTPUT_FILE"
    echo "    <CurrentUser>${current_user}</CurrentUser>" >> "$OUTPUT_FILE"
    echo "    <SudoUsed>${sudo_used}</SudoUsed>" >> "$OUTPUT_FILE"
    echo "  </HostInfo>" >> "$OUTPUT_FILE"
}

# Dump file information into the XML
dump_file_info() {
    local file="$1"
    local error_flag=""

    echo "    <File>" >> "$OUTPUT_FILE"
    echo "      <Path>${file}</Path>" >> "$OUTPUT_FILE"

    if [ -f "$file" ]; then
        local permissions owner md5_hash sha1_hash base64_content
        permissions=$(stat -c "%a" "$file" 2>/dev/null) || error_flag="Permission denied"
        owner=$(stat -c "%U:%G" "$file" 2>/dev/null) || error_flag="Permission denied"
        md5_hash=$(md5sum "$file" 2>/dev/null | awk '{print $1}') || error_flag="Permission denied"
        sha1_hash=$(sha1sum "$file" 2>/dev/null | awk '{print $1}') || error_flag="Permission denied"
        base64_content=$(base64 "$file" 2>/dev/null) || error_flag="Permission denied"

        if [ -n "$error_flag" ]; then
            echo "      <Error>${error_flag}</Error>" >> "$OUTPUT_FILE"
        else
            echo "      <Permissions>${permissions}</Permissions>" >> "$OUTPUT_FILE"
            echo "      <Owner>${owner}</Owner>" >> "$OUTPUT_FILE"
            echo "      <MD5>${md5_hash}</MD5>" >> "$OUTPUT_FILE"
            echo "      <SHA1>${sha1_hash}</SHA1>" >> "$OUTPUT_FILE"
            echo "      <Content encoding=\"base64\">" >> "$OUTPUT_FILE"
            echo "${base64_content}" >> "$OUTPUT_FILE"
            echo "      </Content>" >> "$OUTPUT_FILE"
        fi
    else
        echo "      <Error>File not found</Error>" >> "$OUTPUT_FILE"
    fi

    echo "    </File>" >> "$OUTPUT_FILE"
}

initialize_xml() {
    echo '<?xml version="1.0" encoding="UTF-8"?>' > "$OUTPUT_FILE"
    echo "<ComplianceCheck>" >> "$OUTPUT_FILE"
}

finalize_xml() {
    echo "</ComplianceCheck>" >> "$OUTPUT_FILE"
}

main() {
    initialize_xml
    gather_system_info

    echo "  <Files>" >> "$OUTPUT_FILE"
    for file in "${FILES_TO_DUMP[@]}"; do
        dump_file_info "$file"
    done
    echo "  </Files>" >> "$OUTPUT_FILE"

    finalize_xml

    echo "File information dumped into $OUTPUT_FILE"
}

main