from src.utils import decode_base64

def evaluate_control(control, file_info=None, module_info=None):
    compliance_status = "PASS"
    details = []

    # Check kernel module status
    if "module" in control:
        module_name = control["module"]["name"]
        expected_status = control["module"]["status"]
        actual_status = module_info.get(module_name, "Not Found")
        if actual_status != expected_status:
            compliance_status = "FAIL"
            details.append(f"Kernel module '{module_name}' status is '{actual_status}', expected '{expected_status}'.")

    # Check file-based controls
    if "file" in control:
        if file_info is None:
            # File not found in the system dump
            compliance_status = "FAIL"
            details.append(f"File '{control['file']}' not found in the system dump.")
        else:
            content_decoded = decode_base64(file_info.get("content", ""))
            is_directory = file_info.get("type", "file") == "directory"
            
            # Validate permissions
            if "expected_permission" in control and control["expected_permission"]:
                if file_info.get("permissions") != control["expected_permission"]:
                    compliance_status = "FAIL"
                    details.append(
                        f"Expected permissions {control['expected_permission']} for {'directory' if is_directory else 'file'}, found {file_info.get('permissions')}."
                    )

            # Validate owner
            if "expected_owner" in control and control["expected_owner"]:
                actual_owner = file_info.get("owner", "")
                expected_owner = control["expected_owner"]
                if actual_owner != expected_owner:
                    compliance_status = "FAIL"
                    details.append(
                        f"Expected owner {expected_owner}, found {actual_owner}."
                    )

            if "rule" in control and control["rule"]:
                rule_key, *rule_value = control["rule"].split(maxsplit=1)

                if rule_key == "NoSpecialReferences":
                    prohibited_strings = [r"\m", r"\r", r"\s", r"\v"]
                    os_references = ["Linux", "Ubuntu", "CentOS", "Debian", "Red Hat", "Fedora"]
                    found_prohibited = [string for string in prohibited_strings if string in content_decoded]
                    found_os_references = [ref for ref in os_references if ref in content_decoded]

                    if not content_decoded.strip():
                        compliance_status = "FAIL"
                        details.append(f"File '{control['file']}' is empty or not configured properly.")
                    if found_prohibited:
                        compliance_status = "FAIL"
                        details.append(f"Prohibited sequences found in '{control['file']}': {', '.join(found_prohibited)}.")
                    if found_os_references:
                        compliance_status = "FAIL"
                        details.append(f"OS platform references found in '{control['file']}': {', '.join(found_os_references)}.")

                elif rule_key == "MaxSessions":
                    expected_value = rule_value[0] if rule_value else ""
                    if not any(line.startswith("MaxSessions") and line.split()[1] == expected_value for line in content_decoded.splitlines()):
                        compliance_status = "FAIL"
                        details.append(f"MaxSessions is not configured to {expected_value}.")

                elif rule_key == "AccessConfigured":
                    required_access = ["AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups"]
                    missing_configs = [config for config in required_access if not any(line.startswith(config) for line in content_decoded.splitlines())]
                    if missing_configs:
                        compliance_status = "FAIL"
                        details.append(f"Missing SSH access configurations: {', '.join(missing_configs)}.")

                elif rule_key == "IgnoreRhosts":
                    expected_value = rule_value[0] if rule_value else ""
                    if not any(line.startswith("IgnoreRhosts") and line.split()[1] == expected_value for line in content_decoded.splitlines()):
                        compliance_status = "FAIL"
                        details.append(f"IgnoreRhosts is not configured to {expected_value}.")

                elif rule_key == "PermitEmptyPasswords":
                    expected_value = rule_value[0] if rule_value else ""
                    if not any(line.startswith("PermitEmptyPasswords") and line.split()[1] == expected_value for line in content_decoded.splitlines()):
                        compliance_status = "FAIL"
                        details.append(f"PermitEmptyPasswords is not configured to {expected_value}.")

                elif rule_key == "NoexecOption":
                    partition = rule_value[0] if rule_value else ""
                    if not any(
                        len(fields := line.split()) > 3 and fields[1] == partition and "noexec" in fields[3].split(",")
                        for line in content_decoded.splitlines()
                        if not line.startswith("#") and line.strip()
                    ):
                        compliance_status = "FAIL"
                        details.append(f"The 'noexec' option is not set for the {partition} partition in '{control['file']}'.")

                elif rule_key == "NosuidOption":
                    partition = rule_value[0] if rule_value else ""
                    if not any(
                        len(fields := line.split()) > 3 and fields[1] == partition and "nosuid" in fields[3].split(",")
                        for line in content_decoded.splitlines()
                        if not line.startswith("#") and line.strip()
                    ):
                        compliance_status = "FAIL"
                        details.append(f"The 'nosuid' option is not set for the {partition} partition in '{control['file']}'.")

                elif rule_key == "NodevOption":
                    partition = rule_value[0] if rule_value else ""
                    if not any(
                        len(fields := line.split()) > 3 and fields[1] == partition and "nodev" in fields[3].split(",")
                        for line in content_decoded.splitlines()
                        if not line.startswith("#") and line.strip()
                    ):
                        compliance_status = "FAIL"
                        details.append(f"The 'nodev' option is not set for the {partition} partition in '{control['file']}'.")

                elif rule_key == "SeparatePartition":
                    partition = rule_value[0] if rule_value else ""
                    if not any(
                        len(fields := line.split()) > 1 and fields[1] == partition
                        for line in content_decoded.splitlines()
                        if not line.startswith("#") and line.strip()
                    ):
                        compliance_status = "FAIL"
                        details.append(f"The {partition} partition is not configured as a separate partition in '{control['file']}'.")

                elif rule_key == "CronAllowCheck":
                    if file_info.get("error") == "File not found":
                        compliance_status = "FAIL"
                        details.append("The /etc/cron.allow file does not exist. Only superuser is allowed to use cron.")
                    elif not content_decoded.strip():
                        compliance_status = "FAIL"
                        details.append("The /etc/cron.allow file exists but is empty. It must list authorized users.")
                    elif not all(line.isalnum() for line in content_decoded.splitlines()):
                        compliance_status = "FAIL"
                        details.append("The /etc/cron.allow file contains invalid entries. Each line must contain a single username.")

                elif rule_key == "CronDenyCheck":
                    if not content_decoded.strip():
                        details.append("The /etc/cron.deny file is empty, allowing all users.")
                    else:
                        invalid_entries = [
                            line for line in content_decoded.splitlines() if not line.isalnum()
                        ]
                        if invalid_entries:
                            compliance_status = "FAIL"
                            details.append(
                                f"The /etc/cron.deny file contains invalid entries: {', '.join(invalid_entries)}."
                            )

                elif rule_key == "AtAllowCheck":
                    if file_info.get("error") == "File not found":
                        compliance_status = "FAIL"
                        details.append("The /etc/at.allow file does not exist. Only superuser is allowed to use at.")
                    elif not content_decoded.strip():
                        compliance_status = "FAIL"
                        details.append("The /etc/at.allow file exists but is empty. It must list authorized users.")
                    elif not all(line.isalnum() for line in content_decoded.splitlines()):
                        compliance_status = "FAIL"
                        details.append("The /etc/at.allow file contains invalid entries. Each line must contain a single username.")

                elif rule_key == "AtDenyCheck":
                    if not content_decoded.strip():
                        details.append("The /etc/at.deny file is empty, allowing all users.")
                    else:
                        invalid_entries = [
                            line for line in content_decoded.splitlines() if not line.isalnum()
                        ]
                        if invalid_entries:
                            compliance_status = "FAIL"
                            details.append(
                                f"The /etc/at.deny file contains invalid entries: {', '.join(invalid_entries)}."
                            )

    return compliance_status, " ".join(details)
