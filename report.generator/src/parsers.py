import xml.etree.ElementTree as ET

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
            "path": file_path,
            "permissions": file_element.findtext("Permissions"),
            "owner": file_element.findtext("Owner"),
            "md5": file_element.findtext("MD5"),
            "sha1": file_element.findtext("SHA1"),
            "content": file_element.findtext("Content"),
            "error": file_element.findtext("Error"),
        }

    # Extract module information
    modules = {}
    for module_element in root.findall("./Modules/Module"):
        module_name = module_element.findtext("Name")
        module_status = module_element.findtext("Status")
        modules[module_name] = module_status

    return system_info, files, modules

def parse_control_file(control_file):
    tree = ET.parse(control_file)
    root = tree.getroot()

    controls = []
    for control_element in root.findall("control"):
        control = {
            "id": control_element.findtext("id"),
            "domain": control_element.findtext("domain"),
            "description": control_element.findtext("description"),
            "profile": control_element.findtext("profile"),
        }

        file_element = control_element.find("file")
        if file_element is not None:
            control["file"] = file_element.text
            control["expected_permission"] = control_element.findtext("expected_permission")
            control["expected_owner"] = control_element.findtext("expected_owner")
            control["rule"] = control_element.findtext("rule")

        module_element = control_element.find("module")
        if module_element is not None:
            control["module"] = {
                "name": module_element.findtext("name"),
                "status": module_element.findtext("status"),
            }

        controls.append(control)

    return controls
