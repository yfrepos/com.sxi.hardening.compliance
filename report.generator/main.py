import os
from src.parsers import parse_control_file, parse_dump_file
from src.report_generator import generate_report
from src.evaluator import evaluate_control

# Directories
INPUT_DIR = "input"
CONTROL_DIR = "control"

def main():
    try:
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
                system_info, files, modules = parse_dump_file(dump_file)
                generate_report(system_info, files, modules, controls, control_file, dump_file)

        print("Execution completed successfully. Reports have been generated in the 'output' directory.")

    except Exception as e:
        print("An error occurred during execution:")
        print(str(e))

if __name__ == "__main__":
    main()
