import lief
import sys

def remove_elf_section(elf_path, section_name, output_path):
    """
    Removes a specified section from an ELF file using LIEF.

    Args:
        elf_path (str): Path to the input ELF file.
        section_name (str): Name of the section to remove.
        output_path (str): Path to save the modified ELF file.
    """
    try:
        # Parse the ELF file
        binary = lief.ELF.parse(elf_path)

        if not binary:
            print(f"Error: Could not parse ELF file at {elf_path}")
            return

        # Find the section to remove
        section_to_remove = None
        for section in binary.sections:
            if section.name == section_name:
                section_to_remove = section
                break

        if section_to_remove:
            # Remove the section
            binary.remove(section_to_remove)
            print(f"Section '{section_name}' removed successfully.")

            # Write the modified ELF file
            binary.write(output_path)
            print(f"Modified ELF file saved to {output_path}")
        else:
            print(f"Section '{section_name}' not found in the ELF file.")

    except lief.lief_errors.exception as e:
        print(f"LIEF error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Example usage:
# Create a dummy ELF file for testing, or use an existing one
# (e.g., compile a simple C program with debug info to have more sections)
# Example:
# gcc -g -o my_elf my_source.c

# remove_elf_section("my_elf", ".debug_info", "my_elf_stripped")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input ELF> <output ELF>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    remove_elf_section(input_file, ".debug_info", output_file)