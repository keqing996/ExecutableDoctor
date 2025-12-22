import os
import subprocess
import sys

def build_all_scripts():
    """
    Traverses the 'src' directory and builds all Python scripts into executables
    using PyInstaller, placing them in the 'bin' directory.
    """
    # Determine paths
    project_root = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.join(project_root, 'src')
    bin_dir = os.path.join(project_root, 'artifact')
    build_work_dir = os.path.join(project_root, 'build') # Standard build dir name

    # Validate src directory
    if not os.path.exists(src_dir):
        print(f"Error: Source directory not found at {src_dir}")
        return

    # Create bin directory if needed
    if not os.path.exists(bin_dir):
        try:
            os.makedirs(bin_dir)
            print(f"Created output directory: {bin_dir}")
        except OSError as e:
            print(f"Error creating bin directory: {e}")
            return

    # Check for PyInstaller
    try:
        subprocess.run(['pyinstaller', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("Error: PyInstaller not found. Please install it via 'pip install pyinstaller'.")
        return

    # Find Python scripts
    scripts = [f for f in os.listdir(src_dir) if f.endswith('.py')]
    
    if not scripts:
        print("No Python scripts found in src directory.")
        return

    print(f"Found {len(scripts)} script(s) to build: {', '.join(scripts)}\n")

    # Build each script
    for script in scripts:
        script_path = os.path.join(src_dir, script)
        script_name = os.path.splitext(script)[0]
        
        print(f"--- Building {script} ---")
        
        cmd = [
            'pyinstaller',
            '--onefile',                # Create a single executable file
            '--distpath', bin_dir,      # Output directory for the exe
            '--workpath', build_work_dir, # Temporary work directory
            '--specpath', build_work_dir, # Directory for .spec files
            '--clean',                  # Clean cache
            '--name', script_name,      # Name of the executable
            '--paths', src_dir,         # Add src directory to Python path for package imports
            script_path
        ]
        
        try:
            subprocess.run(cmd, check=True)
            print(f"Successfully built: {os.path.join(bin_dir, script_name + '.exe')}")
        except subprocess.CalledProcessError as e:
            print(f"Error building {script}: {e}")
        
        print("")

    print("All build tasks completed.")

if __name__ == "__main__":
    build_all_scripts()
