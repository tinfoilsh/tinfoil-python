from packaging.tags import sys_tags
import os
import glob
import sys
import platform

# Get the basic platform tag
platform_tag = next(sys_tags()).platform
print(f"Basic platform tag: {platform_tag}")

# For macOS, we need to ensure correct architecture in platform tag
if platform.system() == 'Darwin':
    # Determine architecture
    machine = platform.machine()
    if machine == 'x86_64':
        arch = 'x86_64'
    else:
        arch = 'arm64'
    
    # Create a consistent macOS platform tag
    platform_tag = f'macosx_10_9_{arch}'
    print(f"Adjusted macOS platform tag: {platform_tag}")

python_version = f"cp{sys.version_info.major}{sys.version_info.minor}"
print(f"Python version tag: {python_version}")

wheel_files = glob.glob("dist/*.whl")
for wheel_file in wheel_files:
    base_dir = os.path.dirname(wheel_file)
    filename = os.path.basename(wheel_file)
    name_parts = filename.split('-')
    
    if len(name_parts) >= 2:
        # Typical wheel format: {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl
        
        # Set the Python tag
        name_parts[-3] = python_version
        
        # For Linux wheels on GitHub Actions, ensure manylinux2014 tag
        if 'linux' in platform_tag and 'manylinux' in name_parts[-1]:
            platform_tag = 'manylinux2014_x86_64'
        
        # Create new filename with correct platform tag
        new_filename = '-'.join(name_parts[:-1]) + f'-{platform_tag}.whl'
        new_path = os.path.join(base_dir, new_filename)
        
        if new_path != wheel_file:
            os.rename(wheel_file, new_path)
            print(f"Renamed: {filename} → {os.path.basename(new_path)}")
        else:
            print(f"No rename needed for: {filename}")