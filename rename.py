from packaging.tags import sys_tags
import os
import glob
import sys
import platform

# Get system platform and architecture
platform_tag = next(sys_tags()).platform
print(f"Platform tag: {platform_tag}")

python_version = f"cp{sys.version_info.major}{sys.version_info.minor}"
print(f"Python version tag: {python_version}")

# Different handling for macOS
is_macos = platform.system() == "Darwin"
is_arm = 'arm' in platform.machine().lower()

wheel_files = glob.glob("dist/*.whl")
for wheel_file in wheel_files:
    if platform_tag not in wheel_file:
        base_dir = os.path.dirname(wheel_file)
        filename = os.path.basename(wheel_file)
        name_parts = filename.split('-')
        
        if len(name_parts) >= 2:
            # Use ABI3 tag for better compatibility on macOS
            if is_macos:
                name_parts[-3] = python_version       # Python tag (cp312)
                name_parts[-2] = "abi3"               # More compatible ABI tag
                
                # Ensure correct architecture in platform tag
                if is_arm:
                    final_platform = "macosx_11_0_arm64"
                else:
                    final_platform = "macosx_10_15_x86_64"
                
                new_filename = '-'.join(name_parts[:-1]) + f'-{final_platform}.whl'
            else:
                # Original behavior for non-macOS
                name_parts[-3] = python_version       # Python tag (cp312)
                name_parts[-2] = python_version       # ABI tag (cp312)
                new_filename = '-'.join(name_parts[:-1]) + f'-{platform_tag}.whl'
            
            new_path = os.path.join(base_dir, new_filename)
            os.rename(wheel_file, new_path)
            print(f"Renamed: {wheel_file} → {new_path}")