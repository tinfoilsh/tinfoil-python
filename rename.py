from packaging.tags import sys_tags
import os
import glob
import sys

platform_tag = next(sys_tags()).platform
print(f"Platform tag: {platform_tag}")

python_version = f"cp{sys.version_info.major}{sys.version_info.minor}"
print(f"Python version tag: {python_version}")

wheel_files = glob.glob("dist/*.whl")
for wheel_file in wheel_files:
    if platform_tag not in wheel_file:
        base_dir = os.path.dirname(wheel_file)
        filename = os.path.basename(wheel_file)
        name_parts = filename.split('-')
        if len(name_parts) >= 2:
            name_parts[-3] = python_version  # Python tag (cp312)
            name_parts[-2] = python_version  # ABI tag (cp312) - THIS IS THE KEY FIX
            
            new_filename = '-'.join(name_parts[:-1]) + f'-{platform_tag}.whl'
            new_path = os.path.join(base_dir, new_filename)
            os.rename(wheel_file, new_path)
            print(f"Renamed: {wheel_file} → {new_path}")
