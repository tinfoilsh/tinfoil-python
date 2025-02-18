from packaging.tags import sys_tags
import os
import glob

platform_tag = next(sys_tags()).platform
print(f"Platform tag: {platform_tag}")

wheel_files = glob.glob("dist/*.whl")
for wheel_file in wheel_files:
    if platform_tag not in wheel_file:
        base_dir = os.path.dirname(wheel_file)
        filename = os.path.basename(wheel_file)
        name_parts = filename.split('-')

        if len(name_parts) >= 2:
            # Typical wheel format: {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl
            new_filename = '-'.join(name_parts[:-2]) + f'-{name_parts[-2]}-{platform_tag}.whl'
            new_path = os.path.join(base_dir, new_filename)

            os.rename(wheel_file, new_path)
            print(f"Renamed: {wheel_file} → {new_path}")
