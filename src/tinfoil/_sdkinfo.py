from importlib.metadata import PackageNotFoundError, version

SDK_NAME = "tinfoil-python"
PACKAGE_NAME = "tinfoil"
UNKNOWN_VERSION = "unknown"


def sdk_version() -> str:
    try:
        return version(PACKAGE_NAME)
    except PackageNotFoundError:
        return UNKNOWN_VERSION


def attestation_headers() -> dict[str, str]:
    return {
        "Tinfoil-SDK": SDK_NAME,
        "Tinfoil-SDK-Version": sdk_version(),
    }
