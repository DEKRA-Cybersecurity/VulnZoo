"""
CareOtter Version Information
"""

__title__ = "CareOtter"
__description__ = "IoT Cardiac Monitor - Educational Security Training Platform"
__version__ = "1.0.0-baseline"
__author__ = "VulnZoo Lab"
__author_email__ = "lab@vulnzoo.local"
__license__ = "Educational Use Only"
__copyright__ = "Copyright 2024 VulnZoo Team"
__release_date__ = "2024-01-15"
__status__ = "Stable"

# Version components
VERSION_MAJOR = 1
VERSION_MINOR = 0
VERSION_PATCH = 0
VERSION_PRERELEASE = "baseline"

def version_string():
    """Get full version string"""
    version = f"{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH}"
    if VERSION_PRERELEASE:
        version += f"-{VERSION_PRERELEASE}"
    return version

def version_info():
    """Get detailed version information"""
    return {
        'version': version_string(),
        'title': __title__,
        'description': __description__,
        'author': __author__,
        'status': __status__,
        'release_date': __release_date__
    }

# For package info
VERSION = version_string()

if __name__ == '__main__':
    print(f"{__title__} {version_string()}")
    print(f"Status: {__status__}")
    print(f"Release: {__release_date__}")
