import os

from pip._internal.download import PipSession
from pip._internal.req import parse_requirements
from setuptools import find_packages, setup

from iocparser3 import __version__

REQUIREMENTS = [
    str(requirement.req)
    for requirement in parse_requirements(
        os.path.join(os.path.dirname(__file__), "requirements.txt"),
        session=PipSession(),
    )
]

EXTRAS_REQUIRE = {
    "build": ["wheel", "twine"],
    "lint": ["flake8", "black", "mypy", "isort", "rope"],
}
EXTRAS_REQUIRE["dev"] = EXTRAS_REQUIRE["build"] + EXTRAS_REQUIRE["lint"]

URL = "https://github.com/lc4nt/ioc-parser"


def read(fname):
    """Read the content of the file `fname`."""
    with open(fname) as fp:
        content = fp.read()
    return content


setup(
    name="iocparser3",
    version=__version__,
    description="The original ioc-parser script from Armin Buescher ported to python3 and converted to package",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    author="Armin Buescher",
    author_email="@armbues",
    url=URL,
    packages=find_packages(),
    install_requires=REQUIREMENTS,
    extras_require=EXTRAS_REQUIRE,
    package_data={"iocparser3": ["res/whitelists/*.ini", "res/patterns.ini"]},
    license="MIT",
    keywords="ioc pdf parser",
    classifiers=[
        "Intended Audience :: Developers",
        "Intended Audience :: Incident Response",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.8",
    ],
    python_requires=">=3.8",
    entry_points={"console_scripts": ["iocparser=iocparser3.ioc-parser:main"]},
)