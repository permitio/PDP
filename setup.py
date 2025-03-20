import pathlib

from setuptools import find_packages, setup


def get_requirements(env="") -> list[str]:
    if env:
        env = f"-{env}"
    with pathlib.Path(f"requirements{env}.txt").open() as fp:
        return [x.strip() for x in fp.readlines() if not x.startswith("#")]


def get_data_files(root_directory: str):
    all_files: list[pathlib.Path] = [f for f in pathlib.Path(f"{root_directory}/").glob("**/*") if f.is_file()]
    file_components = [(f.parent, f) for f in all_files]
    grouped_files = {}
    for directory, fullpath in file_components:
        grouped_files.setdefault(directory, []).append(fullpath)
    data_files = []
    for directory, fullpath in iter(grouped_files.items()):
        data_files.append((directory, fullpath))
    return data_files


setup(
    name="horizon",
    version="0.2.0",
    packages=find_packages(),
    python_requires=">=3.8",
    include_package_data=True,
    data_files=get_data_files("horizon/static"),
    install_requires=get_requirements(),
    extras_require={
        "dev": get_requirements("dev"),
    },
)
