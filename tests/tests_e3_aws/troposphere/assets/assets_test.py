from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from e3.aws.troposphere import Stack
from e3.aws.troposphere.asset import FileAsset, DirectoryAsset

CONFIG_DIR = Path(__file__).parent / "example"

EXPECTED_FILE_ASSET_OUTPUT = {
    "MyFileAssetS3KeyOutput": {
        "Description": "S3 Key for the File Asset MyFileAsset",
        "Export": {
            "Name": "MyFileAssetS3KeyOutput",
        },
        "Value": "MyFileAsset/config_file.yaml",
    }
}

EXPECTED_FILE_ASSET_PARAMETER = {
    "MyFileAssetS3Key": {
        "Default": "MyFileAsset/config_file.yaml",
        "Description": "S3 key of asset MyFileAsset",
        "Type": "String",
    },
}

EXPECTED_FILE_ASSET_VERSIONED = (
    "MyFileAsset/"
    "config_file_e39a9030d7761c2d3a6672bfbe6de80cead90dcbeb595d6d4f84cc382c799d8b.yaml"
)

EXPECTED_DIRECTORY_ASSET_OUTPUT = {
    "MyDirectoryAssetS3KeyOutput": {
        "Description": "S3 Key for the Directory Asset MyDirectoryAsset",
        "Export": {
            "Name": "MyDirectoryAssetS3KeyOutput",
        },
        "Value": "MyDirectoryAsset/asset_dir",
    }
}

EXPECTED_DIRECTORY_ASSET_PARAMETER = {
    "MyDirectoryAssetS3Key": {
        "Default": "MyDirectoryAsset/asset_dir",
        "Description": "S3 key of asset MyDirectoryAsset",
        "Type": "String",
    },
}

EXPECTED_DIRECTORY_ASSET_VERSIONED = (
    "MyDirectoryAsset/"
    "asset_dir_231eef51fa7ec9ea25faa21441304c9360678e1ead08314ee5c6f32f04b4fad1"
)

EXPECTED_DIRECTORY_ASSET_IGNORED = (
    "MyDirectoryAsset/"
    "asset_dir_2fd1c0d3b3459469dc582c985d8f22da29378e373596f11edff36c80478c01e6"
)


def test_file_asset(stack: Stack) -> None:
    """Test FileAsset creation."""
    stack.add(
        FileAsset(
            name="MyFileAsset",
            versioning=False,
            file_path=str(CONFIG_DIR / "config_file.yaml"),
        )
    )
    assert stack.export()["Outputs"] == EXPECTED_FILE_ASSET_OUTPUT
    assert stack.export()["Parameters"] == EXPECTED_FILE_ASSET_PARAMETER


def test_file_asset_with_versioning(stack: Stack) -> None:
    """Test FileAsset creation with versioning."""
    stack.add(
        FileAsset(
            name="MyFileAsset",
            versioning=True,
            file_path=str(CONFIG_DIR / "config_file.yaml"),
        )
    )

    expected_asset_output = dict(EXPECTED_FILE_ASSET_OUTPUT)
    expected_asset_output["MyFileAssetS3KeyOutput"][
        "Value"
    ] = EXPECTED_FILE_ASSET_VERSIONED

    expected_asset_parameter = dict(EXPECTED_FILE_ASSET_PARAMETER)
    expected_asset_parameter["MyFileAssetS3Key"][
        "Default"
    ] = EXPECTED_FILE_ASSET_VERSIONED

    assert stack.export()["Outputs"] == expected_asset_output
    assert stack.export()["Parameters"] == expected_asset_parameter


def test_directory_asset(stack: Stack) -> None:
    """Test DirectoryAsset creation."""
    stack.add(
        DirectoryAsset(
            name="MyDirectoryAsset",
            versioning=False,
            data_dir=str(CONFIG_DIR / "asset_dir"),
        )
    )
    assert stack.export()["Outputs"] == EXPECTED_DIRECTORY_ASSET_OUTPUT
    assert stack.export()["Parameters"] == EXPECTED_DIRECTORY_ASSET_PARAMETER


def test_directory_asset_with_versioning(stack: Stack) -> None:
    """Test DirectoryAsset creation with versioning."""
    stack.add(
        DirectoryAsset(
            name="MyDirectoryAsset",
            versioning=True,
            data_dir=str(CONFIG_DIR / "asset_dir"),
        )
    )

    expected_asset_output = deepcopy(EXPECTED_DIRECTORY_ASSET_OUTPUT)
    expected_asset_output["MyDirectoryAssetS3KeyOutput"][
        "Value"
    ] = EXPECTED_DIRECTORY_ASSET_VERSIONED

    expected_asset_parameter = deepcopy(EXPECTED_DIRECTORY_ASSET_PARAMETER)
    expected_asset_parameter["MyDirectoryAssetS3Key"][
        "Default"
    ] = EXPECTED_DIRECTORY_ASSET_VERSIONED

    assert stack.export()["Outputs"] == expected_asset_output
    assert stack.export()["Parameters"] == expected_asset_parameter


def test_directory_asset_with_ignore(stack: Stack) -> None:
    """Test DirectoryAsset creation and ignore some elements."""
    stack.add(
        DirectoryAsset(
            name="MyDirectoryAsset",
            versioning=True,
            data_dir=str(CONFIG_DIR / "asset_dir"),
            ignore=["**/*_file2.yaml", "file_not_exist.txt", "to_ignore"],
        )
    )

    expected_asset_output = deepcopy(EXPECTED_DIRECTORY_ASSET_OUTPUT)
    expected_asset_output["MyDirectoryAssetS3KeyOutput"][
        "Value"
    ] = EXPECTED_DIRECTORY_ASSET_IGNORED

    expected_asset_parameter = deepcopy(EXPECTED_DIRECTORY_ASSET_PARAMETER)
    expected_asset_parameter["MyDirectoryAssetS3Key"][
        "Default"
    ] = EXPECTED_DIRECTORY_ASSET_IGNORED

    assert stack.export()["Outputs"] == expected_asset_output
    assert stack.export()["Parameters"] == expected_asset_parameter
