from __future__ import annotations
from pathlib import Path
import pytest

from e3.aws.troposphere import Stack
from e3.aws.troposphere.asset import FileAsset, DirectoryAsset, AssetLayout

CONFIG_DIR = Path(__file__).parent / "example"

ASSET_URI_PREFIX = "s3://cfn_bucket/assets/"


@pytest.mark.parametrize(
    "versioning, layout, expected_s3_key",
    [
        # Without versioning
        (False, AssetLayout.TREE, "MyFileAsset/config_file.yaml"),
        # With versioning
        (
            True,
            AssetLayout.TREE,
            "MyFileAsset/config_file_e39a9030d7761c2d3a6672bfbe6de80cead90dcbeb"
            "595d6d4f84cc382c799d8b.yaml",
        ),
        # With flat layout
        (False, AssetLayout.FLAT, "config_file.yaml"),
    ],
)
def test_file_asset(
    versioning: bool,
    layout: AssetLayout,
    expected_s3_key: str,
    stack: Stack,
) -> None:
    """Test FileAsset creation.

    :param versioning: enable versioning or not
    :param layout: the asset layout
    :param expected_s3_key: expected S3 key of the asset
    :param stack: a stack instance
    """
    stack.add(
        FileAsset(
            name="MyFileAsset",
            versioning=versioning,
            layout=layout,
            file_path=str(CONFIG_DIR / "config_file.yaml"),
        )
    )
    assert stack.export()["Parameters"] == {
        "MyFileAssetS3Key": {
            "Default": expected_s3_key,
            "Description": "S3 key of asset MyFileAsset",
            "Type": "String",
        },
    }
    assert stack.export()["Outputs"] == {
        "MyFileAssetS3URIOutput": {
            "Description": "S3 URI for the Asset MyFileAsset",
            "Export": {
                "Name": "MyFileAssetS3URIOutput",
            },
            "Value": f"{ASSET_URI_PREFIX}{expected_s3_key}",
        }
    }


@pytest.mark.parametrize(
    "versioning, ignore, layout, expected_s3_key",
    [
        # Without versioning
        (False, None, AssetLayout.TREE, "MyDirectoryAsset/asset_dir"),
        # With versioning
        (
            True,
            None,
            AssetLayout.TREE,
            "MyDirectoryAsset/asset_dir_231eef51fa7ec9ea25faa21441304c9360678e1"
            "ead08314ee5c6f32f04b4fad1",
        ),
        # With versioning and ignore some elements
        (
            True,
            ["**/*_file2.yaml", "file_not_exist.txt", "to_ignore"],
            AssetLayout.TREE,
            "MyDirectoryAsset/asset_dir_2fd1c0d3b3459469dc582c985d8f22da29378e3"
            "73596f11edff36c80478c01e6",
        ),
        # With flat layout
        (False, None, AssetLayout.FLAT, "asset_dir"),
    ],
)
def test_directory_asset(
    versioning: bool,
    ignore: list[str] | None,
    layout: AssetLayout,
    expected_s3_key: str,
    stack: Stack,
) -> None:
    """Test DirectoryAsset creation.

    :param versioning: enable versioning or not
    :param ignore: glob pattern or list of files or directories to ignore
    :param layout: the asset layout
    :param expected_s3_key: expected S3 key of the asset
    :param stack: a stack instance
    """
    stack.add(
        DirectoryAsset(
            name="MyDirectoryAsset",
            versioning=versioning,
            ignore=ignore,
            layout=layout,
            data_dir=str(CONFIG_DIR / "asset_dir"),
        )
    )
    assert stack.export()["Parameters"] == {
        "MyDirectoryAssetS3Key": {
            "Default": expected_s3_key,
            "Description": "S3 key of asset MyDirectoryAsset",
            "Type": "String",
        },
    }
    assert stack.export()["Outputs"] == {
        "MyDirectoryAssetS3URIOutput": {
            "Description": "S3 URI for the Asset MyDirectoryAsset",
            "Export": {
                "Name": "MyDirectoryAssetS3URIOutput",
            },
            "Value": f"{ASSET_URI_PREFIX}{expected_s3_key}",
        }
    }
