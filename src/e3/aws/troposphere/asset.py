from __future__ import annotations

from functools import cached_property
from hashlib import sha256
from pathlib import Path
from troposphere import Export, Output
from typing import TYPE_CHECKING

from e3.aws.troposphere import Asset, Construct

if TYPE_CHECKING:
    import botocore.client
    from collections.abc import Sequence
    from e3.aws.troposphere import Stack
    from troposphere import AWSObject


class DirectoryAsset(Asset):
    """General purpose to create directory asset."""

    def __init__(
        self,
        name: str,
        *,
        data_dir: str,
        ignore: str | Sequence[str] | None = None,
        versioning: bool = True,
    ) -> None:
        """Initialize DirectoryAsset.

        :param name: name of the asset
        :param data_dir: directory that contains the data to add to the assets
        :param ignore: glob pattern or list of files or directories to ignore
        :param versioning: if True, elements are not uploaded if no change has been
          detected
        """
        super().__init__(name)
        self.data_dir = data_dir
        self.ignore = ignore
        self.versioning = versioning

    @cached_property
    def _cached_ignored(self) -> list[Path]:
        """List of all elements in the data directory to ignore."""
        if not self.ignore:
            return []
        to_ignore = [self.ignore] if isinstance(self.ignore, str) else self.ignore
        ignored_list: list[Path] = []
        for p in to_ignore:
            for e in Path(self.data_dir).glob(p):
                ignored_list.append(e)
                if e.is_dir():
                    ignored_list.extend(sub_file for sub_file in e.iterdir())
        return ignored_list

    @cached_property
    def checksum(self) -> str:
        """Prepare the assets directory and return the checksum."""
        if not self.versioning:
            return ""

        fingerprint = sha256()
        for f in Path(self.data_dir).iterdir():
            if f in self._cached_ignored:
                continue
            fingerprint.update(f.relative_to(self.data_dir).as_posix().encode())
            if not f.is_dir():
                fingerprint.update(f.read_bytes())
        return fingerprint.hexdigest()

    @cached_property
    def asset_name(self) -> str:
        """Return the name for the asset with checksum if versioning."""
        return Path(self.data_dir).name + (f"_{self.checksum}" if self.checksum else "")

    @property
    def s3_key(self) -> str:
        """Return a unique S3 key with the checksum of the folder."""
        return f"{self.name}/{self.asset_name}"

    def upload(
        self,
        s3_bucket: str,
        s3_root_key: str,
        client: botocore.client.S3 | None = None,
        dry_run: bool | None = None,
    ) -> None:
        """Upload all objects in the assets directory to S3.

        :param s3_bucket: The S3 bucket to push the assets
        :param s3_root_key: The S3 root prefix to push the assets
        :param client: The botocore S3 client
        :param dry_run: Don't upload assets if set to True
        """
        for f in Path(self.data_dir).iterdir():
            if not f.is_dir() and f not in self._cached_ignored:
                self._upload_file(
                    s3_bucket=s3_bucket,
                    s3_key=f"{s3_root_key}{self.s3_key}/{f.relative_to(self.data_dir)}",
                    root_dir=str(self.data_dir),
                    file=str(f),
                    client=client,
                    check_exists=self.versioning,
                    dry_run=dry_run,
                )

    @property
    def s3_key_output(self) -> Output:
        """Return the output that exports the S3 key to the assets."""
        output_name = f"{self.name}S3KeyOutput"
        return Output(
            output_name,
            Description=f"S3 Key for the Directory Asset {self.name}",
            Export=Export(name=output_name),
            Value=self.s3_key,
        )

    def resources(self, stack: Stack) -> list[AWSObject | Construct]:
        """Return list of AWSObject associated with the construct."""
        # Adding the Output can be useful for Lambda function with versioning
        # The exported value can be retrieved by the lambda without the need to update
        # the lambda version.
        stack.add_output(self.s3_key_output)
        return super().resources(stack)


class FileAsset(Asset):
    """General purpose to create File asset."""

    def __init__(self, name: str, *, file_path: str, versioning: bool = True) -> None:
        """Initialize FileAsset.

        :param name: name of the asset
        :param file_path: file path to add to the asset
        :param versioning: if True, the file is not uploaded if no change has been
          detected
        """
        super().__init__(name)
        self.file_path = file_path
        self.versioning = versioning

    @cached_property
    def checksum(self) -> str:
        """Return the checksum of the file asset if versioning is true."""
        if not self.versioning:
            return ""
        fingerprint = sha256()
        fingerprint.update(Path(self.file_path).read_bytes())
        return fingerprint.hexdigest()

    @cached_property
    def asset_name(self) -> str:
        """Return the name for the asset with checksum."""
        file_name, dot, suffix = Path(self.file_path).name.partition(".")
        return file_name + (f"_{self.checksum}" if self.checksum else "") + dot + suffix

    @property
    def s3_key(self) -> str:
        """Return a unique S3 key with the checksum of the file."""
        return f"{self.name}/{self.asset_name}"

    def upload(
        self,
        s3_bucket: str,
        s3_root_key: str,
        client: botocore.client.S3 | None = None,
        dry_run: bool | None = None,
    ) -> None:
        """Upload the File asset to S3.

        :param s3_bucket: The S3 bucket to push the assets
        :param s3_root_key: The S3 root prefix to push the assets
        :param client: The botocore S3 client
        :param dry_run: Don't upload assets if set to True
        """
        self._upload_file(
            s3_bucket=s3_bucket,
            s3_key=f"{s3_root_key}{self.s3_key}",
            root_dir=str(Path(self.file_path).parent),
            file=self.file_path,
            client=client,
            check_exists=self.versioning,
            dry_run=dry_run,
        )

    @property
    def s3_key_output(self) -> Output:
        """Return the output that exports the S3 key to the assets."""
        output_name = f"{self.name}S3KeyOutput"
        return Output(
            output_name,
            Description=f"S3 Key for the File Asset {self.name}",
            Export=Export(name=output_name),
            Value=self.s3_key,
        )

    def resources(self, stack: Stack) -> list[AWSObject | Construct]:
        """Return list of AWSObject associated with the construct."""
        # Adding the Output can be useful for Lambda function with versioning
        # The exported value can be retrieved by the lambda without the need to update
        # the lambda version.
        stack.add_output(self.s3_key_output)
        return super().resources(stack)
