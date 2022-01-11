from __future__ import annotations

from typing import TYPE_CHECKING

import json
import mimetypes
import tempfile
from contextlib import closing


from e3.event import EventHandler, unique_id
from e3.fs import rm
import e3.log
from e3.aws import Session

if TYPE_CHECKING:
    from typing import Optional, Any
    from e3.event import Event

logger = e3.log.getLogger("S3Handler")


class S3Handler(EventHandler):
    """Event handler that relies on AWS S3."""

    def __init__(
        self,
        event_bucket: str,
        log_bucket: str,
        sse: str = "AES256",
        profile: Optional[str] = None,
    ) -> None:
        """Initialize handler.

        :param event_bucket: event bucket name
        :param log_bucket: log bucket name
        :param sse: encryption method
        :param profile: profile to use for S3 operations
        """
        self.event_bucket = event_bucket
        self.log_bucket = log_bucket
        self.aws_profile = profile
        self.sse = sse

    @classmethod
    def decode_config(cls, config_str: str) -> dict[str, Optional[str]]:
        event_bucket, log_bucket, sse, aws_profile = config_str.split(",", 3)
        return {
            "event_bucket": event_bucket,
            "log_bucket": log_bucket,
            "sse": sse,
            "profile": aws_profile if aws_profile else None,
        }

    def encode_config(self) -> str:
        return "{},{},{},{}".format(
            self.event_bucket,
            self.log_bucket,
            self.sse,
            self.aws_profile if self.aws_profile is not None else "",
        )

    def s3_prefix(self, event: Event) -> str:
        """Additional prefix that depends on the event itself.

        This hook allows a user to add a prefix that depends on the event itself.
        Note that sufixes are still automatically computed so distinct events can
        return the same prefix. The final s3 url used will be
        {log_s3_url}/{s3_prefix}{automatic suffix} for logs and
        {event_s3_url}/{s3_prefix}{automatic suffix} for events metadata.

        :param event: an event
        :return: the prefix
        """
        return ""

    def send_event(self, event: Event) -> bool:
        def s3_cp(
            from_path: str,
            s3_key: str,
            bucket: str,
        ) -> Optional[str]:
            """copy file to S3 bucket.

            :param from_path: File to copy
            :param s3_key: destination in bucket
            :param bucket: name of the bucket
            """
            s_options: dict[str, Any] = {"regions": ["eu-west-1"]}
            if self.aws_profile and self.aws_profile.startswith("arn:aws:iam"):
                # If profile is a role, assume the given role.
                # This is necessary for AWS Lambda as there is no profile file.
                session = Session(**s_options).assume_role(
                    self.aws_profile, "S3Session"
                )
            elif self.aws_profile:
                s_options.update({"profile": self.aws_profile})
                session = Session(**s_options)
            else:
                session = Session(**s_options)

            client = session.to_boto3().client("s3")
            try:
                client.upload_file(
                    Filename=from_path,
                    Bucket=bucket,
                    Key=s3_key,
                    ExtraArgs={"ServerSideEncryption": self.sse},
                )
            except Exception:
                logger.exception(f"Cannot upload file: {s3_key}")
                return None

            return f"s3://{bucket}/{s3_key}"

        # Push attachments to s3 and keep track of their url.
        s3_attachs = {}
        for name, attach in list(event.get_attachments().items()):
            attach_path = attach[0]
            # Push the attachment
            key = f"{self.s3_prefix(event)}{event.uid}/{name}"
            s3_url = s3_cp(attach_path, key, self.log_bucket)

            if s3_url is None:
                return False
            else:
                logger.debug(f"Attachment successfully pushed to {s3_url}")
                ctype, encoding = mimetypes.guess_type(attach_path)
                s3_attachs[name] = {
                    "s3_url": s3_url,
                    "encoding": encoding,
                    "ctype": ctype,
                }

        # Create the JSON to send on the event bucket
        s3_event = {"attachments": s3_attachs, "event": event.as_dict()}

        try:
            tempfile_name = None
            with closing(tempfile.NamedTemporaryFile(mode="w", delete=False)) as fd:
                tempfile_name = fd.name
                json.dump(s3_event, fd)

            # Note that an event can be sent several times with a different
            # status. As a consequence the target url in s3 should be different
            # for call to send.
            key = f"{self.s3_prefix(event)}{event.uid}-{unique_id()}.s3"
            s3_url = s3_cp(tempfile_name, key, self.event_bucket)

            if s3_url is None:
                return False
            else:
                logger.debug(f"Event successfully pushed to {s3_url}")
                return True
        finally:
            if tempfile_name is not None:
                rm(tempfile_name)
