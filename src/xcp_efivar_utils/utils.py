import contextlib
import logging
import os
import pathlib
import struct
import subprocess
import tempfile

import typing

# Assorted utility functions


def unserialize(format: typing.Union[str, bytes], buf: bytes):
    return (buf[struct.calcsize(format) :],) + struct.unpack_from(format, buf)


def unserialize_data(buf: bytes, rem: int, limit: int, strict: bool = True):
    buf, buflen = unserialize("<Q", buf)
    logging.debug("next data length = %d", buflen)

    if buflen > rem:
        raise ValueError("next data length (%d) > remaining length (%d)" % (buflen, rem))
    if buflen == 0:
        raise ValueError("next data length == 0")
    if buflen > limit:
        if strict:
            raise ValueError("next data length (%d) > limit (%d)" % (buflen, limit))
        else:
            logging.debug("next data length (%d) > limit (%d)", buflen, limit)

    var = buf[:buflen]
    buf = buf[buflen:]

    return buf, var


def unserialize_struct(s: struct.Struct, buf: bytes):
    return (buf[s.size :],) + s.unpack_from(buf)


@contextlib.contextmanager
def named_temporary_file(mode="w+b", suffix=None, prefix=None, dir=None, delete=True, **kwargs):
    """
    Unlike tempfile.NamedTemporaryFile, this function only deletes the temp file at context manager exit.
    Also unlike tempfile.NamedTemporaryFile, it returns a tuple (fileobj, path) rather than passing the path in
    fileobj.name.
    """
    # delete_on_close doesn't exist on old Python versions, so we have to use this roundabout method
    tmp_name = None
    try:
        tmp_fd, tmp_name = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=dir, text="b" not in mode)
        with os.fdopen(tmp_fd, mode, **kwargs) as tmp:
            yield tmp, tmp_name
    finally:
        if delete and tmp_name:
            os.unlink(tmp_name)


def convert_certificate_to_der(infile, outfile):
    logging.info(f"converting {infile} -> {outfile}")
    cert_forms = ["PEM", "DER"]
    for inform in cert_forms:
        logging.info(f"trying {inform}")
        try:
            subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(infile),
                    "-inform",
                    inform,
                    "-outform",
                    "DER",
                    "-out",
                    str(outfile),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            logging.info("OK")
            break
        except subprocess.CalledProcessError:
            pass
    else:
        raise Exception(f"Cannot convert certificate file {infile}")


def read_certificate_as_der(infile, tmpdir):
    with named_temporary_file(dir=tmpdir) as (cert_der, cert_path):
        cert_der.close()
        convert_certificate_to_der(infile, cert_path)
        return pathlib.Path(cert_path).read_bytes()
