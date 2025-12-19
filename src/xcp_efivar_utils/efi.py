import datetime
import logging
import pathlib
import struct
import subprocess
import tempfile
import uuid

import typing

# UEFI variable declarations per the spec

EFI_CERT_X509_GUID = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
EFI_CERT_SHA256_GUID = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")

EFI_SIGNATURE_LIST = struct.Struct("<16sIII")

EFI_VARIABLE_NON_VOLATILE = 0x00000001
EFI_VARIABLE_BOOTSERVICE_ACCESS = 0x00000002
EFI_VARIABLE_RUNTIME_ACCESS = 0x00000004
EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020

# Convenient nonstandard alias for all 4
EFI_VARIABLE_SECUREBOOT_KEYS = (
    EFI_VARIABLE_NON_VOLATILE
    | EFI_VARIABLE_BOOTSERVICE_ACCESS
    | EFI_VARIABLE_RUNTIME_ACCESS
    | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
)

EFI_VARIABLE_APPEND_WRITE = 0x00000040

EFI_TIME = struct.Struct("<HBBBBBBIhBB")
assert EFI_TIME.size == 16

# Special EFI_TIME for use on append-mode EFI_VARIABLE_AUTHENTICATION_2 structures
EFI_TIME_APPEND = EFI_TIME.pack(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

WIN_CERTIFICATE_UEFI_GUID = struct.Struct("<IHH16s")
EFI_CERT_TYPE_PKCS7_GUID = uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7")
WIN_CERT_TYPE_EFI_GUID = 0x0EF1


def make_efi_signature_data_sha256(owner: uuid.UUID, hash: bytes):
    if len(hash) != 32:
        raise ValueError("Invalid hash length")
    return owner.bytes_le + hash


def make_efi_signature_data_x509(owner: uuid.UUID, cert_bytes: bytes):
    if not cert_bytes:
        raise ValueError("Empty cert_bytes")
    return owner.bytes_le + cert_bytes


def make_efi_signature_list(type: uuid.UUID, signatures: typing.List[bytes]):
    siglen = len(signatures[0])
    logging.info(f"siglen {siglen}")
    if not all(map(lambda s: len(s) == siglen, signatures)):
        raise ValueError("Invalid signature list")
    header = EFI_SIGNATURE_LIST.pack(
        type.bytes_le,  # signature type
        EFI_SIGNATURE_LIST.size + siglen * len(signatures),  # signature list size
        0,  # signature header size
        siglen,  # signature size
    )
    siglist = b"".join([header] + signatures)
    logging.info(f"siglist len {len(siglist)}")
    return siglist


def make_efi_time(time: datetime.datetime, authvar: bool, append: bool):
    if append:
        # use special timestamp as specified
        return EFI_TIME_APPEND
    else:
        return EFI_TIME.pack(
            time.year,  # Year
            time.month,  # Month
            time.day,  # Day
            time.hour,  # Hour
            time.minute,  # Minute
            time.second,  # Second
            0,  # Pad1
            0 if authvar else time.microsecond * 1000,  # Nanosecond
            0,  # TimeZone
            0,  # Daylight
            0,  # Pad2
        )


def convert_certificate(infile, outfile):
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


def make_efi_variable_authentication_2(
    varname: str,
    varguid: uuid.UUID,
    siglists: typing.List[bytes],
    timestamp: datetime.datetime,
    attributes: int,
    append: bool,
    signer_cert: typing.Union[str, pathlib.Path, None],
    signer_key: typing.Union[str, pathlib.Path, None],
    tmpdir: str,
):
    timestamp_bytes = make_efi_time(timestamp, authvar=True, append=append)

    siglists_bytes = b"".join(siglists)
    logging.info(f"total siglist {len(siglists_bytes)} bytes")

    attributes = attributes | (EFI_VARIABLE_APPEND_WRITE if append else 0)
    logging.info(f"attributes 0x{attributes:x}")
    signable = b"".join([
        varname.encode("utf-16le"),
        varguid.bytes_le,
        struct.pack("<I", attributes),
        timestamp_bytes,
        siglists_bytes,
    ])

    signature = b""
    if signer_cert and signer_key:
        with (
            tempfile.NamedTemporaryFile(dir=pathlib.Path(tmpdir), delete=False) as signable_file,
            tempfile.NamedTemporaryFile(dir=pathlib.Path(tmpdir), delete=False) as signature_file,
        ):
            signable_file.write(signable)
            signable_file.close()

            signature_file.close()
            subprocess.run(
                [
                    "openssl",
                    "smime",
                    "-sign",
                    "-in",
                    signable_file.name,
                    "-out",
                    signature_file.name,
                    "-outform",
                    "DER",
                    "-signer",
                    str(signer_cert),
                    "-inkey",
                    str(signer_key),
                    "-md",
                    "SHA256",
                    "-noattr",
                    "-binary",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            signature = pathlib.Path(signature_file.name).read_bytes()
    elif signer_cert or signer_key:
        raise ValueError("Signer cert and signer key must be provided together")

    authvar = b"".join([
        timestamp_bytes,
        WIN_CERTIFICATE_UEFI_GUID.pack(
            WIN_CERTIFICATE_UEFI_GUID.size + len(signature),  # WIN_CERTIFICATE.dwLength
            0x0200,  # WIN_CERTIFICATE.wRevision
            WIN_CERT_TYPE_EFI_GUID,  # WIN_CERTIFICATE.wCertificateType
            EFI_CERT_TYPE_PKCS7_GUID.bytes_le,  # CertType
        ),
        signature,
        siglists_bytes,
    ])

    return authvar, siglists_bytes, signable, signature
