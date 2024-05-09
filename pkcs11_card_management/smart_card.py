from __future__ import annotations
from enum import Enum
from json import load
from logging import Logger, getLogger
from typing import Sequence, Type

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP384R1,
    EllipticCurvePrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import Certificate, ExtensionNotFound, KeyUsage
from pkcs11_cryptography_keys import (
    KeyTypes,
    Pin4Token,
    PKCS11KeyUsage,
    PKCS11KeyUsageAll,
    PKCS11KeyUsageAllNoDerive,
    PKCS11KeyUsageEncyrption,
    PKCS11KeyUsageSignature,
    PKCS11URIAdminSession,
    PKCS11URIKeySession,
)

from pkcs11_card_management.certificate_factory import CertificateFactory


class KeyCreation(Enum):
    Error = 0
    KeyCreated = 1
    AllCreated = 2


_smart_card_key_usage: dict[KeyTypes, dict] = {
    KeyTypes.EC: {
        "all": PKCS11KeyUsageAll,
        "encryption": PKCS11KeyUsageEncyrption,
        "signature": PKCS11KeyUsageSignature,
    },
    KeyTypes.RSA: {
        "all": PKCS11KeyUsageAllNoDerive,
        "encryption": PKCS11KeyUsageEncyrption,
        "signature": PKCS11KeyUsageSignature,
    },
}

_smart_card_key_types: dict[str, dict] = {
    "secp384r1": {
        "key_type": KeyTypes.EC,
        "EC_curve": SECP384R1(),
    },
    "rsa2048": {
        "key_type": KeyTypes.RSA,
        "RSA_length": 2048,
    },
    "rsa3072": {
        "key_type": KeyTypes.RSA,
        "RSA_length": 3072,
    },
    "rsa4096": {
        "key_type": KeyTypes.RSA,
        "RSA_length": 4096,
    },
}

_cryptography_key_types: dict[Type[PrivateKeyTypes], tuple[KeyTypes, str]] = {
    RSAPrivateKey: (KeyTypes.RSA, "RSA_private_key"),
    EllipticCurvePrivateKey: (KeyTypes.EC, "EC_private_key"),
}


class SmartCard(object):
    def __init__(self, logger: Logger | None = None) -> None:
        self._profile: dict = {}
        self._logger = (
            logger if logger is not None else getLogger("SmartCard prepare")
        )

    @classmethod
    def from_profile(
        cls, profile_file: str, logger: Logger | None = None
    ) -> SmartCard:
        ret = cls(logger)
        with open(profile_file) as p:
            ret._profile = load(p)
        return ret

    def _create_key(self, admin: PKCS11URIAdminSession, params: dict) -> bool:
        ret = False
        with admin as current_admin:
            if current_admin is not None:
                if current_admin.delete_key_pair():
                    self._logger.info("Keypair deleted")
                priv_key = current_admin.create_key_pair(**params)
                self._logger.info("Keypair created")
                ret = True
        return ret

    def _read_pk12(
        self, pk12_file: str, password: bytes | None = None
    ) -> tuple[PrivateKeyTypes, Certificate | None, list[Certificate] | None]:
        with open(pk12_file, "rb") as fd:
            fl = fd.read()
            key_tuple = pkcs12.load_key_and_certificates(fl, password)
            private = key_tuple[0]
            if private is not None:
                cert = key_tuple[1]
                certs = None
                if len(key_tuple) > 2:
                    certs = key_tuple[2]
                return private, cert, certs
            else:
                raise Exception("Private key not persent in PK12 file")

    def _get_key_usage_from_certificate(self, certificate: Certificate):
        try:
            ext = certificate.extensions.get_extension_for_class(KeyUsage)
            return PKCS11KeyUsage.from_X509_KeyUsage(ext.value)
        except ExtensionNotFound:
            self._logger.info(
                "Certificate does not have key usage, so you get all usages."
            )
        return PKCS11KeyUsageAll()

    def _create_certificate(
        self,
        admin: PKCS11URIAdminSession,
        key_session: PKCS11URIKeySession,
        params: dict,
        sig_session: PKCS11URIKeySession | None,
    ):
        factory = CertificateFactory(self._logger)
        factory.prep_cert_data(params)

        # # Slovenija za servis ESEI
        # # <Extension(oid=<ObjectIdentifier(oid=1.3.6.1.4.1.58536.1.1.1.2.1, name=Unknown OID)>, critical=False, value=<UnrecognizedExtension(oid=<ObjectIdentifier(oid=1.3.6.1.4.1.58536.1.1.1.2.1, name=Unknown OID)>, value=b'\x16Rhttps%3A%2F%2Fws.si-trust.gov.si%2Fesei-get%3Fsn%3D4005195643038%26ca%3Deid-ca-low')>)>
        # # <Extension(oid=<ObjectIdentifier(oid=1.3.6.1.4.1.58536.1.1.1.3.1, name=Unknown OID)>, critical=False, value=<UnrecognizedExtension(oid=<ObjectIdentifier(oid=1.3.6.1.4.1.58536.1.1.1.3.1, name=Unknown OID)>, value=b'\x16khttps%3A%2F%2Fws.si-trust.gov.si%2Fesei-validate%3Fsn%3D4005195643038%26ca%3Deid-ca-low%26esei%3D0000000000')>)>

        if sig_session is None:
            with key_session as PK:
                if PK is not None:
                    certificate = factory.make_certificate(
                        PK, PK, hashes.SHA256()
                    )
                else:
                    raise Exception("Key could not be found")
        else:
            with key_session as PK, sig_session as signer:
                if PK is not None and signer is not None:
                    certificate = factory.make_certificate(
                        PK, signer, hashes.SHA256()
                    )
                else:
                    raise Exception("Key or signer key could not be found")

        if certificate != None:
            self._write_certificate(admin, certificate)
        self._logger.info("Certificate creation ended")

    def _write_certificate(
        self, admin_session: PKCS11URIAdminSession, certificate: Certificate
    ):
        with admin_session as current_admin:
            self._logger.info("Writing certificate to the card.")
            if current_admin is not None:
                current_admin.delete_certificate()
                current_admin.write_certificate(certificate)
                self._logger.info("Certificate written to the card.")

    def _gen_key_profile_for_key(self, so_to_create: bool):
        for key_profile in self._profile:
            if "key" in key_profile:
                nm = key_profile["name"]
                admin = PKCS11URIAdminSession(
                    key_profile["uri"],
                    not so_to_create,
                    Pin4Token(nm, "Creating keys."),
                    self._logger,
                )
                key_def = key_profile["key"]
                yield admin, key_def

    def _gen_key_profile_for_certificate(
        self, so_to_create: bool, signature_uri: str | None = None
    ):
        for key_profile in self._profile:
            if "certificate" in key_profile:
                nm = key_profile["name"]
                admin = PKCS11URIAdminSession(
                    key_profile["uri"],
                    not so_to_create,
                    Pin4Token(nm, "Creating keys."),
                    self._logger,
                )
                key_session = PKCS11URIKeySession(
                    key_profile["uri"],
                    Pin4Token(nm, "Adding key to certificate."),
                    self._logger,
                )
                sig_session = None
                if "cert_sig" in key_profile:
                    sig_session = PKCS11URIKeySession(
                        key_profile["cert_sig"],
                        Pin4Token(nm, "Signing certificate with provided key"),
                        self._logger,
                    )
                elif signature_uri is not None:
                    sig_session = PKCS11URIKeySession(
                        signature_uri,
                        Pin4Token(nm, "Signing certificate with provided key"),
                        self._logger,
                    )
                cert_def = key_profile["certificate"]
                yield key_session, sig_session, admin, cert_def

    def _gen_key_profile_for_key_and_certificate(
        self, so_to_create: bool, signature_uri: str | None = None
    ):
        for key_profile in self._profile:
            if "certificate" in key_profile and "key" in key_profile:
                nm = key_profile["name"]
                admin = PKCS11URIAdminSession(
                    key_profile["uri"],
                    not so_to_create,
                    Pin4Token(nm, "Creating keys."),
                    self._logger,
                )
                key_session = PKCS11URIKeySession(
                    key_profile["uri"],
                    Pin4Token(nm, "Adding key to certificate."),
                    self._logger,
                )
                sig_session = None
                if "cert_sig" in key_profile:
                    sig_session = PKCS11URIKeySession(
                        key_profile["cert_sig"],
                        Pin4Token(nm, "Signing certificate with provided key"),
                        self._logger,
                    )
                elif signature_uri is not None:
                    sig_session = PKCS11URIKeySession(
                        signature_uri,
                        Pin4Token(nm, "Signing certificate with provided key"),
                        self._logger,
                    )
                cert_def = key_profile["certificate"]
                key_def = key_profile["key"]
                yield key_session, sig_session, admin, key_def, cert_def

    def _create_key_from_profile(
        self, admin_session: PKCS11URIAdminSession, key_def: dict
    ) -> KeyCreation:
        key_data = {}
        if "key_type" in key_def:
            key_data.update(
                _smart_card_key_types.get(
                    key_def["key_type"],
                    {
                        "key_type": KeyTypes.RSA,
                        "RSA_length": 2048,
                    },
                )
            )
            key_usages = _smart_card_key_usage.get(key_data["key_type"], None)
            if key_usages is not None:
                key_data["key_usage"] = key_usages.get(
                    key_def["key_usage"], PKCS11KeyUsageAll
                )()
            else:
                key_data["key_usage"] = PKCS11KeyUsageAll()
            key_created = self._create_key(admin_session, key_data)
            if key_created:
                return KeyCreation.KeyCreated
            else:
                return KeyCreation.Error
        elif "key_file" in key_def:
            private_key, certificate, CAs = self._read_pk12(
                key_def["key_file"], key_def["file_password"].encode()
            )
            if certificate is not None:
                key_data["key_usage"] = self._get_key_usage_from_certificate(
                    certificate
                )
            else:
                key_data["key_usage"] = PKCS11KeyUsageAll()
            tp = _cryptography_key_types.get(
                type(private_key), (KeyTypes.RSA, "RSA_private_key")
            )
            key_data["key_type"] = tp[0]
            key_data[tp[1]] = private_key
            if self._create_key(admin_session, key_data):
                if certificate is not None:
                    self._write_certificate(admin_session, certificate)
                else:
                    return KeyCreation.KeyCreated
                # if CAs is not None:
                #     for cert in CAs:
                #         self._write_certificate(admin_session, cert)
            return KeyCreation.AllCreated
        else:
            self._logger.info("Key definition is not known.")
            return KeyCreation.Error

    def _create_certificate_from_profile(
        self,
        admin_session: PKCS11URIAdminSession,
        key_session: PKCS11URIKeySession,
        sig_session: PKCS11URIKeySession,
        cert_def: dict,
        personal_data: dict,
        num_days: int = 30,
    ) -> bool:
        ret = False
        if key_session is not None:
            cert_data = {}
            if cert_def is not None:
                cert_data.update(cert_def)
            cert_data.update(personal_data)
            cert_data["num_days"] = num_days
            self._create_certificate(
                admin_session, key_session, cert_data, sig_session
            )
            ret = True
        else:
            self._logger.info("Key session was not present")
            ret = False
        return ret

    def create_keys_and_certificates_serial(
        self,
        personal_data: dict[str, Sequence[str]] | None = None,
        num_days: int = 30,
        signature_uri: str | None = None,
        so_to_create: bool = True,
    ) -> bool:
        ret = False
        no_key = False
        for (
            admin_session,
            key_def,
        ) in self._gen_key_profile_for_key(so_to_create):
            creation = self._create_key_from_profile(admin_session, key_def)
            if creation == KeyCreation.Error:
                self._logger.info("Key was not created! {0}".format(key_def))
                no_key = True
                break
            elif creation == KeyCreation.AllCreated:
                ret = True
        if not no_key:
            for (
                key_session,
                sig_session,
                admin_session,
                cert_def,
            ) in self._gen_key_profile_for_certificate(
                so_to_create, signature_uri
            ):
                if personal_data is not None:
                    ret = self._create_certificate_from_profile(
                        admin_session,
                        key_session,
                        sig_session,
                        cert_def,
                        personal_data,
                        num_days,
                    )
                else:
                    ret = False
                if not ret:
                    self._logger.info("Certificate was not created!")
                    break

        return ret

    def create_keys_and_certificates(
        self,
        personal_data: dict[str, Sequence[str]] | None = None,
        num_days: int = 30,
        signature_uri: str | None = None,
        so_to_create: bool = True,
    ) -> bool:
        ret = False
        for (
            key_session,
            sig_session,
            admin_session,
            key_def,
            cert_def,
        ) in self._gen_key_profile_for_key_and_certificate(
            so_to_create, signature_uri
        ):
            creation = self._create_key_from_profile(admin_session, key_def)
            if creation == KeyCreation.Error:
                self._logger.info("Key was not created! {0}".format(key_def))
                break
            elif creation == KeyCreation.KeyCreated:
                if personal_data is not None:
                    ret = self._create_certificate_from_profile(
                        admin_session,
                        key_session,
                        sig_session,
                        cert_def,
                        personal_data,
                        num_days,
                    )
                else:
                    ret = False
                if not ret:
                    self._logger.info("Certificate was not created!")
                    break

        return ret
