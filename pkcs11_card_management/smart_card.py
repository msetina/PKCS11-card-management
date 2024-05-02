from json import load
from logging import Logger

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1
from pkcs11_cryptography_keys import (
    KeyTypes,
    Pin4Token,
    PKCS11KeyUsageAll,
    PKCS11KeyUsageAllNoDerive,
    PKCS11KeyUsageEncyrption,
    PKCS11KeyUsageSignature,
    PKCS11URIAdminSession,
    PKCS11URIKeySession,
)

from .certificate_factory import CertificateFactory

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


class SmartCard(object):
    def __init__(self, logger: Logger | None = None) -> None:
        self._profile: dict = {}
        self._logger = (
            logger if logger is not None else Logger("SmartCard prepare")
        )

    @classmethod
    def from_profile(cls, profile_file: str, logger: Logger | None = None):
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
            with admin as current_admin:
                self._logger.info("Writing key to the card.")
                if current_admin is not None:
                    current_admin.delete_certificate()
                    current_admin.write_certificate(certificate)
                    self._logger.info("Key written to the card.")
        self._logger.info("Certificate creation ended")

    def create_keys_and_certificates(
        self,
        personal_data: dict[str, str],
        num_days: int = 30,
        signature_uri: str | None = None,
        so_to_create: bool = True,
    ) -> bool:
        ret = False
        for key_profile in self._profile:
            nm = key_profile["name"]
            admin = PKCS11URIAdminSession(
                key_profile["uri"],
                not so_to_create,
                Pin4Token(nm),
                self._logger,
            )
            key_session = PKCS11URIKeySession(
                key_profile["uri"], Pin4Token(nm), self._logger
            )
            sig_session = None
            if "cert_sig" in key_profile:
                sig_session = PKCS11URIKeySession(
                    key_profile["cert_sig"], Pin4Token(nm), self._logger
                )
            elif signature_uri is not None:
                sig_session = PKCS11URIKeySession(
                    signature_uri, Pin4Token(nm), self._logger
                )
            ky = key_profile["key"]
            key_data = {}
            key_data.update(
                _smart_card_key_types.get(
                    ky["key_type"],
                    {
                        "key_type": KeyTypes.RSA,
                        "RSA_length": 2048,
                    },
                )
            )
            key_usages = _smart_card_key_usage.get(key_data["key_type"], None)
            if key_usages is not None:
                key_data["key_usage"] = key_usages.get(
                    ky["key_usage"], PKCS11KeyUsageAll
                )()
            else:
                key_data["key_usage"] = PKCS11KeyUsageAll()

            if self._create_key(admin, key_data):
                if key_session is not None:
                    cert_data = {}
                    if "certificate" in key_profile:
                        cert_data.update(key_profile["certificate"])
                    cert_data.update(personal_data)
                    cert_data["num_days"] = num_days
                    self._create_certificate(
                        admin, key_session, cert_data, sig_session
                    )
                    ret = True
                else:
                    self._logger.info("Key session was not present")
                    ret = False
            else:
                ret = False
                self._logger.info("Key was not created!")
                break

        return ret
