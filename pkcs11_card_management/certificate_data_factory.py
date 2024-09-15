import datetime
from logging import Logger
from typing import Callable

from cryptography import x509
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    NameOID,
)


class ExtensionCarrier(object):
    def __init__(self, critical: bool, extension: x509.ExtensionType) -> None:
        self.critical = critical
        self.extension = extension


class CertificateDataFactory(object):
    def __init__(self, logger: Logger) -> None:
        self._logger = logger
        self._subject: x509.Name | None = None
        self._is_ca = False
        self._name_translation = {
            "country": NameOID.COUNTRY_NAME,
            "state": NameOID.STATE_OR_PROVINCE_NAME,
            "organizational unit": NameOID.ORGANIZATIONAL_UNIT_NAME,
            "organization": NameOID.ORGANIZATION_NAME,
            "surname": NameOID.SURNAME,
            "given name": NameOID.GIVEN_NAME,
            "common name": NameOID.COMMON_NAME,
            "email": NameOID.EMAIL_ADDRESS,
            "title": NameOID.TITLE,
            "post address": NameOID.POSTAL_ADDRESS,
            "post": NameOID.POSTAL_CODE,
            "street address": NameOID.STREET_ADDRESS,
            "user id": NameOID.USER_ID,
        }

        self._extra_name_translation: dict[
            str,
            Callable[[list], ExtensionCarrier | None]
            | Callable[[dict], ExtensionCarrier | None],
        ] = {
            "alt_names": self._add_alternative_name_extensions,
            "urls": self._add_crl_urls_extensions,
            "auth_infos": self._add_auth_info_extensions,
            "key_usage": self._add_key_usage_extensions,
        }

        self._ext_key_usages = {
            "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH,
            "server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
            "code_sign": ExtendedKeyUsageOID.CODE_SIGNING,
            "ocsp_sign": ExtendedKeyUsageOID.OCSP_SIGNING,
            "email_protect": ExtendedKeyUsageOID.EMAIL_PROTECTION,
            "sc_logon": ExtendedKeyUsageOID.SMARTCARD_LOGON,
            "ipsec_ike": ExtendedKeyUsageOID.IPSEC_IKE,
            "any": ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
        }

    def _add_key_usage_extensions(
        self, e_key_usages: list
    ) -> ExtensionCarrier | None:
        key_usages = []
        for ku in e_key_usages:
            if ku in self._ext_key_usages:
                key_usages.append(self._ext_key_usages[ku])
        if key_usages:
            return ExtensionCarrier(False, x509.ExtendedKeyUsage(key_usages))
        else:
            self._logger.info("Key usage extensions could not be created")
            return None

    def _add_alternative_name_extensions(
        self, e_names: list
    ) -> ExtensionCarrier | None:
        if e_names:
            ext_names = []
            for e_name in e_names:
                ext_names.append(x509.RFC822Name(e_name))
            return ExtensionCarrier(
                False, x509.SubjectAlternativeName(ext_names)
            )
        else:
            self._logger.info(
                "Alternative name extensions could not be created"
            )
            return None

    # <Extension(oid=<ObjectIdentifier(oid=2.5.29.31, name=cRLDistributionPoints)>, critical=False, value=<CRLDistributionPoints([<DistributionPoint(full_name=[<UniformResourceIdentifier(value='http://si-trust-data.gov.si/crl/si-trust-eid-nizka-raven.crl')>], relative_name=None, reasons=None, crl_issuer=None)>])>)>
    def _add_crl_urls_extensions(
        self, crl_urls: list
    ) -> ExtensionCarrier | None:
        if crl_urls:
            urls = [x509.UniformResourceIdentifier(c) for c in crl_urls]
            dps = [
                x509.DistributionPoint(
                    full_name=[c],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None,
                )
                for c in urls
            ]
            return ExtensionCarrier(False, x509.CRLDistributionPoints(dps))
        else:
            self._logger.info("CRL url extensions could not be created")
            return None

    # <Extension(oid=<ObjectIdentifier(oid=1.3.6.1.5.5.7.1.1, name=authorityInfoAccess)>, critical=False, value=<AuthorityInformationAccess([<AccessDescription(access_method=<ObjectIdentifier(oid=1.3.6.1.5.5.7.48.2, name=caIssuers)>, access_location=<UniformResourceIdentifier(value='http://si-trust-data.gov.si/crt/si-trust-eid-nizka-raven.cer')>)>, <AccessDescription(access_method=<ObjectIdentifier(oid=1.3.6.1.5.5.7.48.1, name=OCSP)>, access_location=<UniformResourceIdentifier(value='http://si-trust-ocsp.gov.si/eid')>)>])>)>
    def _add_auth_info_extensions(self, urls: dict) -> ExtensionCarrier | None:
        auth_info_access = []
        if urls:
            for tp, url in urls.items():
                if tp == "ocsp":
                    uri = x509.UniformResourceIdentifier(url)
                    auth_info_access.append(
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.OCSP,
                            access_location=uri,
                        )
                    )
                if tp == "issuer":
                    uri = x509.UniformResourceIdentifier(url)
                    auth_info_access.append(
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                            access_location=uri,
                        )
                    )
            return ExtensionCarrier(
                False, x509.AuthorityInformationAccess(auth_info_access)
            )
        else:
            self._logger.info(
                "URLs for Authority information were not provided"
            )
            return None

    def _get_names_n_extensions(
        self, params: dict
    ) -> tuple[list, list, datetime.datetime, datetime.datetime]:
        names = []
        extensions = []
        one_day = datetime.timedelta(1, 0, 0)
        not_valid_before = datetime.datetime.today() - one_day
        not_valid_after = datetime.datetime.today() + one_day
        for k, v in params.items():
            if k in self._name_translation:
                oid = self._name_translation[k]
                if isinstance(v, list):
                    for l in v:
                        names.append(x509.NameAttribute(oid, l))
                else:
                    names.append(x509.NameAttribute(oid, v))
            elif k in self._extra_name_translation:
                proc = self._extra_name_translation[k]
                extension = proc(v)
                extensions.append(extension)
            elif k == "ca":
                self._is_ca = v
            elif k == "num_days":
                not_valid_after = datetime.datetime.today() + (one_day * v)
        return names, extensions, not_valid_before, not_valid_after

    # TODO
    # # <Extension(oid=<ObjectIdentifier(oid=2.5.29.32, name=certificatePolicies)>, critical=False, value=<CertificatePolicies([<PolicyInformation(policy_identifier=<ObjectIdentifier(oid=1.3.6.1.4.1.6105.12.1.1, name=Unknown OID)>, policy_qualifiers=['https://www.si-trust.gov.si/cps/'])>])>)>
