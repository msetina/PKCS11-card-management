from logging import Logger

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from pkcs11_card_management.certificate_data_factory import (
    CertificateDataFactory,
)


class CertificateFactory(CertificateDataFactory):
    def __init__(self, logger: Logger) -> None:
        super(CertificateFactory, self).__init__(logger)
        self.__builder: x509.CertificateBuilder | None = None

    # Prepare data from personal data in params dict
    def prep_cert_data(self, params: dict) -> None:
        self.__builder = x509.CertificateBuilder()
        self.__builder = self.__builder.serial_number(
            x509.random_serial_number()
        )
        names, extensions, not_valid_before, not_valid_after = (
            self._get_names_n_extensions(params)
        )
        if len(names) > 0:
            self._subject = x509.Name(names)
            if self._subject is not None:
                self.__builder = self.__builder.subject_name(self._subject)
        if len(extensions) > 0:
            for ext in extensions:
                if ext is not None:
                    self.__builder = self.__builder.add_extension(
                        critical=ext.critical, extval=ext.extension
                    )
        self.__builder = self.__builder.not_valid_before(not_valid_before)
        self.__builder = self.__builder.not_valid_after(not_valid_after)

        self.__builder = self.__builder.add_extension(
            x509.BasicConstraints(ca=self._is_ca, path_length=None),
            critical=True,
        )

    ##Make certificate with provided keys
    def make_certificate(
        self,
        certificate_key,
        ca_key,
        sign_hash,
    ) -> x509.Certificate:
        if self.__builder is not None:
            key_usage = certificate_key.read_key_usage()
            usages = key_usage.get_X509_usage(self._is_ca)
            self.__builder = self.__builder.add_extension(
                x509.KeyUsage(**usages),
                critical=True,
            )
            public_key = certificate_key.public_key()
            subject_key = x509.SubjectKeyIdentifier.from_public_key(public_key)
            self.__builder = self.__builder.add_extension(
                subject_key, critical=False
            )
            self.__builder = self.__builder.public_key(public_key)
            authority_key = x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            )
            self.__builder = self.__builder.add_extension(
                authority_key, critical=False
            )

            cert_PEM = ca_key.certificate()
            if cert_PEM is not None:
                cert = x509.load_pem_x509_certificate(cert_PEM, default_backend)
                self.__builder = self.__builder.issuer_name(cert.subject)
            else:
                if self._subject is not None:
                    self.__builder = self.__builder.issuer_name(self._subject)

            if isinstance(ca_key, RSAPrivateKey):
                if False:
                    padding1 = padding.PSS(
                        mgf=padding.MGF1(sign_hash),
                        salt_length=padding.PSS.DIGEST_LENGTH,
                    )
                    certificate = self.__builder.sign(
                        ca_key, algorithm=sign_hash, rsa_padding=padding1
                    )
                else:
                    certificate = self.__builder.sign(
                        ca_key,
                        algorithm=sign_hash,
                        rsa_padding=padding.PKCS1v15(),
                    )

            else:
                certificate = self.__builder.sign(ca_key, algorithm=sign_hash)
            return certificate
        else:
            raise Exception("Certificate data not initialized.")
