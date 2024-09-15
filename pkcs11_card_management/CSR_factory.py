from logging import Logger

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from pkcs11_card_management.certificate_data_factory import (
    CertificateDataFactory,
)


class CSRFactory(CertificateDataFactory):
    def __init__(self, logger: Logger) -> None:
        super(CSRFactory, self).__init__(logger)
        self.__builder: x509.CertificateSigningRequestBuilder | None = None

    # Prepare data from personal data in params dict
    def prep_cert_data(self, params: dict) -> None:
        self.__builder = x509.CertificateSigningRequestBuilder()
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

        self.__builder = self.__builder.add_extension(
            x509.BasicConstraints(ca=self._is_ca, path_length=None),
            critical=True,
        )

    def read_cert_data(self, existing_cert: x509.Certificate):
        self.__builder = x509.CertificateSigningRequestBuilder()
        # Extract attributes and extensions from the existing certificate
        # TODO: remove extensions added later....
        names = []
        for subject in existing_cert.subject:
            # TODO check if usable subject
            names.append(subject)
        self.__builder = self.__builder.subject_name(x509.Name(names))
        for extension in existing_cert.extensions:
            # TODO check if usable extension
            do_not_copy = [
                x509.OID_KEY_USAGE,
                x509.OID_SUBJECT_KEY_IDENTIFIER,
                x509.OID_AUTHORITY_KEY_IDENTIFIER,
            ]
            if extension.oid not in do_not_copy:
                self.__builder = self.__builder.add_extension(
                    extension.value, extension.critical
                )

    ##Make certificate signing request with provided keys
    def make_CSR(
        self,
        certificate_key,
        sign_hash,
    ) -> x509.CertificateSigningRequest:
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
            # self.__builder = self.__builder.public_key(public_key)

            if isinstance(certificate_key, RSAPrivateKey):
                if False:
                    padding1 = padding.PSS(
                        mgf=padding.MGF1(sign_hash),
                        salt_length=padding.PSS.DIGEST_LENGTH,
                    )
                    csr = self.__builder.sign(
                        certificate_key,
                        algorithm=sign_hash,
                        rsa_padding=padding1,
                    )
                else:
                    csr = self.__builder.sign(
                        certificate_key,
                        algorithm=sign_hash,
                        rsa_padding=padding.PKCS1v15(),
                    )

            else:
                csr = self.__builder.sign(certificate_key, algorithm=sign_hash)
            return csr
        else:
            raise Exception("Certificate data not initialized.")
