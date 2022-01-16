import datetime
import os
from typing import Union, Tuple
from pycountry import countries, db as pycountry_db
from cryptography.hazmat.backends.openssl.backend import (
    backend as x509_openssl_backend
)
from cryptography.x509 import (
    base as x509,
    extensions as x509_extensions,
    oid as x509_oid,
    DNSName, IPAddress, UniformResourceIdentifier
)


class CountryStatistics:
    CERT_EXTENSION_PEM = ".pem"
    CERT_EXTENSIONS = (CERT_EXTENSION_PEM)

    def __init__(self, certs_directory: str):
        if not os.path.exists(certs_directory):
            raise ValueError("Given directory '{}' doesn't exist!".format(certs_directory))
        if not os.path.isdir(certs_directory):
            raise ValueError("Given path '{}' isn't a directory!".format(certs_directory))
        self.cert_dir = certs_directory

    def get_country_statistics(self) -> dict:
        countries_with_certs = {}
        for file in os.listdir(self.cert_dir):
            _, file_extension = os.path.splitext(file)
            if file_extension not in self.CERT_EXTENSIONS:
                continue

            # Go read the cert
            cert_file = os.path.join(self.cert_dir, file)
            country_data, cert_validity = self._read_country_from_cert(cert_file)
            if not country_data:
                continue

            if country_data.alpha_2 in countries_with_certs:
                # A cert from this country has been recorded earlier.
                if cert_validity < countries_with_certs[country_data.alpha_2][1]:
                    # This cert has older validity datetime than previous one
                    countries_with_certs[country_data.alpha_2] = (country_data, cert_validity)
            else:
                countries_with_certs[country_data.alpha_2] = (country_data, cert_validity)

        # Done looping the cert-files

        return countries_with_certs

    def _read_country_from_cert(self, certfile: str) -> Tuple[
        Union[None, pycountry_db.Data],
        Union[None, datetime.datetime]
    ]:
        st_cert = open(certfile, 'rb').read()
        certificate = x509.load_pem_x509_certificate(st_cert, x509_openssl_backend)

        for subject_compo in certificate.subject:
            if not subject_compo.oid._name == 'countryName':
                continue
            alpha_2 = subject_compo.value
            country_data = countries.get(alpha_2=alpha_2)

            return country_data, certificate.not_valid_before

        return None, None
