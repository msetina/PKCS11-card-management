from logging import INFO, StreamHandler, getLogger
from sys import stdout

from pkcs11_card_management.smart_card import SmartCard

_cards = {"openPGP_ZeitControl": "openpgp_ZeitControl_card.json"}

ch = StreamHandler(stdout)
ch.setLevel(INFO)
logger = getLogger("Prepare a smartcard")
logger.setLevel(INFO)
logger.addHandler(ch)

sc = SmartCard.from_profile(_cards["openPGP_ZeitControl"], logger)

personal_data = {
    "country": "SI",
    "state": "Slovenija",
    "organizational unit": ["Secret unit"],
    "organization": "Qbit",
    "surname": "Šetina",
    "given name": "Miha",
    "common name": "Miha Šetina",
    "email": "miha_setina@t-2.net",
    "alt_names": ["miha_setina@t-2.net"],
}


sc.create_keys_and_certificates(personal_data)
