from smart_card import SmartCard

_cards = {"openPGP_ZeitControl": "openpgp_ZeitControl_card.json"}

sc = SmartCard.from_profile(_cards["openPGP_ZeitControl"])

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
