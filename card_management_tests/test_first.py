class TestFirst:

    def test_create_keys_and_certs(self):
        from pkcs11_card_management.smart_card import SmartCard

        sc = SmartCard.from_profile("card_management_tests/softhsm_test.json")

        personal_data = {
            "country": "US",
            "state": "United states",
            "organizational unit": ["Secret unit"],
            "organization": "The Firm",
            "surname": "Secret",
            "given name": "Joe",
            "common name": "Joe Secret",
            "email": "joe.secret@example.net",
            "alt_names": ["joe.secret@example.net"],
        }

        ret = sc.create_keys_and_certificates(personal_data, 30, None, False)
        assert ret

    def test_create_keys_and_certs_serial(self):
        from pkcs11_card_management.smart_card import SmartCard

        sc = SmartCard.from_profile("card_management_tests/softhsm_test.json")

        personal_data = {
            "country": "US",
            "state": "United states",
            "organizational unit": ["Secret unit"],
            "organization": "The Firm",
            "surname": "Secret",
            "given name": "Joe",
            "common name": "Joe Secret",
            "email": "joe.secret@example.net",
            "alt_names": ["joe.secret@example.net"],
        }

        ret = sc.create_keys_and_certificates_serial(
            personal_data, 30, None, False
        )
        assert ret
