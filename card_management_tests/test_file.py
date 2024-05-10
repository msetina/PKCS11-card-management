class TestFile:

    def test_create_keys_and_certs_from_file(self):
        from pkcs11_card_management.smart_card import SmartCard

        sc = SmartCard.from_profile(
            "card_management_tests/softhsm_test_file.json"
        )

        ret = sc.create_keys_and_certificates(None, 30, None, False)
        assert ret

    def test_create_keys_and_certs_from_file_serial(self):
        from pkcs11_card_management.smart_card import SmartCard

        sc = SmartCard.from_profile(
            "card_management_tests/softhsm_test_file.json"
        )

        ret = sc.create_keys_and_certificates_serial(None, 30, None, False)
        assert ret
