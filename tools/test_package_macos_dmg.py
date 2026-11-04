import unittest
from datetime import datetime, timedelta, timezone

from package_macos_dmg import app_entitlements


class MacProfileTests(unittest.TestCase):
    def test_only_the_authorized_gui_identity_is_claimed(self):
        team = "2SK9S5ZTVR"
        identifier = "app.frameleaf.desktop"
        claims = {"com.apple.application-identifier": f"{team}.{identifier}", "com.apple.developer.team-identifier": team}
        profile = {"Entitlements": {**claims, "keychain-access-groups": [f"{team}.*"]},
                   "ExpirationDate": datetime.now(timezone.utc) + timedelta(days=1),
                   "TeamIdentifier": [team], "Platform": ["OSX"], "ProvisionsAllDevices": True}
        self.assertEqual(app_entitlements(profile, team, identifier), claims)
        for override in [{"Platform": ["iOS"]}, {"Entitlements": {}}, {"TeamIdentifier": ["OTHER"]},
                         {"ProvisionsAllDevices": False}, {"ExpirationDate": datetime.min}]:
            with self.subTest(override=override), self.assertRaises(ValueError):
                app_entitlements({**profile, **override}, team, identifier)
