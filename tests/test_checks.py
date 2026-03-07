import unittest
from checks.linux_cis import FilePermissionCheck
from checks.linux_nist import (
    RootAccountCheck,
    EmptyPasswordAccountCheck,
    LoginLockoutCheck,
    LoginBannerCheck,
    SysctlCheck,
    TimeSyncCheck,
    WorldWritableCheck,
    get_nist_checks,
)


class TestFilePermissionCheck(unittest.TestCase):
    def test_check_creation(self):
        check = FilePermissionCheck("/etc/passwd", "644", "root", "root")
        self.assertEqual(check.check_id, "FILE_PERM_PASSWD")
        self.assertEqual(check.severity, "HIGH")


class TestNISTCheckCreation(unittest.TestCase):
    def test_root_account_check(self):
        check = RootAccountCheck()
        self.assertEqual(check.check_id, "NIST_ROOT_ACCOUNTS")
        self.assertEqual(check.framework, "NIST")
        self.assertEqual(check.control_id, "AC-2")
        self.assertEqual(check.severity, "CRITICAL")

    def test_empty_password_check(self):
        check = EmptyPasswordAccountCheck()
        self.assertEqual(check.check_id, "NIST_EMPTY_PASSWORDS")
        self.assertEqual(check.control_id, "AC-2")

    def test_login_lockout_check(self):
        check = LoginLockoutCheck()
        self.assertEqual(check.check_id, "NIST_LOGIN_LOCKOUT")
        self.assertEqual(check.control_id, "AC-7")

    def test_login_banner_check(self):
        check = LoginBannerCheck()
        self.assertEqual(check.check_id, "NIST_LOGIN_BANNER")
        self.assertEqual(check.control_id, "AC-8")

    def test_sysctl_check(self):
        check = SysctlCheck("net.ipv4.tcp_syncookies", "1", "SC-5")
        self.assertEqual(check.check_id, "NIST_SYSCTL_NET_IPV4_TCP_SYNCOOKIES")
        self.assertEqual(check.framework, "NIST")

    def test_time_sync_check(self):
        check = TimeSyncCheck()
        self.assertEqual(check.check_id, "NIST_TIME_SYNC")
        self.assertEqual(check.control_id, "AU-8")

    def test_world_writable_check(self):
        check = WorldWritableCheck()
        self.assertEqual(check.check_id, "NIST_WORLD_WRITABLE_ETC")
        self.assertEqual(check.control_id, "AC-6")


class TestGetNISTChecks(unittest.TestCase):
    def test_all_checks_loaded(self):
        checks = get_nist_checks(["all"])
        self.assertEqual(len(checks), 20)

    def test_category_filter(self):
        fs_checks = get_nist_checks(["filesystem"])
        self.assertEqual(len(fs_checks), 4)

        access_checks = get_nist_checks(["access"])
        self.assertEqual(len(access_checks), 8)

        service_checks = get_nist_checks(["services"])
        self.assertEqual(len(service_checks), 2)

        network_checks = get_nist_checks(["network"])
        self.assertEqual(len(network_checks), 4)

        logging_checks = get_nist_checks(["logging"])
        self.assertEqual(len(logging_checks), 2)

    def test_all_checks_have_nist_framework(self):
        checks = get_nist_checks(["all"])
        for check in checks:
            self.assertEqual(check.framework, "NIST")


if __name__ == '__main__':
    unittest.main()