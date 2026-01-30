import unittest
from checks.linux_cis import FilePermissionCheck

class TestFilePermissionCheck(unittest.TestCase):
    def test_check_creation(self):
        check = FilePermissionCheck("/etc/passwd", "644", "root", "root")
        self.assertEqual(check.check_id, "FILE_PERM_PASSWD")
        self.assertEqual(check.severity, "HIGH")

if __name__ == '__main__':
    unittest.main()