import unittest
import ghub
import re
from mock import patch

class TestGhubFunctions(unittest.TestCase):
    def test_version(self):
        result = ghub.git_cmd(['version',])
        self.assertRegexpMatches(result, 'git version \d.\d.\d')

    def test_get_console_width(self):
        self.assertGreater(ghub.get_console_width(), 40)

    @patch('ghub.get_console_width', lambda: 80)
    def test_wrap_to_console(self):
        text = (
            """He stared at me in silence for a moment, then said, """
            """Good evening." After that I heard him pacing up and down his """
            """room for quite a while. Then his bed creaked.  Through the """
            """wall there came to me a little wheezing sound, and I guessed """
            """that he was weeping. For some reason, I don't know what, I """
            """began thinking of Mother. But I had to get up early next day; """
            """so, as I wasn't feeling hungry, I did without supper, and went """
            """straight to bed.""")
        result = ghub.wrap_to_console(text)
        for line in result:
            self.assertLess(len(line), 80)
    
    @patch('ghub.git_cmd', lambda x: 'refs/heads/__test__master')
    def test_get_branch(self):
        self.assertEqual(ghub.get_branch(), '__test__master')


class TestGetApiToken(unittest.TestCase):
    def setUp(self):
        self.git_config_token = 'github.__test__.token'
        ghub.git_cmd("config --global".split() + [self.git_config_token, 'foobar'])

    def tearDown(self):
        ghub.git_cmd("config --global --unset".split() + [self.git_config_token])

    def test_get_api_token(self):
        with patch('ghub.GIT_CONFIG_TOKEN', self.git_config_token):
            self.assertEqual(ghub.get_api_token(), 'foobar')
