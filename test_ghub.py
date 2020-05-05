import os
import unittest
from io import StringIO
from unittest.mock import patch
import ghub


class TestGhubFunctions(unittest.TestCase):

    def test_version(self):
        result = ghub.git_cmd(['version', ])
        self.assertRegex(result, 'git version \d+.\d+.\d+')

    def test_get_console_width(self):
        # travis tests don't have a console, so console width is 0
        self.assertGreaterEqual(ghub.get_console_width(), 0)

    def test_state_color(self):
        self.assertEqual(ghub.state_color('open'), 'green')
        self.assertEqual(ghub.state_color('closed'), 'red')

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

    def test_remote(self):
        tests = (('git@github.com:ccstolley/ghub',
                 ('ccstolley', 'ghub', 'https://api.github.com')),

                 ('git@sandwich.net:ccstolley/ghub',
                 ('ccstolley', 'ghub', 'https://sandwich.net/api/v3')),

                 ('git@sandwich.net:ccstolley/ghub.git',
                 ('ccstolley', 'ghub', 'https://sandwich.net/api/v3')),

                 ('https://sandwich.net/ccstolley/ghub',
                 ('ccstolley', 'ghub', 'https://sandwich.net/api/v3')),

                 ('ssh://sandwich.net/ccstolley/ghub',
                 ('ccstolley', 'ghub', 'https://sandwich.net/api/v3')),

                 ('git://sandwich.net/ccstolley/ghub',
                 ('ccstolley', 'ghub', 'https://sandwich.net/api/v3')),

                 ('git://github.com/ccstolley/ghub.git',
                 ('ccstolley', 'ghub', 'https://api.github.com')),
                 )

        for git_output, expected in tests:
            with patch('ghub.git_cmd', lambda x: git_output):
                self.assertEqual(ghub.get_remote(), expected)


    def test_get_lead_commit(self):
        git_output = (
            '+ 7cec2b67173717c2dab0e62dfc27943851c40618 message\n'
            '+ 2819029108291089090890890890943851c40892 what is')
        with patch('ghub.git_cmd', lambda x: git_output):
            self.assertEqual(
                ghub.get_lead_commit('master'),
                ('7cec2b67173717c2dab0e62dfc27943851c40618', 'message'))

    @patch('ghub.git_cmd', lambda x: 'foobar\nfoobar2\n')
    def test_get_commit_message_body(self):
        self.assertEqual(
            ghub.get_commit_message_body('23121aed'),
            'foobar\nfoobar2\n')

    @patch('ghub.make_github_request')
    @patch('ghub.git_cmd', lambda x: 'git@github.com:user1/repo1')
    def test_get_pull_requests(self, mock_req):
        self.assertEqual(mock_req.return_value, ghub.get_pull_requests())
        mock_req.assert_called_once_with(
            'https://api.github.com/repos/user1/repo1/pulls?state=open')

    @patch('ghub.make_github_request')
    @patch('ghub.git_cmd', lambda x: 'git@github.com:user1/repo1')
    def test_get_pull_requests__specific_number(self, mock_req):
        self.assertEqual(mock_req.return_value, ghub.get_pull_requests(5))
        mock_req.assert_called_once_with(
            'https://api.github.com/repos/user1/repo1/pulls/5')

    @patch('ghub.make_github_request')
    @patch('ghub.git_cmd', lambda x: 'git@github.com:user1/repo1')
    def test_get_issues(self, mock_req):
        self.assertEqual(mock_req.return_value, ghub.get_issues())
        mock_req.assert_called_once_with(
            'https://api.github.com/repos/user1/repo1/issues?filter=all&state=open')

    @patch('ghub.make_github_request')
    @patch('ghub.git_cmd', lambda x: 'git@github.com:user1/repo1')
    def test_get_issues__specific_number(self, mock_req):
        self.assertEqual(mock_req.return_value, ghub.get_issues('4'))
        mock_req.assert_called_once_with(
            'https://api.github.com/repos/user1/repo1/issues/4')

    @patch('ghub.make_github_request')
    @patch('ghub.git_cmd', lambda x: 'git@github.com:user1/repo1')
    def test_get_pull_request_diff(self, mock_req):
        self.assertEqual(mock_req.return_value, ghub.get_pull_request_diff(4))
        mock_req.assert_called_once_with(
            'https://api.github.com/repos/user1/repo1/pulls/4',
            headers={'accept': 'application/vnd.github.diff'})

    @patch('sys.stdout', new_callable=StringIO)
    @patch('ghub.get_pull_requests', lambda x: None)
    def test_display_pull_requests__empty(self, mock_print):
        ghub.display_pull_requests(1)
        self.assertEqual(mock_print.getvalue(), 'No results.\n')

    @patch('sys.stdout', new_callable=StringIO)
    @patch('ghub.get_pull_requests')
    def test_display_pull_requests__number(self, mock_req, mock_print):
        mock_req.return_value = {
            'number': '1',
            'title': 'pr1',
            'html_url': 'foo',
            'user': {'login': 'foo'},
            'assignee': None}
        ghub.display_pull_requests(verbose=False, number=1)
        self.assertRegex(mock_print.getvalue(), '#1 pr1')

    @patch('sys.stdout', new_callable=StringIO)
    @patch('ghub.get_issues', lambda x: [])
    def test_display_issues__empty(self, mock_print):
        ghub.display_issues('1')
        self.assertEqual(mock_print.getvalue(), 'No results.\n')

    @patch('sys.stdout', new_callable=StringIO)
    @patch('ghub.get_issues')
    def test_display_issues__number(self, mock_req, mock_print):
        print(mock_req)
        mock_req.return_value = {
            'number': '1',
            'title': 'issue1',
            'html_url': 'foo',
            'user': {'login': 'foo'},
            'assignee': None}
        ghub.display_issues('1')
        self.assertRegex(mock_print.getvalue(), '#1 issue1')


TEST_TOKEN_PATH = '/tmp/zzaaaTESTGHUB'


@patch('ghub.secret_file_path', lambda: TEST_TOKEN_PATH)
@patch('ghub.__fallback_get_api_token', lambda: None)
class TestGetApiToken(unittest.TestCase):

    @patch('ghub.secret_file_path', lambda: TEST_TOKEN_PATH)
    def tearDown(self):
        if os.path.exists(TEST_TOKEN_PATH):
            os.remove(TEST_TOKEN_PATH)

    def test_stash_api_token(self):
        ghub.stash_api_token('atesttoken')
        self.assertEqual(ghub.get_api_token(), 'atesttoken')

    def test_unstash_api_token(self):
        with open(TEST_TOKEN_PATH, 'w') as f:
            f.write('testunstash')
        ghub.unstash_api_token()
        self.assertFalse(os.path.exists(TEST_TOKEN_PATH))


@patch('ghub.secret_file_path', lambda: TEST_TOKEN_PATH)
class TestGetApiTokenFallback(unittest.TestCase):

    def tearDown(self):
        ghub.git_cmd("config --global --remove-section github.__testghub__".split())
        if os.path.exists(TEST_TOKEN_PATH):
            os.remove(TEST_TOKEN_PATH)

    def test_get_api_token__fallback(self):
        self.git_config_token = 'github.__testghub__.token'
        ghub.git_cmd("config --global".split() + [self.git_config_token, 'foobar'])
        with patch('ghub.GIT_CONFIG_TOKEN', self.git_config_token):
            self.assertEqual(ghub.get_api_token(), 'foobar')
