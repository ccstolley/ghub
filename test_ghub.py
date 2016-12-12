import unittest
import ghub
from StringIO import StringIO
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

    def test_get_user_and_repo(self):
        git_output = ('Fetch URL: git@github.com:ccstolley/ghub\n'
                      'Push  URL: git@github.com:ccstolley/ghub\n'
                      'HEAD branch: (not queried)\n')
        with patch('ghub.git_cmd', lambda x: git_output):
            self.assertEqual(ghub.get_user_and_repo(),
                             ('ccstolley', 'ghub'))

    def test_get_lead_commit(self):
        git_output = (
            '+ 7cec2b67173717c2dab0e62dfc27943851c40618 message\n'
            '+ 2819029108291089090890890890943851c40892 what is\n')
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
    @patch('ghub.get_user_and_repo', lambda x, y: ('user1', 'repo1'))
    def test_get_pull_requests(self, mock_req):
        self.assertEqual(mock_req.return_value, ghub.get_pull_requests())
        mock_req.assert_called_once_with(
            'https://api.github.com/repos/user1/repo1/pulls')

    @patch('ghub.make_github_request')
    @patch('ghub.get_user_and_repo', lambda x, y: ('user1', 'repo1'))
    def test_get_pull_requests__specific_number(self, mock_req):
        self.assertEqual(mock_req.return_value, ghub.get_pull_requests(5))
        mock_req.assert_called_once_with(
            'https://api.github.com/repos/user1/repo1/pulls/5')

    @patch('ghub.make_github_request')
    @patch('ghub.get_user_and_repo', lambda *args: ('user1', 'repo1'))
    def test_get_issues(self, mock_req):
        self.assertEqual(mock_req.return_value, ghub.get_issues())
        mock_req.assert_called_once_with(
            'https://api.github.com/repos/user1/repo1/issues?assignee=user1')

    @patch('ghub.make_github_request')
    @patch('ghub.get_user_and_repo', lambda *args: ('user1', 'repo1'))
    def test_get_issues__specific_number(self, mock_req):
        self.assertEqual(mock_req.return_value, ghub.get_issues('4'))
        mock_req.assert_called_once_with(
            'https://api.github.com/repos/user1/repo1/issues/4')

    @patch('ghub.make_github_request')
    @patch('ghub.get_user_and_repo', lambda *args: ('user1', 'repo1'))
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
            'number':'1', 'title':'pr1', 'user': {'login': 'foo'}}
        ghub.display_pull_requests(verbose=False, number=1)
        self.assertRegexpMatches(mock_print.getvalue(), '#1 pr1')

    @patch('sys.stdout', new_callable=StringIO)
    @patch('ghub.get_issues', lambda x: [])
    def test_display_issues__empty(self, mock_print):
        ghub.display_issues('1')
        self.assertEqual(mock_print.getvalue(), 'No results.\n')

    @patch('sys.stdout', new_callable=StringIO)
    @patch('ghub.get_issues')
    def test_display_issues__number(self, mock_req, mock_print):
        mock_req.return_value = {
            'number':'1', 'title':'issue1', 'user': {'login': 'foo'}}
        ghub.display_issues('1')
        self.assertRegexpMatches(mock_print.getvalue(), '#1 issue1')




class TestGetApiToken(unittest.TestCase):
    def setUp(self):
        self.git_config_token = 'github.__test__.token'
        ghub.git_cmd("config --global".split() + [self.git_config_token, 'foobar'])

    def tearDown(self):
        ghub.git_cmd("config --global --unset".split() + [self.git_config_token])

    def test_get_api_token(self):
        with patch('ghub.GIT_CONFIG_TOKEN', self.git_config_token):
            self.assertEqual(ghub.get_api_token(), 'foobar')