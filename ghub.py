#!/usr/bin/env python3

"""
CLI interface to github.

Make sure to run these first:
    git config --global github.token <github personal access token>
    git remote add upstream git@github.com:owner/repo
    git remote add origin git@github.com:username/repo
"""
from operator import itemgetter
import fcntl
import http.client
import json
import os
import socket
import ssl
import struct
import sys
import subprocess
import tempfile
import termios
import textwrap
import urllib.request, urllib.error, urllib.parse

GITHUB_API_URL = u'https://api.github.com'
ORIGIN_LINE_START = b'Push  URL:'
GIT_EXECUTABLE = subprocess.Popen(
    r'which \git', shell=True, stdout=subprocess.PIPE).communicate()[0].strip()
GIT_CONFIG_TOKEN = 'github.token'


class SafeHTTPSConnection(http.client.HTTPConnection):

    """
    Provide an HTTPS connection which verifies certificate validity.

    Uses default system ca cert files for verification.
    """

    ca_cert_file_locations = (
        '/etc/ssl/cert.pem', '/etc/ssl/certs/ca-certificates.crt',
        '/usr/local/share/certs/ca-root-nss.crt',
        '/etc/ssl/certs/ca-bundle.trust.crt',
        '/usr/local/etc/openssl/cert.pem')
    default_port = 443

    def __init__(self, host, port=None, strict=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        """Initialize SafeHTTPSConnection."""
        http.client.HTTPConnection.__init__(self, host, port, strict, timeout)

    def get_ca_certs_file(self):
        """
        Try to find a ca-certificates file in the usual places.

        If a valid certificates file can't be found, the program exits.
        """
        for certsfile in self.ca_cert_file_locations:
            if os.path.isfile(certsfile):
                return certsfile
        print("FATAL: Unable to verify SSL certificate validity.")
        raise SystemExit

    def connect(self):
        """Connect to a host on a given (SSL) port."""
        sock = socket.create_connection((self.host, self.port), self.timeout)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(
            sock, ca_certs=self.get_ca_certs_file(),
            cert_reqs=ssl.CERT_REQUIRED)


class SafeHTTPSHandler(urllib.request.HTTPSHandler):

    def https_open(self, req):
        return self.do_open(SafeHTTPSConnection, req)


opener = urllib.request.build_opener(SafeHTTPSHandler)
urllib.request.install_opener(opener)


def git_cmd(args):
    """Execute git with the supplied arguments."""
    result, _ = subprocess.Popen(
        [GIT_EXECUTABLE, ] + args, shell=False, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE).communicate()
    return result.strip()


def get_console_width():
    """Obtain the current width of the console window."""
    result = struct.unpack('hhhh', fcntl.ioctl(
        0, termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0)))
    return result[1]


def wrap_to_console(text):
    """Wrap text to console width."""
    width = max(get_console_width() - 16, 52)
    return textwrap.wrap(text, width, replace_whitespace=False,
                         break_long_words=False, break_on_hyphens=False)


def make_github_request(*args, **kwargs):
    """Send an authorization token in a github api request."""
    token = get_api_token()
    method = kwargs.pop('method', None)
    verbose = kwargs.pop('verbose', None)
    kwargs.setdefault('headers', {}).update(
        {'Authorization': 'token %s' % token,
         'User-agent': 'ccstolley-ghub'})
    req = urllib.request.Request(*args, **kwargs)
    if method:
        req.get_method = lambda: method
    try:
        urlstream = urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        if e.getcode() == 404:
            return []
        print("%d %s" % (e.getcode(), e.geturl()))
        print(json.dumps(json.loads(e.read().decode('utf8')), indent=2))
        raise SystemExit
    except urllib.error.URLError as e:
        print(e.reason)  # probably an ssl error
        raise SystemExit
    content_type = urlstream.headers['content-type']
    data = urlstream.read()
    if verbose:
        print(urlstream.headers)
        print(urlstream.getcode())
        print(data)
    if content_type.split(';')[0] == ('application/json'):
        return json.loads(data.decode('utf8'), encoding='utf8')
    else:
        return data.decode('utf8')


def get_api_token():
    """Retrieve the API token."""
    token = git_cmd("config --get".split() + [GIT_CONFIG_TOKEN])
    if not token:
        print ("Unable to find github token. Run:\n\t"
               "git config --global github.token <github "
               "personal access token>")
        raise SystemExit
    return token.decode('utf8')


def get_branch():
    """Get the current local branch."""
    branch_name = git_cmd("symbolic-ref HEAD".split()).decode('utf8')
    if branch_name:
        return branch_name.strip().replace("refs/heads/", "")
    else:
        print("ERROR: detached HEAD")
        raise SystemExit


def get_user_and_repo(remote_name='origin', alt_name=None):
    """
    Retrieve the repo and user for the specified remote name.

    Typical values are 'upstream' and 'origin'. If alt_name is
    supplied, use it as an alternative repo name if remote_name is
    not found.
    """
    def get_repo_line(cmd_output):
        for line in cmd_output.splitlines():
            line = line.strip()
            if line.startswith(ORIGIN_LINE_START):
                return line[len(ORIGIN_LINE_START):].strip().decode('utf8')

    repo_line = get_repo_line(git_cmd(('remote show -n ' +
                                       remote_name).split()))
    if repo_line.find(':') < 1 and alt_name is not None:
        repo_line = get_repo_line(git_cmd(('remote show -n ' +
                                           alt_name).split()))
    if repo_line.find(':') < 1:
        print(("Unable to find remote repo named '%s'. Run:\n\t"
               "git remote add %s ..." % (remote_name, remote_name)))
        raise SystemExit
    else:
        _, user_name_repo = repo_line.split(':')
        while user_name_repo.startswith('/'):
            user_name_repo = user_name_repo[1:]
        user_name, repo = user_name_repo.split('/')[-2:]
        repo = repo.replace('.git', '')
    return user_name, repo


def get_lead_commit(base_branch):
    """Retreieve the first commit to appear only on this branch."""
    commit = git_cmd(("cherry -v " + base_branch).split()).decode('utf8')
    if not commit and get_branch() == base_branch:
        commit = git_cmd(("cherry -v HEAD~1").split()).decode('utf8')
    commit = commit.splitlines()[0].split()
    return (commit[1], ' '.join(commit[2:]))


def get_commit_message_body(commit_sha1):
    """Return commit message body (no subject) for the given sha1."""
    cmd = "log --format=%b -n 1 " + commit_sha1
    return git_cmd(cmd.split()).decode('utf8')


def get_pull_requests(number=None):
    """
    Retreive a specific pull request or all pull requests if
    number == None. Return a dictionary or list of dictionaries.
    """
    user, repo = get_user_and_repo('upstream', 'origin')
    url = GITHUB_API_URL + '/repos/%s/%s/pulls' % (user, repo)
    if number:
        url += '/%d' % int(number)
    return make_github_request(url)


def get_reviews(number):
    """
    Retreive reviews for a specific pull request.
    Returns a list of dicts.
    """
    user, repo = get_user_and_repo('upstream', 'origin')
    url = GITHUB_API_URL + '/repos/%s/%s/pulls/%d/reviews' % (user, repo, int(number))
    return make_github_request(url)


def get_issues(filterby=None):
    """
    Retreive issues from github.

    Filter by either a specific number or assignee. Return a
    dictionary or list of dictionaries.
    """
    upstream_user, repo = get_user_and_repo('upstream', 'origin')
    url = GITHUB_API_URL + '/repos/%s/%s/issues' % (upstream_user, repo)
    if filterby and filterby.isdigit():
        url += '/%d' % int(filterby)
    else:
        if filterby:
            assignee = filterby
        else:
            assignee, _ = get_user_and_repo('origin')
        url += '?assignee=' + urllib.parse.quote(assignee)
    return make_github_request(url)


def get_pull_request_diff(number):
    """
    Retrieve diff of specified pull request.

    Return a string.
    """
    user, repo = get_user_and_repo('upstream', 'origin')
    url = GITHUB_API_URL + '/repos/%s/%s/pulls/%s' % (user, repo, number)
    return make_github_request(
        url, headers={'accept': 'application/vnd.github.diff'})


def display_pull_requests(verbose=False, number=None):
    """Obtain and display pull requests."""
    pullreqs = get_pull_requests(number)
    if not pullreqs:
        print("No results.")
        return
    if number:
        pullreqs = (pullreqs, )

    for pr in pullreqs:
        print_pull_request(pr, verbose)
        print()


def display_issues(filterby, verbose=False):
    """Obtain and display issues."""
    issues = get_issues(filterby)
    if not issues:
        print("No results.")
        return
    if filterby and str(filterby).isdigit():
        issues = (issues, )
    for issue in issues:
        print_pull_request(issue, verbose)


def colored(text, color, attrs=None):
    """Colorize specified text."""
    colormap = dict(zip(
        ['grey', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan',
         'white', ], range(30, 38)))
    attrmap = dict(zip(
        ['bold', 'dark', '', 'underline', 'blink', '', 'reverse', 'concealed'],
        range(1, 9)))
    reset = u'\033[0m'
    fmt_str = u'\033[%dm%s'
    text = fmt_str % (colormap[color], text)
    if attrs is not None:
        for attr in attrs:
            text = fmt_str % (attrmap[attr], text)
    return text + reset


def print_tuple(a, b, a_color='white', b_color='white'):
    """Format string arguments a and b for display on screen in two columns."""
    b = b if b is not None else 'None'
    print(u'%25s : %s' % (
        colored(a, a_color, attrs=['bold']),
        colored(b, b_color)))


def get_pull_request_comments(number):
    """
    Retreive pull request comments and issue comments from the
    specified issue/pr number.
    """
    user, repo = get_user_and_repo('upstream', 'origin')
    url = GITHUB_API_URL + '/repos/%s/%s/issues/%d/comments' % (
        user, repo, number)
    issue_comments = make_github_request(url)
    url = GITHUB_API_URL + '/repos/%s/%s/pulls/%d/comments' % (
        user, repo, number)
    pull_comments = make_github_request(url)
    return sorted(issue_comments + pull_comments, key=itemgetter('created_at'))


def print_pull_request_comments(comment_obj):
    """Obtain and display pr comments on the console."""
    if isinstance(comment_obj, int):
        comments = get_pull_request_comments(comment_obj)
    else:
        comments = (comment_obj, )
    for comment in comments:
        paragraphs = comment['body'].splitlines()
        for i, par in enumerate(paragraphs):
            wrapped_body = wrap_to_console(par)
            if i == 0:
                print_tuple(comment['user']['login'][:12], wrapped_body.pop(0),
                            a_color='cyan')
            for line in wrapped_body:
                print_tuple('', line)
        print()


def print_pull_request(pr, verbose, reviews=None):
    """Display pull requests or issues on screen."""
    if verbose:
        print_tuple('Title', '#%s %s' % (pr['number'], pr['title']),
                    b_color='yellow')
        print_tuple('Submitter', pr['user']['login'])
        if 'assignee' in pr and pr['assignee']:
            print_tuple('Assignee', (pr['assignee'] or {}).get('login'))
        print_tuple('Created At', pr['created_at'])
        # tack on reviews
        reviews = {(review['user']['login'], review['state'])
                   for review in get_reviews(pr['number'])}
        for user, state in reviews:
            state = state.title()
            if state == 'Approved':
                state = colored(state, 'green')
            else:
                state = colored(state, 'magenta')
            print_tuple('Review', '{} by {}'.format(state, user))
        if 'mergeable' in pr:
            if pr['merged']:
                mergelabel = ('Already merged', 'white', 'magenta')
            elif pr['mergeable']:
                mergelabel = ('Yes', 'white', 'green')
            else:
                mergelabel = ('No', 'white', 'red')
            print_tuple('Mergable', *mergelabel)
        print_tuple('URL', pr['html_url'])
        if 'commits' in pr:
            adds = colored("+%d" % pr['additions'], 'green')
            dels = colored("-%d" % pr['deletions'], 'red')
            print_tuple('Commits', "%d (%s, %s)" % (
                pr['commits'], adds, dels))
        # Added this condition in case a user does not enter any info to the body.
        if pr['body']:
            paragraphs = pr['body'].splitlines()
            for i, par in enumerate(paragraphs):
                if i == 0:
                    print_tuple('Body', '')
                for line in wrap_to_console(par):
                    print_tuple('', line)
        else:
            print("There is no description to this issue")
        print()
        print_pull_request_comments(pr['number'])
    else:
        print_tuple(pr['user']['login'][:12],
                    wrap_to_console('#%s %s' % (pr['number'], pr['title']))[0],
                    a_color='cyan')


def create_pull_request(base_branch):
    """
    Create a new pull request from the commits in the current branch against
    the supplied base branch in upstream.
    """
    (upstream_user, upstream_repo) = get_user_and_repo('upstream', 'origin')
    (user, _) = get_user_and_repo('origin')
    (sha1, subj) = get_lead_commit(base_branch)
    body = get_commit_message_body(sha1)
    branch = get_branch()
    url = GITHUB_API_URL + '/repos/%s/%s/pulls' % (
        upstream_user, upstream_repo)
    textlines = get_text_from_editor(
        "%s\n\n%s" % (subj, body), list_format=True)
    (subj, body) = textlines[0], '\n'.join(textlines[1:])
    data = json.dumps({'title': subj, 'body': body,
                       'head': ":".join((user, branch)), 'base': base_branch}).encode('utf8')
    result = make_github_request(url, data,
                                 headers={'content-type': 'application/json'})
    if 'number' in result:
        print("Submitted Pull Request #%d - %s" % (result['number'],
                                                   result['title']))
        print(result['html_url'])
    else:
        print("Sorry, something bad happened:" + result)


def get_text_from_editor(def_text, list_format=False):
    """Run the default text editor and return the text entered."""
    tmp = tempfile.mktemp()
    open(tmp, "w", encoding='utf8').write(def_text)
    editor = os.environ.get("EDITOR", "vim")
    os.system("%s %s" % (editor, tmp))
    if list_format:
        return [k.rstrip() for k in open(tmp).read().splitlines()
                if not (k.startswith("#") or k.rstrip() == '')]
    else:
        return "\n".join([k.rstrip() for k in open(tmp).read().splitlines()
                          if not (k.startswith("#") or k.rstrip() == '')])


def merge_pull_request(number):
    """Prompt for a comment and merge specified pull request."""
    (upstream_user, upstream_repo) = get_user_and_repo('upstream', 'origin')
    commit_msg = get_text_from_editor("\n# Enter merge comments for PR %d" %
                                      number)
    if not commit_msg:
        print("No commit message: Aborting.")
        raise SystemExit
    data = json.dumps({'commit_message': commit_msg}).encode('utf8')
    url = GITHUB_API_URL + '/repos/%s/%s/pulls/%d/merge' % (
        upstream_user, upstream_repo, number)
    result = make_github_request(
        url, data, method='PUT', headers={'content-type': 'application/json'})
    if 'merged' in result:
        print("Pull Request #%d: %s" % (number, result['message']))
    else:
        print("Sorry, something bad happened:", result)


def approve_pull_request(number):
    """
    Submit "approve" review for given PR number.
    """
    (upstream_user, upstream_repo) = get_user_and_repo('upstream')
    (reviewer, _) = get_user_and_repo('origin')
    reviews = {review['user']['login'] for review in get_reviews(number) if review['state'] == 'APPROVED'}
    if reviewer in reviews:
        # github lets you approve multiple times?
        print('You already approved PR', number)
        return
    data = json.dumps({'event': 'APPROVE'}).encode('utf8')
    url = GITHUB_API_URL + '/repos/%s/%s/pulls/%d/reviews' % (
        upstream_user, upstream_repo, number)
    result = make_github_request(
        url, data, method='POST', headers={'content-type': 'application/json'})
    if result and result.get('state') == 'APPROVED':
        print('PR #{} approved.'.format(colored(number, 'yellow')))
    else:
        print('ERROR: unable to approve PR', number, result)


def review_pull_request(number, reviewers_str):
    """
    Request review by 1 or more logins.
    """
    reviewers = reviewers_str.split(',')
    upstream_user, upstream_repo = get_user_and_repo('upstream')
    data = json.dumps({'reviewers': reviewers}).encode('utf8')
    url = GITHUB_API_URL + '/repos/%s/%s/pulls/%d/requested_reviewers' % (
        upstream_user, upstream_repo, number)
    result = make_github_request(
        url, data, method='POST', headers={'content-type': 'application/json'})
    if result and 'requested_reviewers' in result:
        confirmed_reviewers = ','.join(r['login'] for r in result['requested_reviewers'])
        print("Reviews requested from", confirmed_reviewers)
    else:
        print("Unable to request reviews:", result)

def create_issue():
    """
    Create a new issue.

    Open editor and read title from first line and body from
    subsequent lines.
    """
    (upstream_user, upstream_repo) = get_user_and_repo('upstream', 'origin')
    issue_text = get_text_from_editor(
        "\n# Enter issue title on the first line. Lines starting with '#' "
        "\n# will be ignored and an empty message aborts the issue creation.",
        list_format=True)
    if not issue_text:
        print("No issue title: Aborting.")
        raise SystemExit
    data = {'title': issue_text.pop(0)}
    if issue_text:
        data['body'] = '\n'.join(issue_text)
    data = json.dumps(data)
    url = GITHUB_API_URL + '/repos/%s/%s/issues' % (
        upstream_user, upstream_repo)
    result = make_github_request(
        url, data, headers={'content-type': 'application/json'})
    if 'title' in result:
        print("Created issue #%d: %s" % (result['number'], result['title']))
    else:
        print("Sorry, something bad happened: " + str(result))


def post_issue_comment(number):
    """
    Post a comment to an issue.

    POST /repos/:owner/:repo/issues/:number/comments
    """
    msg = get_text_from_editor("\n# Enter comments for issue %d" % number)
    if not msg:
        print("No comments: Aborting.")
        raise SystemExit
    (upstream_user, upstream_repo) = get_user_and_repo('upstream', 'origin')
    url = GITHUB_API_URL + '/repos/%s/%s/issues/%d/comments' % (
        upstream_user, upstream_repo, number)
    data = json.dumps({'body': msg})
    result = make_github_request(
        url, data, headers={'content-type': 'application/json'})
    if 'body' in result:
        print_pull_request_comments(result)
    else:
        print("Something bad happened: " + str(result))


def assign_issue(number, assignee):
    """
    Assign issue number to assignee.

    PATCH /repos/:owner/:repo/issues/:number
    """
    (upstream_user, upstream_repo) = get_user_and_repo('upstream', 'origin')
    if not assignee:
        (assignee, _) = get_user_and_repo('origin')
    data = json.dumps({'assignee': assignee})
    url = GITHUB_API_URL + '/repos/%s/%s/issues/%d' % (
        upstream_user, upstream_repo, number)
    result = make_github_request(
        url, data, method='PATCH',
        headers={'content-type': 'application/json'})
    if 'assignee' in result:
        print("Assigned # %d to %s" % (result['number'],
                                       result['assignee']['login']))
    else:
        print("Something bad happened: " + str(result))


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='command line interface to github')
    parser.add_argument("number", nargs='?', type=str,
                        help="optional issue/PR number/login")
    parser.add_argument(
        '-i', '--showissue', action="store_true",
        help='show issue #, or show all for specified user')
    parser.add_argument(
        '-p', '--showpull', action="store_true",
        help='show pull request # or show all')
    parser.add_argument(
        '-d', '--diff', action="store_true",
        help='show diff for pull request #')
    parser.add_argument(
        '-n', '--newpull',
        help='create a new pull request from the current '
        'branch to base_branch', metavar='base', nargs=1)
    parser.add_argument(
        '-m', '--mergepull', help='merge pull request #', action="store_true")
    parser.add_argument(
        '-c', '--comment', help='post comment on issue #',
        action="store_true")
    parser.add_argument(
        '-o', '--openissue', help='create a new issue', action='store_true')
    parser.add_argument(
        '-a', '--assign', help='assign an issue to login', metavar='login',
        nargs='?', type=str, default='')
    parser.add_argument(
        '-v', '--verbose', help='be verbose', action='store_true')
    parser.add_argument(
        '-ok', '--approve', help='approve pull request #', action='store_true')
    parser.add_argument(
        '-r', '--review', help='request review from login(s)', nargs='?', metavar='login[,login2]',
        type=str, default='')
    args = parser.parse_args()

    def _issue_number(optional=False):
        if args.number and args.number.isdigit():
            return int(args.number)
        elif args.number is None and optional:
            return None
        else:
            print("Must specify a numeric issue/PR #")
            parser.print_usage()
            raise SystemExit

    if args.showpull:
        display_pull_requests(number=_issue_number(optional=True),
                              verbose=args.verbose or args.number)
    elif args.showissue:
        display_issues(filterby=args.number,
                       verbose=args.verbose or (
                           args.number and args.number.isdigit()))
    elif args.diff:
        print(get_pull_request_diff(_issue_number()))
    elif args.newpull:
        create_pull_request(args.newpull[0])
    elif args.mergepull:
        merge_pull_request(_issue_number())
    elif args.comment:
        post_issue_comment(_issue_number())
    elif args.openissue:
        create_issue()
    elif args.assign:
        if not args.number:
            (args.number, args.assign) = (args.assign, None)
        assign_issue(_issue_number(), args.assign)
    elif args.approve:
        approve_pull_request(_issue_number())
    elif args.review:
        review_pull_request(_issue_number(), args.review)
    else:
        parser.print_usage()


if __name__ == '__main__':
    sys.exit(main())
