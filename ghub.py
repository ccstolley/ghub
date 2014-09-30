"""
CLI interface to github.

Make sure to run these first:
    git config --global github.token <github personal access token>
    git remote add upstream git@github.com:owner/repo
    git remote add origin git@github.com:username/repo
"""
from operator import itemgetter
import fcntl
import httplib
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
import urllib2

GITHUB_API_URL = 'https://api.github.com'
ORIGIN_LINE_START = 'Push  URL:'
GIT_EXECUTABLE = subprocess.Popen(
    r'which \git', shell=True, stdout=subprocess.PIPE).communicate()[0].strip()


class SafeHTTPSConnection(httplib.HTTPConnection):

    """
    Provide an HTTPS connection which verifies certificate validity.

    Uses default system ca cert files for verification.
    """

    ca_cert_file_locations = (
        '/etc/ssl/cert.pem', '/etc/ssl/certs/ca-certificates.crt',
        '/usr/local/share/certs/ca-root-nss.crt',
        '/etc/ssl/certs/ca-bundle.trust.crt')
    default_port = 443

    def __init__(self, host, port=None, strict=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        """Initialize SafeHTTPSConnection."""
        httplib.HTTPConnection.__init__(self, host, port, strict, timeout)

    def get_ca_certs_file(self):
        """
        Try to find a ca-certificates file in the usual places.

        If a valid certificates file can't be found, the program exits.
        """
        for certsfile in self.ca_cert_file_locations:
            if os.path.isfile(certsfile):
                return certsfile
        print "FATAL: Unable to verify SSL certificate validity."
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


class SafeHTTPSHandler(urllib2.HTTPSHandler):

    def https_open(self, req):
        return self.do_open(SafeHTTPSConnection, req)


opener = urllib2.build_opener(SafeHTTPSHandler)
urllib2.install_opener(opener)


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
    req = urllib2.Request(*args, **kwargs)
    if method:
        req.get_method = lambda: method
    try:
        urlstream = urllib2.urlopen(req)
    except urllib2.HTTPError as e:
        if e.getcode() == 404:
            return []
        print "%d %s" % (e.getcode(), e.geturl())
        print json.dumps(json.loads(e.read()), indent=2)
        raise SystemExit
    except urllib2.URLError as e:
        print e.reason  # probably an ssl error
        raise SystemExit
    content_type = urlstream.headers['content-type']
    data = urlstream.read()
    if verbose:
        print urlstream.headers
        print urlstream.getcode()
        print data
    if content_type.split(';')[0] == ('application/json'):
        return json.loads(data)
    else:
        return data


def get_api_token():
    """Retrieve the API token."""
    token = git_cmd("config --get github.token".split())
    if not token:
        print ("Unable to find github token. Run:\n\t"
               "git config --global github.token <github "
               "personal access token>")
        raise SystemExit
    return token


def get_branch():
    """Get the current local branch."""
    branch_name = git_cmd("symbolic-ref HEAD".split())
    if branch_name:
        return branch_name.strip().replace("refs/heads/", "")
    else:
        print "ERROR: detached HEAD"
        raise SystemExit


def get_repo_and_user(remote_name='origin', alt_name=None):
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
                return line[len(ORIGIN_LINE_START):].strip()

    repo_line = get_repo_line(git_cmd(('remote show -n ' +
                                       remote_name).split()))
    if repo_line.find(':') < 1 and alt_name is not None:
        repo_line = get_repo_line(git_cmd(('remote show -n ' +
                                           alt_name).split()))
    if repo_line.find(':') < 1:
        print ("Unable to find remote repo named '%s'. Run:\n\t"
               "git remote add %s ..." % (remote_name, remote_name))
        raise SystemExit
    else:
        _, user_name_repo = repo_line.split(':')
        while user_name_repo.startswith('/'):
            user_name_repo = user_name_repo[1:]
        user_name, repo = user_name_repo.split('/')
        repo = repo.replace('.git', '')
    return user_name, repo


def get_lead_commit(base_branch):
    """Retreieve the first commit to appear only on this branch."""
    commit = git_cmd(("cherry -v " + base_branch).split())
    if not commit and get_branch() == base_branch:
        commit = git_cmd(("cherry -v").split())
    commit = commit.splitlines()[0].split()
    return (commit[1], ' '.join(commit[2:]))


def get_commit_message_body(commit_sha1):
    """Return commit message body (no subject) for the given sha1."""
    cmd = "log --format=%b -n 1 " + commit_sha1
    return git_cmd(cmd.split())


def get_pull_requests(number):
    """
    Retreive a specific pull request or all pull requests if
    number == None. Return a dictionary or list of dictionaries.
    """
    user, repo = get_repo_and_user('upstream', 'origin')
    url = GITHUB_API_URL + '/repos/%s/%s/pulls' % (user, repo)
    if number:
        url += '/%d' % int(number)
    return make_github_request(url)


def get_issues(filterby):
    """
    Retreive issues from github.

    Filter by either a specific number or assignee. Return a
    dictionary or list of dictionaries.
    """
    upstream_user, repo = get_repo_and_user('upstream', 'origin')
    url = GITHUB_API_URL + '/repos/%s/%s/issues' % (upstream_user, repo)
    if filterby and filterby.isdigit():
        url += '/%d' % int(filterby)
    else:
        if filterby:
            assignee = filterby
        else:
            assignee, _ = get_repo_and_user('origin')
        url += '?assignee=' + urllib2.quote(assignee)
    return make_github_request(url)


def get_pull_request_diff(number):
    """
    Retrieve diff of specified pull request.

    Return a string.
    """
    user, repo = get_repo_and_user('upstream', 'origin')
    url = GITHUB_API_URL + '/repos/%s/%s/pulls/%s' % (user, repo, number)
    return make_github_request(
        url, headers={'accept': 'application/vnd.github.diff'})


def display_pull_requests(verbose=False, number=None):
    """Obtain and display pull requests."""
    pullreqs = get_pull_requests(number)
    if not pullreqs:
        print "Not results."
        return
    if number:
        pullreqs = (pullreqs, )
    for pr in pullreqs:
        print_pull_request(pr, verbose)
        print


def display_issues(filterby, verbose=False):
    """Obtain and display issues."""
    issues = get_issues(filterby)
    if filterby and filterby.isdigit():
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
    reset = '\033[0m'
    fmt_str = '\033[%dm%s'
    text = fmt_str % (colormap[color], text)
    if attrs is not None:
        for attr in attrs:
            text = fmt_str % (attrmap[attr], text)
    return text + reset


def print_tuple(a, b, a_color='white', b_color='white'):
    """Format string arguments a and b for display on screen in two columns."""
    b = b if b is not None else 'None'
    print '%25s : %s' % (
        colored(a, a_color, attrs=['bold']),
        colored(b.encode('ascii', 'replace'), b_color))


def get_pull_request_comments(number):
    """
    Retreive pull request comments and issue comments from the
    specified issue/pr number.
    """
    user, repo = get_repo_and_user('upstream', 'origin')
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
        print


def print_pull_request(pr, verbose):
    """Display pull requests or issues on screen."""
    if verbose:
        print_tuple('Title', '#%s %s' % (pr['number'], pr['title']),
                    b_color='yellow')
        print_tuple('Submitter', pr['user']['login'])
        if 'assignee' in pr:
            print_tuple('Assignee', (pr['assignee'] or {}).get('login'))
        print_tuple('Created At', pr['created_at'])
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
        paragraphs = pr['body'].splitlines()
        for i, par in enumerate(paragraphs):
            if i == 0:
                print_tuple('Body', '')
            for line in wrap_to_console(par):
                print_tuple('', line)
        print
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
    (upstream_user, upstream_repo) = get_repo_and_user('upstream', 'origin')
    (user, _) = get_repo_and_user('origin')
    (sha1, subj) = get_lead_commit(base_branch)
    body = get_commit_message_body(sha1)
    branch = get_branch()
    url = GITHUB_API_URL + '/repos/%s/%s/pulls' % (
        upstream_user, upstream_repo)
    textlines = get_text_from_editor(
        "%s\n\n%s" % (subj, body), list_format=True)
    (subj, body) = textlines[0], '\n'.join(textlines[1:])
    data = json.dumps({'title': subj, 'body': body,
                       'head': ":".join((user, branch)), 'base': base_branch})
    result = make_github_request(url, data,
                                 headers={'content-type': 'application/json'})
    if 'number' in result:
        print "Submitted Pull Request #%d - %s" % (result['number'],
                                                   result['title'])
    else:
        print "Sorry, something bad happened:" + result


def get_text_from_editor(def_text, list_format=False):
    """Run the default text editor and return the text entered."""
    tmp = tempfile.mktemp()
    open(tmp, "w").write(def_text)
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
    (upstream_user, upstream_repo) = get_repo_and_user('upstream', 'origin')
    commit_msg = get_text_from_editor("\n# Enter merge comments for PR %d" %
                                      number)
    if not commit_msg:
        print "No commit message: Aborting."
        raise SystemExit
    data = json.dumps({'commit_message': commit_msg})
    url = GITHUB_API_URL + '/repos/%s/%s/pulls/%d/merge' % (
        upstream_user, upstream_repo, number)
    result = make_github_request(
        url, data, method='PUT', headers={'content-type': 'application/json'})
    if 'merged' in result:
        print "Pull Request #%d: %s" % (number, result['message'])
    else:
        print "Sorry, something bad happened: " + str(result)


def create_issue():
    """
    Create a new issue.

    Open editor and read title from first line and body from
    subsequent lines.
    """
    (upstream_user, upstream_repo) = get_repo_and_user('upstream', 'origin')
    issue_text = get_text_from_editor(
        "\n# Enter issue title on the first line. Lines starting with '#' "
        "\n# will be ignored and an empty message aborts the issue creation.",
        list_format=True)
    if not issue_text:
        print "No issue title: Aborting."
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
        print "Created issue #%d: %s" % (result['number'], result['title'])
    else:
        print "Sorry, something bad happened: " + str(result)


def post_issue_comment(number):
    """
    Post a comment to an issue.

    POST /repos/:owner/:repo/issues/:number/comments
    """
    msg = get_text_from_editor("\n# Enter comments for issue %d" % number)
    if not msg:
        print "No comments: Aborting."
        raise SystemExit
    (upstream_user, upstream_repo) = get_repo_and_user('upstream', 'origin')
    url = GITHUB_API_URL + '/repos/%s/%s/issues/%d/comments' % (
        upstream_user, upstream_repo, number)
    data = json.dumps({'body': msg})
    result = make_github_request(
        url, data, headers={'content-type': 'application/json'})
    if 'body' in result:
        print_pull_request_comments(result)
    else:
        print "Something bad happened: " + str(result)


def assign_issue(number, assignee):
    """
    Assign issue number to assignee.

    PATCH /repos/:owner/:repo/issues/:number
    """
    (upstream_user, upstream_repo) = get_repo_and_user('upstream', 'origin')
    if not assignee:
        (assignee, _) = get_repo_and_user('origin')
    data = json.dumps({'assignee': assignee})
    url = GITHUB_API_URL + '/repos/%s/%s/issues/%d' % (
        upstream_user, upstream_repo, number)
    result = make_github_request(
        url, data, method='PATCH',
        headers={'content-type': 'application/json'})
    if 'assignee' in result:
        print "Assigned # %d to %s" % (result['number'],
                                       result['assignee']['login'])
    else:
        print "Something bad happened: " + str(result)


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
    args = parser.parse_args()

    def _issue_number(optional=False):
        if args.number and args.number.isdigit():
            return int(args.number)
        elif args.number is None and optional:
            return None
        else:
            print "Must specify a numeric issue/PR #"
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
        print get_pull_request_diff(_issue_number())
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

    else:
        parser.print_usage()


if __name__ == '__main__':
    sys.exit(main())
