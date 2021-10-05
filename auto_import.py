#!/usr/bin/env python3
import argparse
import datetime
import hashlib
import logging
import os
import pickle
import re
import subprocess
import sys
from collections import defaultdict

PRELOADED_IMPORTS_DB = {}
PRELOADED_IMPORTS_DB.update(
    {std_module: (None, std_module, None) for std_module in [
        'abc', 'aifc', 'argparse', 'array', 'ast', 'asynchat', 'asyncio', 'asyncore', 'atexit', 'audioop', 'base64',
        'bdb', 'binascii', 'binhex', 'bisect', 'builtins', 'bz2', 'calendar', 'cgi', 'cgitb', 'chunk', 'cmath', 'cmd',
        'code', 'codecs', 'codeop', 'collections', 'colorsys', 'compileall', 'concurrent', 'configparser', 'contextlib',
        'contextvars', 'copy', 'copyreg', 'cProfile', 'crypt', 'csv', 'ctypes', 'curses', 'dataclasses', 'datetime',
        'dbm', 'decimal', 'difflib', 'dis', 'distutils', 'doctest', 'dummy_threading', 'email', 'encodings',
        'ensurepip', 'enum', 'errno', 'faulthandler', 'fcntl', 'filecmp', 'fileinput', 'fnmatch', 'formatter',
        'fractions', 'ftplib', 'functools', 'gc', 'getopt', 'getpass', 'gettext', 'glob', 'grp', 'gzip', 'hashlib',
        'heapq', 'hmac', 'html', 'http', 'imaplib', 'imghdr', 'imp', 'importlib', 'inspect', 'io', 'ipaddress',
        'itertools', 'json', 'keyword', 'lib2to3', 'linecache', 'locale', 'logging', 'lzma', 'macpath', 'mailbox',
        'mailcap', 'marshal', 'math', 'mimetypes', 'mmap', 'modulefinder', 'msilib', 'msvcrt', 'multiprocessing',
        'netrc', 'nis', 'nntplib', 'numbers', 'operator', 'optparse', 'os', 'ossaudiodev', 'parser', 'pathlib', 'pdb',
        'pickle', 'pickletools', 'pipes', 'pkgutil', 'platform', 'plistlib', 'poplib', 'posix', 'pprint', 'profile',
        'pstats', 'pty', 'pwd', 'py_compile', 'pyclbr', 'pydoc', 'queue', 'quopri', 'random', 're', 'readline',
        'reprlib', 'resource', 'rlcompleter', 'runpy', 'sched', 'secrets', 'select', 'selectors', 'shelve', 'shlex',
        'shutil', 'signal', 'site', 'smtpd', 'smtplib', 'sndhdr', 'socket', 'socketserver', 'spwd', 'sqlite3', 'ssl',
        'stat', 'statistics', 'string', 'stringprep', 'struct', 'subprocess', 'sunau', 'symbol', 'symtable', 'sys',
        'sysconfig', 'syslog', 'tabnanny', 'tarfile', 'telnetlib', 'tempfile', 'termios', 'test', 'textwrap',
        'threading', 'time', 'timeit', 'tkinter', 'token', 'tokenize', 'trace', 'traceback', 'tracemalloc', 'tty',
        'turtle', 'turtledemo', 'types', 'typing', 'unicodedata', 'unittest', 'urllib', 'uu', 'uuid', 'venv',
        'warnings', 'wave', 'weakref', 'webbrowser', 'winreg', 'winsound', 'wsgiref', 'xdrlib', 'xml', 'xmlrpc',
        'zipapp', 'zipfile', 'zipimport', 'zlib',
    ]}
)
PRELOADED_IMPORTS_DB.update({
    'timedelta': ('datetime', 'timedelta', None),
    'defaultdict': ('collections', 'defaultdict', None),
    'deque': ('collections', 'deque', None),
    'namedtuple': ('collections', 'namedtuple', None),
    'OrderedDict': ('collections', 'OrderedDict', None),

    'np': (None, 'numpy', 'np'),
    'numpy': (None, 'numpy', None),
    'pd': (None, 'pandas', 'pd'),
    'pytz': (None, 'pytz', None),
    'requests': (None, 'requests', None),
    'six': (None, 'six', None),
})


def get_command_output(cmd, stdin=None, cwd=None):
    raw_output, raw_error = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd
    ).communicate(stdin)
    if raw_error:
        cmd_rendered = ' '.join(cmd)
        logging.warning('Error when running command `{}`{}: "{}"{}'.format(
            cmd_rendered[:200],
            '[... command truncated]' if len(cmd_rendered) > 200 else '',
            raw_error[:200],
            '[... error truncated]' if len(raw_error) > 200 else '',
        ))
    return raw_output.decode('utf-8')


def get_valid_filename(s):
    """
    Credit: Django Project
    License: 3 Clause BSD https://github.com/django/django/blob/c7cc7526d5ee7d38a6ee1af03610f1aba1ea0c78/LICENSE
    """
    s = str(s).strip().replace(' ', '_')
    return re.sub(r'(?u)[^-\w.]', '', s)


def module_path_join(modules):
    return '.'.join([module.strip('.') for module in modules if module])


def construct_import_statement(terms):
    statement = ''
    if terms[0]:
        statement += 'from {} '.format(terms[0])
    if terms[1]:
        statement += 'import {} '.format(terms[1])
    if terms[2]:
        statement += 'as {} '.format(terms[2])
    return statement.strip()


def parse_import_statement(statement):
    """
        Returns [(imported_name, terms)], where terms is a tuple describing an import statement's properties:
        (import_base, import_name, import_alias)
    """
    match = re.search(
        r'(?:from ([a-zA-Z_0-9 .,]+) )?'
        r'import \(?((?:[a-zA-Z_0-9]+(?:, )?)+)\)?'
        r'(?: as ([a-zA-Z_0-9.]+))?',
        statement
    )
    if not match:
        raise RuntimeError('Failed to parse import statement: ' + statement)
    import_base = match.group(1) if match.group(1) else None
    import_list = [term.strip() for term in match.group(2).split(',')]
    import_alias = match.group(3) if match.group(3) else None
    if import_alias:
        return [(import_alias, (import_base, import_list[0], import_alias))]
    return [(term, (import_base, term, import_alias)) for term in import_list]


def build_imports_database(project_root_path):
    import_freq_db = defaultdict(lambda: defaultdict(lambda: 0))

    # Preload some common import statements from the built-in DB
    import_freq_db.update({
        name: defaultdict(lambda: 0, [(terms, 0)]) for name, terms in PRELOADED_IMPORTS_DB.items()
    })

    # Scan your current project's codebase for import statement patterns, to see how you commonly import different
    # names.
    # (Outsources the core file regex searching to a highly optimized utility.)
    if project_root_path is not None:
        ag_output = get_command_output(
            ['ag', '--python', '--nonumbers', '--noheading', '--nofilename', '--nobreak',
            r'^(?:from [a-zA-Z_0-9 .,]+ )?import \(?[a-zA-Z_0-9 ,]+\)?', project_root_path])

        for line in ag_output.split('\n'):
            if not line:
                continue
            for imported_name, terms in parse_import_statement(line):
                import_freq_db[imported_name][terms] += 1
                logging.debug('Found an import pattern for {}'.format(imported_name))

    # Convert the temporary database of input patterns + their frequency to a simplified database which only provides
    # each name's single most frequently used input pattern.
    import_db = dict()
    for name, imports_dict in import_freq_db.items():
        most_frequent_import_for_name = max(
            imports_dict.items(), key=lambda item: item[1])[0]
        import_db[name] = most_frequent_import_for_name
    return import_db


def get_imports_database(project_root_path):
    DATABASE_CACHE_EXPIRY = datetime.timedelta(minutes=15)
    DATABASE_CACHES_PATH = os.path.join(
        os.environ.get('XDG_CACHE_HOME', os.path.expanduser('~/.cache')),
        'py_auto_import',
        'db_cache',
    )
    if project_root_path is None:
        project_root_path_str = 'none'
    else:
        project_root_path_str = project_root_path
    root_path_hash = hashlib.md5(project_root_path_str.encode('utf-8')).hexdigest()
    cache_path = os.path.join(
        DATABASE_CACHES_PATH,
        get_valid_filename(os.path.basename(project_root_path_str) + '_' + root_path_hash) + '.pickle'
    )

    if os.path.exists(cache_path):
        cache_mtime = datetime.datetime.utcfromtimestamp(os.path.getmtime(cache_path))
        if (datetime.datetime.now() - cache_mtime) < DATABASE_CACHE_EXPIRY:
            logging.debug('Using cached imports db {}'.format(cache_path))
            with open(cache_path, 'rb') as cache_file:
                return pickle.load(cache_file)

    db = build_imports_database(project_root_path)
    os.makedirs(DATABASE_CACHES_PATH, exist_ok=True)
    logging.debug('Writing imports db cache {}'.format(cache_path))
    with open(cache_path, 'wb') as cache_file:
        pickle.dump(db, cache_file)
    return db


def get_project_root_path(code_base_dir):
    if code_base_dir is None:
        return None
    try:
        git_repo_root = get_command_output(['git', 'rev-parse', '--show-toplevel'], cwd=code_base_dir).strip()
        if git_repo_root:
            return git_repo_root
    except FileNotFoundError:
        pass

    return code_base_dir


def get_undefined_references(code):
    # Use Pyflakes to get undefined references.
    linter_report = get_command_output(
        ['/usr/bin/env', 'python3', '-m', 'pyflakes'], stdin=code.encode('utf-8'))

    undefined_references = set()
    for report_line in set(linter_report.split('\n')):
        if not report_line:
            continue
        match = re.search(r'undefined name \'([^\']+)\'', report_line)
        if not match:
            continue
        undefined_references.add(match.group(1))

    return undefined_references


def get_unused_import_statements_with_fixes(code):
    """
        returns (unused_import_lines, unused_import_fix_statements)
    """
    # Use Pyflakes to get unused imports.
    linter_report = get_command_output(
        ['/usr/bin/env', 'python3', '-m', 'pyflakes'], stdin=code.encode('utf-8'))

    code_lines = code.split('\n')
    unused_import_lines = []
    expanded_import_terms = set()
    unused_module_names = set()
    # For every linter error, expand the import terms from that line, make a note to delete the entire line, and record
    # the unused package name in the error.
    for report_line in set(linter_report.split('\n')):
        print(report_line)
        if not report_line:
            continue
        match = re.search(r':(\d+)(?::\d+)? \'([^\']+)\' imported but unused', report_line)
        if not match:
            continue

        line_number = int(match.group(1))
        unused_name_msg = match.group(2)
        unused_module = re.match(r'(\S+)', unused_name_msg).group(1)

        code = code_lines[line_number - 1]
        if 'import' not in code or '(' in code or code[-1] == '\\':
            # If either import keyword does not appear anywhere in the line or ( appears, then we can be sure this is
            # part of a multi-line import statement. We cannot handle fixing multi-line imports with our simplistic
            # parsing, so ignore it.
            continue

        expanded_import_terms.update([x[1] for x in parse_import_statement(code)])
        unused_import_lines.append(line_number)
        unused_module_names.add(unused_module)

    # For every unused module name, filter out its import(s) from expanded_import_terms
    expanded_import_terms = [
        terms for terms in expanded_import_terms
        if module_path_join([terms[0], terms[1]]) not in unused_module_names
    ]

    # Rewrite the import statements from the (now filtered) expanded import terms
    unused_import_fix_statements = [construct_import_statement(terms) for terms in expanded_import_terms]
    return unused_import_lines, unused_import_fix_statements


def get_missing_import_statements(code, code_base_dir):
    # Find undefined references (an undefined reference is potentially indicative of a missing module import)
    undefined_references = get_undefined_references(code)

    # Attempt to identify the import statements that satisfy the undefined references
    root_path = get_project_root_path(code_base_dir=code_base_dir)
    db = get_imports_database(root_path)

    needed_import_statements = set()
    for name in undefined_references:
        if '.' in name:
            name_base = name[name.rfind('.') + 1:]
        else:
            name_base = None
        if name in db:
            needed_import_statements.add(construct_import_statement(db[name]))
        elif name_base in db:
            needed_import_statements.add(construct_import_statement(db[name_base]))
        else:
            logging.warning('Not able to find how to import \'{}\''.format(name))

    return needed_import_statements


def verify_dependencies_installed():
    if not get_command_output(['which', 'ag']).strip():
        raise RuntimeError(
            'Dependency \'ag\' not found. '
            'Please install the_silver_searcher via your operating system package manager.')
    if not get_command_output(['which', 'pyflakes']).strip():
        raise RuntimeError('Dependency \'pyflakes\' not found. Please install the pyflakes pip package.')


def main():
    # Basic Setup
    logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', stream=sys.stderr, level=logging.INFO)
    verify_dependencies_installed()

    # Parse Args
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='file to fix or \'-\' for standard in')
    parser.add_argument(
        '--base_dir',
        help='the filesystem directory for where the code would be, if using standard in. This provides context for '
             'determining what import statements and import styles are preferred across a codebase. (default=.)',
        default='.',
    )
    args = parser.parse_args()

    # Load Specified File
    if args.file == '-':
        code = sys.stdin.read().decode('utf-8')
        code_base_dir = os.path.abspath(args.base_dir)
    else:
        with open(args.file) as input_file:
            code = input_file.read()
        code_base_dir = os.path.dirname(os.path.abspath(args.file))

    # Find missing or unused import statements
    needed_import_statements = get_missing_import_statements(code, code_base_dir)
    unused_import_lines, unused_import_fix_statements = get_unused_import_statements_with_fixes(code)

    # Output
    if needed_import_statements:
        print(str('\n'.join(['Add: ' + statement for statement in sorted(needed_import_statements)])))
    if unused_import_lines:
        print(str('\n'.join(['Remove L' + str(line_number) for line_number in sorted(unused_import_lines)])))
        print(str('\n'.join(['Add: ' + statement for statement in sorted(unused_import_fix_statements)])))


if __name__ == '__main__':
    main()
