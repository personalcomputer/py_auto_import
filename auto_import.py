#!/usr/bin/env python3

from collections import defaultdict
import argparse
import datetime
import hashlib
import logging
import os
import pickle
import re
import subprocess
import sys

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

    'argparse': (None, 'argparse', None),
    'np': (None, 'numpy', 'np'),
    'numpy': (None, 'numpy', None),
    'pd': (None, 'pandas', 'pd'),
    'pytz': (None, 'pytz', None),
    'requests': (None, 'requests', None),
    'six': (None, 'six', None),
})


def get_command_output(cmd, stdin=None):
    raw_output, _ = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE).communicate(stdin)
    return raw_output.decode('utf-8')


def get_valid_filename(s):
    """
    Credit: Django Project
    License: 3 Clause BSD https://github.com/django/django/blob/c7cc7526d5ee7d38a6ee1af03610f1aba1ea0c78/LICENSE
    """
    s = str(s).strip().replace(' ', '_')
    return re.sub(r'(?u)[^-\w.]', '', s)


def module_path_join(*modules):
    return '.'.join([module.strip('.') for module in modules])


def construct_import_statement(terms):
    statement = ''
    if terms[0]:
        statement += f'from {terms[0]} '
    if terms[1]:
        statement += f'import {terms[1]} '
    if terms[2]:
        statement += f'as {terms[2]} '
    return statement.strip()


def build_imports_database(project_root_path):
    import_freq_db = defaultdict(lambda: defaultdict(lambda: 0))

    # Preload some common import statements from the built-in DB
    import_freq_db.update({
        name: defaultdict(lambda: 0, [(terms, 0)]) for name, terms in PRELOADED_IMPORTS_DB.items()
    })

    # Scan your current project's codebase for import statement patterns, to see how you commonly import different
    # names.
    # (Outsources the core file regex searching to a highly optimized utility.)
    ag_output = get_command_output(
        ['ag', '--python', r'^(?:from [a-zA-Z_0-9 .,]+ )?import \(?[a-zA-Z_0-9 ,]+\)?', project_root_path])

    matches = re.findall(
        r'(?:from ([a-zA-Z_0-9 .,]+) )?'
        r'import \(?([a-zA-Z_0-9 ,]+)\)?'
        r'(?: as ([a-zA-Z_0-9.]+))?',
        ag_output
    )
    for match in matches:
        import_base = match[0] if match[0] else None
        import_list = [term.strip() for term in match[1].split(',')]
        import_alias = match[2] if match[2] else None
        if import_alias:
            import_freq_db[import_alias][
                (import_base, import_list[0], import_alias)] += 1
            logging.debug(f'Found an import pattern for {import_alias}')
        else:
            for term in import_list:
                import_freq_db[term][
                    (import_base, term, import_alias)] += 1
            logging.debug(f'Found an import pattern for {term}')

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
        os.environ.get('XDG_DATA_HOME', os.path.expanduser('~/.local/share')),
        'py_auto_import',
        'db_cache',
    )
    root_path_hash = hashlib.md5(project_root_path.encode('utf-8')).hexdigest()
    cache_path = os.path.join(
        DATABASE_CACHES_PATH,
        get_valid_filename(os.path.basename(project_root_path) + '_' + root_path_hash) + '.pickle'
    )

    if os.path.exists(cache_path):
        cache_mtime = datetime.datetime.utcfromtimestamp(os.path.getmtime(cache_path))
        if (datetime.datetime.now() - cache_mtime) < DATABASE_CACHE_EXPIRY:
            with open(cache_path, 'rb') as cache_file:
                return pickle.load(cache_file)

    db = build_imports_database(project_root_path)
    os.makedirs(DATABASE_CACHES_PATH, exist_ok=True)
    with open(cache_path, 'wb') as cache_file:
        pickle.dump(db, cache_file)
    return db


def get_project_root_path():
    try:
        git_repo_root = get_command_output(['git', 'rev-parse', '--show-toplevel']).strip()
        if git_repo_root:
            return git_repo_root
    except FileNotFoundError:
        pass

    return os.path.abspath('.')


def get_undefined_references(code):
    # Use Flake8 to get undefined references.
    FLAKE8_ERROR_CODE_UNDEFINED_REFERENCE = 'F821'
    flake8_report = get_command_output(
        ['flake8', '--select', FLAKE8_ERROR_CODE_UNDEFINED_REFERENCE, '-'], stdin=code.encode('utf-8'))

    undefined_references = set()
    for report_line in set(flake8_report.split('\n')):
        if not report_line:
            continue
        match = re.search(r'undefined name \'([^\']+)\'', report_line)
        undefined_references.add(match.group(1))

    return undefined_references


def get_missing_import_statements(code):
    # Find undefined references (an undefined reference is potentially indicative of a missing module import)
    undefined_references = get_undefined_references(code)

    # Attempt to identify the import statements that satisfy the undefined references
    root_path = get_project_root_path()
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
            logging.warning(f'Not able to find how to import \'{name}\'')

    return needed_import_statements


def verify_dependencies_installed():
    try:
        get_command_output(['ag', '--version'])
    except FileNotFoundError:
        raise RuntimeError(
            'Dependency \'ag\' not found. '
            'Please install the_silver_searcher via your operating system package manager.')
    try:
        get_command_output(['flake8', '--version'])
    except FileNotFoundError:
        raise RuntimeError('Dependency \'flake8\' not found. Please install the flake8 pip package.')


def main():
    # Basic Setup
    logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', stream=sys.stderr, level=logging.INFO)
    verify_dependencies_installed()

    # Parse Args
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'files', help='files to fix or \'-\' for standard in'
    )
    args = parser.parse_args()

    # Load Specified File
    if args.files == '-':
        code = sys.stdin.read().decode('utf-8')
    else:
        if ' ' in args.files:
            raise NotImplementedError(
                'Sorry, using more than one file argument has not been implemented, '
                'please specify one file per invocation')
        with open(args.files) as input_file:
            code = input_file.read()

    # Find missing import statements
    needed_import_statements = get_missing_import_statements(code)

    # Output
    if needed_import_statements:
        print(str('\n'.join(sorted(needed_import_statements))))


if __name__ == '__main__':
    main()
