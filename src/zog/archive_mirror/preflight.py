"""Non-mutating checks to run with the generation's own Python inside its root."""
import importlib
import json
import sys


def check_runtime():
    checks = []
    def check(name, action):
        try:
            action()
        except Exception as error:
            checks.append({'name': name, 'ready': False, 'error': type(error).__name__})
        else:
            checks.append({'name': name, 'ready': True})

    def python_version():
        if sys.version_info < (3, 12):
            raise RuntimeError('Python 3.12 or newer required')
    check('python', python_version)
    for name in ('ssl', 'sqlite3', 'lzma', 'django', 'waitress', 'jwt', 'zog.host_identify.archive', 'zog.host_identify.storage'):
        check(name, lambda name=name: importlib.import_module(name))

    def database():
        import sqlite3
        with sqlite3.connect(':memory:') as connection:
            assert connection.execute('select 1').fetchone() == (1,)
    check('sqlite-operation', database)

    def compression():
        import lzma
        assert lzma.decompress(lzma.compress(b'archive-mirror')) == b'archive-mirror'
    check('xz-operation', compression)

    def signature():
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        data = b'archive-mirror-preflight'
        key.public_key().verify(key.sign(data), data)
    check('ed25519-operation', signature)
    return {'version': 1, 'python': sys.version.split()[0],
            'ready': all(item['ready'] for item in checks), 'checks': checks}


def main():
    report = check_runtime()
    print(json.dumps(report))
    return 0 if report['ready'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
