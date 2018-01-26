import os
from setuptools import setup, find_packages

__here__ = os.path.dirname(os.path.abspath(__file__))

runtime = {
    'requests',
    'flask_session',
    'flask',
    'Jinja2',
    'flask-ldap',
    'kerberos',
    'pycrypto',
}

develop = {
    'flake8',
    'coverage',
    'pytest',
    'pytest-cov',
    'Sphinx',
    'sphinx_rtd_theme',
}

if __name__ == "__main__":
    # allows for runtime modification of rpm name
    name = "flask-multiauth"

    try:
        setup(
            name=name,
            version="0.0.1",
            description="Insights RuleAnalysis Services",
            packages=find_packages(),
            include_package_data=True,
            py_modules=['flask_multiauth'],
            install_requires=list(runtime),
            extras_require={
                'develop': list(runtime | develop),
                'optional': ['python-cjson', 'python-logstash', 'python-statsd', 'watchdog'],
            },
        )
    finally:
        pass
