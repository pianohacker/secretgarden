## Ansible plugin
DOCUMENTATION = """
    lookup: secretgarden
    author: Jesse Weaver <pianohacker@gmail.com>
    short_description: read/generate secrets
    description:
        - This lookup returns the contents from a file on the Ansible controller's file system.
    options:
      _terms:
        description: path(s) of files to read
        required: True
      rstrip:
        description: whether or not to remove whitespace from the ending of the looked-up file
        type: bool
        required: False
        default: True
      lstrip:
        description: whether or not to remove whitespace from the beginning of the looked-up file
        type: bool
        required: False
        default: False
    notes:
      - if read in variable context, the file can be interpreted as YAML if the content is valid to the parser.
      - this lookup does not understand 'globing', use the fileglob lookup instead.
"""

from ansible.errors import AnsibleLookupError
from ansible.plugins.lookup import LookupBase
from ansible.module_utils.six.moves import shlex_quote
import subprocess

class LookupModule(LookupBase):
    def run(self, terms, variables, **kwargs):
        process = subprocess.Popen(
            ['secretgarden'] + terms + [
                (
                    ('--{}'.format(k) if v else '')
                    if isinstance(v, bool) else
                    '--{}={}'.format(k, shlex_quote(str(v)))
                ) for (k, v) in kwargs.items()
            ],
            text = True,

            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
        )
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            raise AnsibleLookupError('Failed to lookup secret from secretgarden (exit code {}): {}'.format(process.returncode, stderr))

        return [stdout[:-1]]

# vim: set et :
