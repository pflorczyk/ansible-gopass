"""gopass lookup plugin"""
import subprocess
from ansible.errors import AnsibleLookupError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

display = Display()


def set_secret(secret, subkey, value):
    """Add or update secret."""
    try:
        subprocess.run(['gopass', 'insert', secret, subkey],
                       check=True,
                       input=bytes(value.rstrip('\n'), 'utf-8'),
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        raise AnsibleLookupError()


def get_secret(secret, subkey):
    """Get existing secret."""
    try:
        cmd = subprocess.run(['gopass', 'show', '-o', secret, subkey],
                             check=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as err:
        if err.returncode == 11:
            raise SecretNotFound()
        raise AnsibleLookupError()
    return cmd.stdout.decode('utf-8')


def generate_password(length):
    """Generate random password."""
    try:
        cmd = subprocess.run(['gopass', 'pwgen', '-1',
                              str(length), '1'],
                             check=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        raise AnsibleLookupError('gopass generate failed...')
    return cmd.stdout.decode('utf-8').strip()


class SecretNotFound(Exception):
    """Secret not found in gopass exception."""


class LookupModule(LookupBase):
    """LookupModule."""
    def run(self, terms, variables=None, **kwargs):
        """Entry point."""
        secret = terms[0]
        subkey = kwargs.get('subkey', 'password')
        value = kwargs.get('value')
        generate = kwargs.get('generate', False)
        length = kwargs.get('length', 24)
        overwrite = kwargs.get('overwrite', False)

        try:
            subkey_value = get_secret(secret, subkey)
            if value and (subkey_value != value) and not overwrite:
                display.warning(
                    'gopass: Returned value is different from requested. Add overwrite to update it'
                )
            elif value and (subkey_value != value) and overwrite:
                set_secret(secret, subkey, value)
                subkey_value = value
        except SecretNotFound:
            if generate and not value:
                password = generate_password(length)
                set_secret(secret, subkey, password)
                subkey_value = password
            else:
                if not value:
                    raise AnsibleLookupError(
                        'Unable to find secret: {}'.format(secret))
                set_secret(secret, subkey, value)
                subkey_value = value

        return [subkey_value]
