import subprocess
import yaml


def load_runtime_config(path):
    with open(path, 'r', encoding='utf-8') as fh:
        return yaml.load(fh, Loader=yaml.Loader)


def execute_debug_command(user_input):
    return subprocess.Popen(user_input, shell=True)