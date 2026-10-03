import socket
import time


def probe(source_ip: str, target: str, port: int) -> dict:
    started = time.monotonic()
    observation = {'transport': 'TCP', 'target': target, 'port': port, 'requested_source_ip': source_ip,
                   'actual_source_ip': None, 'source_port': None, 'attempted': False}
    phase = 'bind'
    try:
        with socket.socket(socket.AF_INET6 if ':' in target else socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2.0)
            # Binding is mandatory. Never silently fall back to the default route/interface.
            sock.bind((source_ip, 0))
            observation['actual_source_ip'], observation['source_port'] = sock.getsockname()[:2]
            phase = 'connect'
            observation['attempted'] = True
            sock.connect((target, port))
            observation['state'] = 'TCP_CONNECTED'
            observation['detail'] = 'TCP connection accepted. No application data was sent.'
    except ConnectionRefusedError:
        observation.update(state='TCP_REFUSED', detail='TCP connection refused; this does not identify the rejecting device or prove firewall isolation.')
    except TimeoutError:
        observation.update(state='TIMEOUT', detail='No conclusive response within two seconds; do not interpret this as a blocked or secure zone.')
    except OSError as exc:
        observation.update(state='SOURCE_ERROR' if phase == 'bind' else 'NETWORK_ERROR',
                           detail=f'{phase} failed (OS error {exc.errno}); no segmentation conclusion.')
    observation['duration_ms'] = round((time.monotonic() - started) * 1000)
    return observation

