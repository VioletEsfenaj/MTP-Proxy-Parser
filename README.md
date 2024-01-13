# MTP-Proxy-Parser
A simple script to parse MTProto Proxy links.

- Usage:
```python
from mtproxyParser import parse

parse('https://t.me/proxy?server=1.2.3.4&port=443&secret=3QAAAAAAAAAAAAAAAAAAAAA')

>>> (True,
 {'type': 'Randomized',
  'protocol': 'Secure Base64',
  'server': '1.2.3.4',
  'port': '443',
  'secret': '00000000000000000000000000000000',
  'raw_secret': '00000000000000000000000000000000',
  'domain': ''})
```
