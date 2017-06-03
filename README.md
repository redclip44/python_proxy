# Python Static and Reverse Proxy

## Usage:
 * For static proxy
  ```
usage: ./proxy.py staticproxy [-h] [--listen-port LISTEN_PORT]
                              [--listen-host LISTEN_HOST]
                              [--listen-unix LISTEN_UNIX]
                              [--listen-ssl LISTEN_SSL]
                              [--listen-ca-cert LISTEN_CA_CERT]
                              [--listen-cert LISTEN_CERT]
                              [--listen-key LISTEN_KEY]
                              [--proxy-port PROXY_PORT]
                              [--proxy-host PROXY_HOST]
                              [--proxy-unix PROXY_UNIX]
                              [--proxy-ssl PROXY_SSL]

optional arguments:
  -h, --help            show this help message and exit
  --listen-port LISTEN_PORT
                        Listen port for proxy only with --listen-host
  --listen-host LISTEN_HOST
                        Listen host for proxy only with --listen-port
  --listen-unix LISTEN_UNIX
                        Listen unix socket for proxy
  --listen-ssl LISTEN_SSL
                        Listen with SSL
  --listen-ca-cert LISTEN_CA_CERT
                        PEM-CA-Cert for listening
  --listen-cert LISTEN_CERT
                        PEM-Cert for listening
  --listen-key LISTEN_KEY
                        PEM-Key for listening
  --proxy-port PROXY_PORT
                        Port of the TCP proxy endpoint, only with --proxy-host
  --proxy-host PROXY_HOST
                        Host of the proxy endpoint, only with --proxy-port
  --proxy-unix PROXY_UNIX
                        Unix socket of the proxy endpoint
  --proxy-ssl PROXY_SSL
                        Proxy endpoint uses SSL?
  ```
 * For reverse proxy:

  ```
usage: ./proxy.py reverseproxy [-h] [--listen-port LISTEN_PORT]
                               [--listen-host LISTEN_HOST]
                               [--listen-unix LISTEN_UNIX]
                               [--listen-ssl LISTEN_SSL]
                               [--proxy-ssl PROXY_SSL]
                               [--proxy-module PROXY_MODULE]

optional arguments:
  -h, --help            show this help message and exit
  --listen-port LISTEN_PORT
                        Listen port for proxy only with --listen-host
  --listen-host LISTEN_HOST
                        Listen host for proxy only with --listen-port
  --listen-unix LISTEN_UNIX
                        Listen unix socket for proxy
  --listen-ssl LISTEN_SSL
                        Listen with SSL
  --proxy-ssl PROXY_SSL
                        Reverse proxy endpoints use SSL?
  --proxy-module PROXY_MODULE
                        Import .py file as a module containing a class named
                        ProxyHandler to handle reverse proxy functionality
  ```

## Configure Reverse Proxy

 * Create a file with .py extension (xxx.py) containing a class named ProxyHandler.
 * Proxy handler must implement these methods:
 ```
class ProxyHandler(object):
    ### Initialize first end forward
    initial_handshake(self, socket)
        @socket: accepted socket
        @return: void

    ### Get Proxy Address
    get_reverse_proxy(self)
        @return: tuple|string, boolean -> (tuple tcp address|string unix address, needs_ssl?)

    ### Initialize second end forward
    init_reverse_proxy(self, socket)
        @socket: created proxy socket
        @return: boolean -> (False: init failed, True: init successfull)

    ### Modify data while forwarding
    @staticmethod
    modify_data(data)
        @data: data to forward
        @return: string -> (modified data)
   ```

 * Call ```./proxy.py reverseproxy --proxy-module=xxx.py --...```
