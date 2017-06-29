# based on "logging_proxy.py" from the maproxy: https://github.com/zferentz/maproxy/tree/master/demos

import tornado.ioloop
import maproxy.proxyserver
import maproxy.session
import string  # for the "filter"
import json


class LoggingSession(maproxy.session.Session):
    """
    This class tries to catch all HTTP requests from client and evaluate them
    
    """

    # Class variable: counter for the number of connections
    running_counter = 0

    def __init__(self, *args, **kwargs):
        """
        Currently overriding the "__init__" is not really required since the parent's 
        __init__ is doing absolutely nothing, but it is a good practice for
        the future... (future updates)
        """
        self.connid = None
        super(LoggingSession, self).__init__(*args, **kwargs)

    def new_connection(self, stream, address, proxy):
        """
        Override the maproxy.session.Session.new_connection() function
        This function is called by the framework (proxyserver) for every new session
        """
        # Let's increment the "autonumber" (remember: this is single-threaded, so on lock is required)
        LoggingSession.running_counter += 1
        self.connid = LoggingSession.running_counter
        super(LoggingSession, self).new_connection(stream, address, proxy)

    def on_c2p_done_read(self, data):
        """
        Override the maproxy.session.Session.on_c2p_done_read(data) function
        This function is called by the framework (proxyserver) when we get data from the client 
        (to the target-server)
        """
        try:
            header, payload = data.decode('utf-8').split('\r\n\r\n')
            headers = header.split('\r\n')
            method, resource, protocol = headers[0].split(' ')
            if method != "GET" and payload != "":
                req = json.loads(payload)
                # just PoC
                if req['Image'] == 'alpine':
                    resp_payload = '{"message": "I don\'t like alpine Image"}'
                    pl = ("HTTP/1.1 403 Forbidden\r\n"
                          "Api-Version: 1.27\r\n"
                          "Content-Type: application/json\r\n"
                          "Docker-Experimental: false\r\n"
                          "Ostype: linux\r\n"                          
                          "Content-Length: {}\r\n".format(len(resp_payload)) +
                          "\r\n"
                          "{}\n".format(resp_payload))
                    super(LoggingSession, self).c2p_start_write(pl.encode('utf-8'))
                else:
                    super(LoggingSession, self).on_c2p_done_read(data)
            else:
                # pass the request if not POST
                super(LoggingSession, self).on_c2p_done_read(data)
        except ValueError:
            # pass the request if it can't be parsed as HTTP Request
            super(LoggingSession, self).on_c2p_done_read(data)


class LoggingSessionFactory(maproxy.session.SessionFactory):
    """
    This session-factory will be used by the proxy when new sessions
    need to be generated .
    We only need a "new" function that will generate a session object
    that derives from maproxy.session.Session.
    The session that we create is our lovely LoggingSession that we declared
    earlier
    """

    def __init__(self):
        super(LoggingSessionFactory, self).__init__()

    def new(self, *args, **kwargs):
        return LoggingSession(*args, **kwargs)


if __name__ == "__main__":
    server = maproxy.proxyserver.ProxyServer("localhost", 2375, session_factory=LoggingSessionFactory())
    server.listen(2376)
    print("proxy to localhost started")
    tornado.ioloop.IOLoop.instance().start()
