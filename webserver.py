#!/usr/bin/python

import signal  # Internal signal processing
import subprocess  # Scripting
import sys  # duh
import socket  # duh
import threading  # To permit concurrent client connections
import json  # To read config files
import logging  # yep this is here too.
import os


def getRequest(method):
    """
    GET request handler
    Params:
        method - String representing the type of request
    Returns:
        code - HTTP code as string
        page - page the user will view, as a string
    """
    global root
    code = "200"
    if method == "":
        method = "index.php"
    try:
        if method == "webserver.py":
            raise ValueError("Cannot get this")
        with open(root + method) as f:
            page = f.read()
    except (IOError, OSError, ValueError) as e:
        if type(e) == ValueError:
            code = "403"
        elif e.errno == 2:  # File not found
            code = "404"
        elif e.errno == 13:  # Permission denied
            code = "403"
        else:
            code = "500"
        with open(root + code + ".html") as f:
            page = f.read()
    return code, page


def postRequest(path, headers, requestbody):
    """
    POST request handler
    Params:
        method - String representing the type of request
    Returns:
        code - HTTP code as string
        page - page the user will view, as a string
    """
    global root
    code = "200"
    body = ""
    if path == "":
        path = "index.php"
    try:
        try:
            if int(headers["Content-Length"][1:]) != len(requestbody) and 0 != len(requestbody):
                raise KeyError
            if path[-3:] == "php":
                code, body = getPhp(path, requestbody)
            else:
                with open(path, mode='w') as f:
                    body = f.read()
        except KeyError:
            code = "411"
            with open(root + code + ".html") as f:
                body = f.read()
            return code, body
    except (IOError, OSError) as e:
        if e.errno == 2:  # File not found
            code = "404"
        elif e.errno == 13:  # Permission denied
            code = "403"
        else:
            code = "500"
        with open(root + code + ".html") as f:
            body = f.read()
    except:
        code = "500"
        with open(root + code + ".html") as f:
            body = f.read()

    # the rest of the function
    return code, body


def connectproxy(source, dest):
    while(source):
        source.send(dest.recv(65535))
        dest.send(source.recv(65535))


def connectRequest(target, headers, sock):
    """
    CONNECT request handler
    """
    code = "200"
    try:
        host, port = target.split(":")
        port = int(port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s = socket.connect((host, port))
        threading.Thread(target=connectproxy, args=(s, sock)).start()
        return code
    except:
        with open(root + "500.html") as f:
            response = f.read()
        return "500 Internal Server Error", response


def putRequest(method, putbody):
    """
    PUT request handler
    """
    global root
    body = ""
    try:
        with open(method, 'w') as f:
            f.write(root + putbody)
            code = "200"
    except (IOError, OSError) as e:
        if e.errno == 2:  # File not found
            code = "404"
        elif e.errno == 13:  # Permission denied
            code = "403"
        else:
            code = "500"
        with open(root + code + ".html") as f:
            body = f.read()
    return code, body


def deleteRequest(method):
    """
    DELETE request handler
    """
    global root
    code = "200"
    body = ""
    try:
        os.remove(root + method)
    except (IOError, OSError) as e:
        if e.errno == 2:  # File not found
            code = "404"
        elif e.errno == 13:  # Permission denied
            code = "403"
        else:
            code = "500"
        with open(root + code + ".html") as f:
            body = f.read()
    return code, body


def getResponse(method, headers, requestbody, sock):
    """
    Generates HTTP response for a request
    Params:
        request: an un-sanitized string containing the user's request.
    Return:
        String containing response code
    Potential codes:
        200, All is well
        400, Bad request
        401, Unauthorized
        403, Forbidden
        404, File not found
        411, Length required
        500, Internal server error
        505 HTTP version not supported
    """
    if method is None and headers is None and requestbody is None:
        code = "400"
        with open(root + code + ".html") as f:
            body = f.read()
    global disabled
    code = "200"
    body = ""
    try:
        if method[2] != "HTTP/1.1":
            code = "505"
            body = "HTTP version not supported"
            return "HTTP/1.1 " + code + "\r\n\r\n" + body
        if method[0] == "GET" and "GET" not in disabled:
            if method[1][-3:] == "php":
                code, body = getPhp(method[1], "")
            else:
                code, body = getRequest(method[1])
        elif method[0] == "POST" and "POST" not in disabled:
            code, body = postRequest(method[1], headers, requestbody[0])
        elif method[0] == "PUT" and "PUT" not in disabled:
            code, body = putRequest(method[1], requestbody)
        elif method[0] == "DELETE" and "DELETE" not in disabled:
            code, body = deleteRequest(method[1])
        elif method[0] == "CONNECT" and "CONNECT" not in disabled:
            code, body = connectRequest(method[1], headers, sock)
        else:
            code = "500"
            with open(root + code + ".html") as f:
                body = f.read()
    except:
        code = "500"
        with open(root + code + ".html") as f:
            body = f.read()
    return "HTTP/1.1 " + code + "\r\n\r\n" + body


def getHeaders(headerlist):
    """
    Isolates headers in un-sanitized input
    Params:
        headerlist: an un-sanitized list containing the user's header options.
    Return:
        Dictionary of headers
    """
    dic = {}
    for header in headerlist:
        header = header.split(":")
        for item in header:
            item = item.strip()
        dic[header[0]] = header[1]
    return dic


def getPhp(phpfile, variableinput):
    """
    Executes php scripts
    Params:
        phpfile: a file that the web server is hosting.
    Return:
        The php output as a string
    """
    global root
    code = "200"
    variableinput = variableinput.split("&")
    variables = {}
    for i in variableinput:
        x = i.split("=")
        variables[x[0]] = x[1]
    try:
        process = subprocess.Popen(["php", phpfile, variableinput, variableinput, "REQUEST_METHOD=POST"], stdout=subprocess.PIPE)
        process.wait()
        result, err = process.communicate()
        result = result.split('line 4')[-1]
    except:
        code = "500"
        with open(root + code + ".html") as f:
            result = f.read()
    return code, result


def parseRequest(request, badlog):
    """
    Generates HTTP response for a request
    Params:
        request: an un-sanitized string containing the whole user request.
    Returns:
        (method, headers, body)
    """
    try:
        request = request.split("\r\n\r\n")
        headers = request[0]
        headers = headers.split("\r\n")
        method = headers[0].split(" ")
        method[1] = method[1][1:]
    except:
        badlog.info("Could not parse request")
        return(None, None, None)
    headers = getHeaders(headers[1:])  # This will change headers to a dictionary.
    return(method, headers, request[1:])


def getConfig(configfile):
    """
    Retrieve configuration from settings file
    Params:
        configfile: String containing config file name
    Return:
        Dictionary linking settings keywords to definitions
    """
    with open(configfile) as f:
        data = json.load(f)  # load the whole config file
    return data


def requestHandler(client, goodlog, badlog):
    """
    A thread used to parse and respond to a particular HTTP request.
    Params:
        client - a socket object representing the client.
    Return:
        None
    """
    method, headers, body = parseRequest(client.recv(65535), badlog)
    response = getResponse(method, headers, body, client)

    client.send(response)
    # Because HTTP is stateless we close the connection at the end of every action
    client.close()


def initLogs(glog, blog):
    """
    Initializes logger objects from given strings
    Params:
        goodlog: string of good log file location
        badlog: string of bad log file location
    Return:
        (goodlog, badlog)
    """
    # Set up both log file outputs
    goodlog = logging.getLogger('good_logs')  # set up logger for easy logging.
    goodhdlr = logging.FileHandler(glog)
    goodformatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    goodhdlr.setFormatter(goodformatter)
    goodlog.addHandler(goodhdlr)
    goodlog.setLevel(logging.INFO)
    badlog = logging.getLogger('bad_logs')  # set up logger for easy logging.
    badhdlr = logging.FileHandler(blog)
    badformatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    badhdlr.setFormatter(badformatter)
    badlog.addHandler(badhdlr)
    badlog.setLevel(logging.INFO)
    return (goodlog, badlog)


def main():
    """
    Basic web server implementing  GET, POST, PUT, DELETE, and CONNECT
    with the basic error reporting codes and a scripting language.
    Return:
        None
    """
    try:
        conf = getConfig(sys.argv[1])
    except IndexError:
        print("Using default config: \"./webserver.blob\"")
        conf = getConfig("webserver.blob")

    if conf["root"][-1] != "/":
        conf["root"] += "/"
    global root
    root = conf["root"]
    goodlog, badlog = initLogs(conf["goodlog"], conf["badlog"])

    global disabled
    disabled = conf["disabled"]

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def signal_handler(signal, frame):
            print('\nClosing server.\n')
            s.close()
            sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        s.bind((conf["host"], int(conf["port"])))  # Bind to port
    except socket.error, e:
        print("Could not bind to port: " + str(e))
        sys.exit(1)

    s.listen(10)  # concurrent connections possible

    try:
        while(True):
            # Client is an object representing the client
            # adr is an array of information about the client
            client, adr = s.accept()  # Accept is a blocking call
            goodlog.info("New connection from {0}:{1}".format(adr[0], adr[1]))

            # requestHandler is the function being run in the thread
            # args are the parameters it takes
            # You need the comma because it needs to be iterable
            threading.Thread(target=requestHandler, args=(client, goodlog, badlog)).start()

    except socket.error, exc:
        badlog.error("Caught exception socket.error: {}".format(exc.message))


if __name__ == "__main__":
    main()
