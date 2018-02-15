#!/usr/bin/python

import subprocess
import sys
import socket
import threading  # To permit concurrent client connections
import json  # To read config files
import logging


def getResponse(request):
    """
    Generates HTTP response for a request
    Params:
        request: an un-sanitized string containing the user's request.
    Return:
        String containing response code
    Potential returns:
        200, 400, 401, 403, 404, 411, 500, 505
    """
    version = "HTTP/1.1 "
    response = "200 OK"
    return version + response + "\r\n"


def getHeaders(request):
    """
    Isolates headers in un-sanitized input
    Params:
        request: an un-sanitized string containing the user's request.
    Return:
        Dictionary of headers
    """
    return "\r\n"


def getPhp(page):
    """
    Isolates headers in un-sanitized input
    Params:
        page: a file that the web server is hosting.
    Return:
        The whole file as a string
    """
    # with open(page) as p:
    #    output = p.readlines()
    result = subprocess.check_output(["php", page])
    return result


def parseRequest(request):
    """
    Generates HTTP response for a request
    Params:
        request: an un-sanitized string containing the whole user request.
    Returns:
        (method, headers, body)
    """
    request = request.split("\r\n\r\n")
    headers = request[0]
    headers = headers.split("\r\n")
    method = headers[0].split(" ")
    return(method, headers[1:], request[1:])


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
    response = parseRequest(client.recv(65535))

    client.send(response)
    # Because HTTP is connectionless we close the connection at the end of every action
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
        print("Defaulting to \"./webserver.blob\"")
        conf = getConfig("webserver.blob")

    if conf["root"][-1] != "/":
        conf["root"] += "/"
    glog = conf["root"] + conf["goodlog"]
    blog = conf["root"] + conf["badlog"]  # create full path to log files from config
    goodlog, badlog = initLogs(glog, blog)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.bind((conf["host"], int(conf["port"])))  # Bind to port
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
        badlog.error("Caught exception socket.error: {}".format(exc))


if __name__ == "__main__":
    main()
