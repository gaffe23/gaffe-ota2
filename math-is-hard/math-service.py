#!/usr/bin/python2

import sys, socket, multiprocessing, time, random, math, string

# ratelimit, in seconds
RATELIMIT = 0.01

# maximum amount of time a client can stay connected, in seconds
MAX_CONN_TIME = 3 * 60

PORT_NUMBER = 12121
NUM_SIMULTANEOUS_CONNS = 20
FLAG = "flag{l3ts_g0_shOpP1ng}"

def log_msg(clientinfo, msg):
    """log current time, client info, and status messages."""
    print "%s <%s:%s> %s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), clientinfo[0], clientinfo[1], msg)

def get_client_input(s):
    clientinfo = s.getpeername()
    starttime = time.time()
    buf = s.recv(2048).rstrip()
    endtime = time.time()
    timediff = endtime - starttime
    log_msg(clientinfo, "\"%s\" (response time %.3f seconds)" % (buf, timediff))
    return buf, timediff

def shutdown_connection(s, connstart, msg):
    """send message to the client (if possible) saying why we're disconnecting
    them, and then close out the socket. if any operation fails along the way,
    assume that the socket is already closed."""
    clientinfo = s.getpeername()
    try:
        s.send(msg)
        s.shutdown(socket.SHUT_RDWR)
        s.close()
    except:
        pass
    log_msg(clientinfo, "disconnected after %.3f seconds" % (time.time() - connstart))
    sys.exit()

def check_time(s, connstart, timediff, limit):
    """check whether the client answered the problem within the specified time
    limit, and disconnect them if they were too slow."""
    clientinfo = s.getpeername()
    if(timediff > limit):
        log_msg(clientinfo, "disconnected after %.3f seconds (too slow)" % (time.time() - connstart))
        shutdown_connection(s, connstart, "Sorry, too slow!\n")

def check_answer(s, connstart, correctanswer, clientanswer):
    """check whether the client's answer was correct, and disconnect them if
    their answer was incorrect."""
    clientinfo = s.getpeername()
    if clientanswer != correctanswer:
        log_msg(clientinfo, "disconnected after %.3f seconds (wrong answer)" % (time.time() - connstart))
        shutdown_connection(s, connstart, "Sorry dude, that ain't right...\n")

def termstostring(terms):
    termlist = []
    for coeff,exp in terms:
        if exp == 0:
            termlist.append("%d" % coeff)
        elif coeff == 0:
            continue
        else:
            termlist.append("%dx^%d" % (coeff, exp))
    return " + ".join(termlist)

def deriv(x, terms):
    total = 0
    for coeff,exp in terms:
        if coeff == 0:
            continue
        else:
            newcoeff = coeff * exp
            newexp = exp - 1
            total += newcoeff * math.pow(x, newexp)
    total = int(total)
    return total

def client_process(s):
    """handles client connections. provides the client with increasingly
    difficult math problems, and ends the connection if the client gets a
    question wrong."""

    clientinfo = s.getpeername()
    connstart = time.time()
    log_msg(clientinfo, "connected")

    s.send("Hey dude, can you help me with my math homework? I have a few addition problems to do...\n")
    i = 10.0

    # phase 1 - adding random numbers

    while time.time() - connstart < MAX_CONN_TIME and i > 0.5:

        # choose random numbers with an upper bound that increases
        # exponentially as the amount of time available to solve the challenge
        # decreases

        upperbound = math.pow(math.ceil(100 / (i)), 3)
        num1 = random.randint((-1 * upperbound), upperbound)
        num2 = random.randint((-1 * upperbound), upperbound)

        try:
            s.send("You have %f seconds to solve this problem: %d + %d\n" % (i, num1, num2))

            buf, timediff = get_client_input(s)
            check_time(s, connstart, timediff, i)

            clientanswer = int(buf)
            check_answer(s, connstart, num1 + num2, clientanswer)

            i /= 1.5
            time.sleep(RATELIMIT)
        except Exception, e:
            log_msg(clientinfo, "Exception: \"%s\"" % (str(e)))
            shutdown_connection(s, connstart, "Sorry dude, I have no idea what you're talking about.\n")

    log_msg(clientinfo, "completed stage 1 after %.3f seconds" % (time.time() - connstart))
    try:
        s.send("Hey, nice job! Okay, we're done with the addition part, now it's going to get harder:");
    except:
        pass

    i = 10.0

    # phase 2 - solving random systems of equations

    while time.time() - connstart < MAX_CONN_TIME and i > 0.5:

        upperbound = math.pow(math.ceil(100 / (i)), 3)

        # set up system of equations
        x = random.randint((-1 * upperbound), upperbound)
        y = random.randint((-1 * upperbound), upperbound)
        coeffx1 = random.randint((-1 * upperbound), upperbound)
        coeffy1 = random.randint((-1 * upperbound), upperbound)
        const1 = (coeffx1 * x) + (coeffy1 * y)
        coeffx2 = random.randint((-1 * upperbound), upperbound)
        coeffy2 = random.randint((-1 * upperbound), upperbound)
        const2 = (coeffx2 * x) + (coeffy2 * y)

        try:
            s.send("You have %f seconds to solve the following system of equations:\n" % i)
            s.send("%dx + %dy = %d\n" % (coeffx1, coeffy1, const1))
            s.send("%dx + %dy = %d\n" % (coeffx2, coeffy2, const2))

            s.send("Enter the value of x:\n")
            buf, timediff = get_client_input(s)
            clientx = int(buf)
            check_time(s, connstart, timediff, i)

            s.send("Enter the value of y:\n")
            buf, timediff = get_client_input(s)
            clienty = int(buf)
            check_time(s, connstart, timediff, i)

            check_answer(s, connstart, x, clientx)
            check_answer(s, connstart, y, clienty)

            i /= 1.5
            time.sleep(RATELIMIT)
        except Exception, e:
            log_msg(clientinfo, "Exception: \"%s\"" % (str(e)))
            shutdown_connection(s, connstart, "Sorry dude, I have no idea what you're talking about.\n")

    log_msg(clientinfo, "completed stage 2 after %.3f seconds" % (time.time() - connstart))
    try:
        s.send("Thanks man. Hey uh, also, how much do you know about calculus?\n")
    except:
        pass

    i = 10.0

    # phase 3 - calculating derivatives of polynomials at specific points

    while time.time() - connstart < MAX_CONN_TIME and i > 0.5:

        termcount = int(math.ceil(11 - i))

        upperbound = 9

        terms = []

        for count in xrange(termcount):
            coeff = random.randint(0, upperbound)
            exp = random.randint(0, upperbound)
            terms.append([coeff, exp])

        polynomial = termstostring(terms)

        x = random.randint(1, upperbound)
        y = deriv(x, terms)

        try:
            s.send("You have %f seconds to calculate the derivative of the following equation at point %d:\n" % (i, x))
            s.send("f(x) = %s\n" % polynomial)

            s.send("Enter the value of f'(x):\n")
            buf, timediff = get_client_input(s)
            clienty = int(buf)
            check_time(s, connstart, timediff, i)
            check_answer(s, connstart, y, clienty)

            i /= 1.5
            time.sleep(RATELIMIT)
        except Exception, e:
            log_msg(clientinfo, "Exception: \"%s\"" % (str(e)))
            shutdown_connection(s, connstart, "Sorry dude, I have no idea what you're talking about.\n")

    log_msg(clientinfo, "got flag after %.3f seconds" % (time.time() - connstart))
    shutdown_connection(s, connstart, "Hey, thanks buddy! Here's a little somethin' for your trouble: %s\n" % FLAG)

if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((socket.gethostname(), PORT_NUMBER))
    s.listen(NUM_SIMULTANEOUS_CONNS)
    print "listening on %s:%d..." % (socket.gethostbyname(socket.gethostname()), PORT_NUMBER)

    # fork off a new process for each connection
    while 1:
        (clientsocket, address) = s.accept()
        newclient = multiprocessing.Process(target = client_process, args = (clientsocket, ))
        newclient.start()
