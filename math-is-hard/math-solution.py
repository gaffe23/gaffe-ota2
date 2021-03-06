#!/usr/bin/python

import socket, string, math

family = socket.AF_INET
type_ = socket.SOCK_STREAM
proto = socket.IPPROTO_TCP

s = socket.socket(family, type_, proto)
s.connect(("104.131.107.153", 12121))

def get_response():
  response = s.recv(2048)
  print "[receiving] \"%s\"" % response.rstrip()
  return response

def send_message(message):
  s.send(message + "\n")
  print "[sending] \"" + message + "\""

# stage 1 intro message
input = get_response()
input = get_response()
input = input.split("\n")[0]

# solve stage 1
while "nice job" not in input:
  input = input.split(" ")
  num1 = int(input[8])
  num2 = int(input[10])
  solution = num1 + num2
  send_message(str(solution))
  input = get_response()

# stage 2 intro message
input = get_response()
input = input.split("\n")[1:]

# solve stage 2
while True:
  equation1 = input[0].split(" ")
  equation1 = [string.strip(equation1[0], "x"), string.strip(equation1[2], "y"), equation1[4]] 
  equation2 = input[1].split(" ")
  equation2 = [string.strip(equation2[0], "x"), string.strip(equation2[2], "y"), equation2[4]] 

  coeffx1 = int(equation1[0])
  coeffy1 = int(equation1[1])
  const1 = int(equation1[2])
  coeffx2 = int(equation2[0])
  coeffy2 = int(equation2[1])
  const2 = int(equation2[2])

  newcoeffx1 = coeffx1 * coeffy2
  newcoeffy1 = coeffy1 * coeffy2
  newconst1 = const1 * coeffy2
  newcoeffx2 = coeffx2 * coeffy1
  newcoeffy2 = coeffy2 * coeffy1
  newconst2 = const2 * coeffy1

  # calculate x
  x = (newconst1 - newconst2) / (newcoeffx1 - newcoeffx2)
  send_message(str(x))

  # "enter the value of y" message
  get_response()

  # use known x value to calculate y
  y = (const1 - (coeffx1 * x)) / coeffy1
  send_message(str(y))

  input = get_response()
  if "Thanks" in input:
    break
  input = get_response()
  input = input.split("\n")

# solve stage 3
input = get_response()
lines = input.split('\n')
x = int(lines[0].split(' ')[15].rstrip(':'))
polynomial = lines[1].lstrip("f(x) = ").split(' + ')
while True:
  total = 0
  for term in polynomial:
    if "x" not in term:
      continue
    term = term.split("x^")
    exp = int(term[1])
    coeff = int(term[0]) * exp
    exp -= 1
    total += coeff * math.pow(x, exp)
  total = int(total)

  send_message(str(total))

  input = get_response()
  if "flag" in input:
    break
  x = int(input.split(' ')[15].rstrip(':\n'))

  input = get_response()
  polynomial = input.split('\n')[0].lstrip("f(x) = ").split(' + ')
