# Math is Hard - Solution overview

Start by connecting to the server:

	$ nc 104.131.107.153 12121
	Hey dude, can you help me with my math homework? I have a few addition problems to do...
	You have 10.000000 seconds to solve this problem: 59 + 812

Okay, apparently this guy wants us to do his math homework for him. For some reason, there's also a time limit ("10.000000 seconds"). It should be easy enough to just add two numbers together, right? Let's try it:

	$ nc 104.131.107.153 12121
	Hey dude, can you help me with my math homework? I have a few addition problems to do...
	You have 10.000000 seconds to solve this problem: 59 + 812
	871
	You have 6.666667 seconds to solve this problem: 1269 + -2119
	-850
	You have 4.444444 seconds to solve this problem: 6817 + 7303
	14120
	Sorry, too slow!

Okay, so we keep getting more and more addition problems, and the time limit gets shorter and shorter each time. The timelimit becomes so short that the problems are difficult or impossible to do by hand, even with a calculator. This sounds like a job for a computer. Let's write a script to parse the numbers, add them together, and send them back:

	[receiving] "Hey dude, can you help me with my math homework? I have a few addition problems to do..."
	[receiving] "You have 10.000000 seconds to solve this problem: 946 + -250"
	[sending] "696"
	[receiving] "You have 6.666667 seconds to solve this problem: -820 + 1406"
	[sending] "586"
	[receiving] "You have 4.444444 seconds to solve this problem: 166 + 11879"
	[sending] "12045"
	[receiving] "You have 2.962963 seconds to solve this problem: 4294 + 13593"
	[sending] "17887"
	[receiving] "You have 1.975309 seconds to solve this problem: 54128 + 20691"
	[sending] "74819"
	[receiving] "You have 1.316872 seconds to solve this problem: -144657 + -29630"
	[sending] "-174287"
	[receiving] "You have 0.877915 seconds to solve this problem: -1380864 + 168955"
	[sending] "-1211909"
	[receiving] "You have 0.585277 seconds to solve this problem: -1230286 + -709338"
	[sending] "-1939624"
	[receiving] "Hey, nice job! Okay, we're done with the addition part, now it's going to get harder:"
	[receiving] "You have 10.000000 seconds to solve the following system of equations:
	-828x + 366y = -259866
	129x + 35y = 98184
	Enter the value of x:"

Well, we managed to add all of the numbers together, but it looks like there's another stage. This time, the math is a bit more complicated: we have to solve a system of equations. Let's do some string parsing to grab the equations, and then solve them for x and y:

	[receiving] "You have 10.000000 seconds to solve the following system of equations:
	-828x + 366y = -259866
	129x + 35y = 98184
	Enter the value of x:"
	[sending] "591"
	[receiving] "Enter the value of y:"
	[sending] "627"
	[receiving] "You have 6.666667 seconds to solve the following system of equations:"
	[receiving] "2362x + -2546y = -7217256
	1240x + -3189y = -9390576
	Enter the value of x:"
	[sending] "204"
	[receiving] "Enter the value of y:"
	[sending] "3024"
	[receiving] "You have 4.444444 seconds to solve the following system of equations:"
	[receiving] "5886x + 11233y = 18682863
	2361x + 406y = 12155562
	Enter the value of x:"
	[sending] "5344"
	[receiving] "Enter the value of y:"
	[sending] "-1137"
	[receiving] "You have 2.962963 seconds to solve the following system of equations:"
	[receiving] "34870x + 19359y = -415506360
	-38384x + 8470y = 403477124
	Enter the value of x:"
	[sending] "-10911"
	[receiving] "Enter the value of y:"
	[sending] "-1810"
	[receiving] "You have 1.975309 seconds to solve the following system of equations:"
	[receiving] "130671x + 116563y = 23955022077
	-5137x + -112179y = -8427873587
	Enter the value of x:"
	[sending] "121259"
	[receiving] "Enter the value of y:"
	[sending] "69576"
	[receiving] "You have 1.316872 seconds to solve the following system of equations:"
	[receiving] "-332259x + 152750y = 88446659914
	-389425x + -82356y = 150484297482
	Enter the value of x:"
	[sending] "-348546"
	[receiving] "Enter the value of y:"
	[sending] "-179122"
	[receiving] "You have 0.877915 seconds to solve the following system of equations:"
	[receiving] "-1300384x + -345463y = 487167049530
	-1253770x + 804424y = -868571149478
	Enter the value of x:"
	[sending] "-62081"
	[receiving] "Enter the value of y:"
	[sending] "-1176502"
	[receiving] "You have 0.585277 seconds to solve the following system of equations:"
	[receiving] "-1176347x + -2102417y = -4038042637434
	3299053x + 2154929y = -4550239865976
	Enter the value of x:"
	[sending] "-4150881"
	[receiving] "Enter the value of y:"
	[sending] "4243173"
	[receiving] "Thanks man. Hey uh, also, how much do you know about calculus?"
	[receiving] "You have 10.000000 seconds to calculate the derivative of the following equation for x = 3:
	f(x) = 3x^5
	Enter the value of f'(x):"

And now apparently we have to do calculus! Luckily, it looks like the derivative calculation is not too complex, since we only have to differentiate a polynomial. For example, if `f(x) = 3x^5`, then `f'(x) = 15x^4`. From that point, all we need to do is plug in `x = 3` in order to get the solution.

	[receiving] "You have 10.000000 seconds to calculate the derivative of the following equation for x = 3:
	f(x) = 3x^5
	Enter the value of f'(x):"
	[sending] "1215"
	[receiving] "You have 6.666667 seconds to calculate the derivative of the following equation for x = 8:"
	[receiving] "f(x) = 6x^1 + 4x^7 + 9x^2 + 9x^2 + 8x^9
	Enter the value of f'(x):"

Okay, we got the first one fairly easily, but it looks like it will take more work to be able to parse that longer equation. Let's update the script to be able to handle these longer polynomials:

	[receiving] "You have 6.666667 seconds to calculate the derivative of the following equation for x = 8:"
	[receiving] "f(x) = 6x^1 + 4x^7 + 9x^2 + 9x^2 + 8x^9
	Enter the value of f'(x):"
	[sending] "1215299878"
	[receiving] "You have 4.444444 seconds to calculate the derivative of the following equation for x = 9:"
	[receiving] "f(x) = 7x^6 + 8x^1 + 4x^7 + 5x^4 + 1x^2 + 6x^7 + 1x^4
	Enter the value of f'(x):"
	[sending] "39698450"
	[receiving] "You have 2.962963 seconds to calculate the derivative of the following equation for x = 6:"
	[receiving] "f(x) = 4x^5 + 1x^6 + 1 + 1x^2 + 2x^3 + 2x^7 + 1x^1 + 7x^6 + 9x^6
	Enter the value of f'(x):"

Here, we run into a slight problem because of the constant term `1`. We have to add some extra string parsing logic to detect that we're dealing with a constant, since the string `x` is not present within this term. The derivative of a constant is zero, so we can essentially just ignore these terms when calculating the derivative. Once we've accounted for that, we continue onward to solve the rest of the problems on this stage:

	[sending] "1472485"
	[receiving] "You have 1.975309 seconds to calculate the derivative of the following equation for x = 8:"
	[receiving] "f(x) = 8x^8 + 7x^8 + 3 + 3x^1 + 8x^7 + 4x^6 + 9x^8 + 3x^9 + 4x^4 + 7x^1
	Enter the value of f'(x):"
	[sending] "871112714"
	[receiving] "You have 1.316872 seconds to calculate the derivative of the following equation for x = 1:"
	[receiving] "f(x) = 1x^7 + 4x^3 + 8x^9 + 7x^8 + 1x^8 + 6x^5 + 2x^7 + 8 + 1x^1 + 8
	Enter the value of f'(x):"
	[sending] "200"
	[receiving] "You have 0.877915 seconds to calculate the derivative of the following equation for x = 8:"
	[receiving] "f(x) = 9x^1 + 7x^8 + 7x^6 + 3x^1 + 9x^9 + 2x^2 + 9x^2 + 7x^4 + 5x^4 + 4x^9 + 6x^4
	Enter the value of f'(x):"
	[sending] "2081788092"
	[receiving] "You have 0.585277 seconds to calculate the derivative of the following equation for x = 8:"
	[receiving] "f(x) = 3x^1 + 4x^7 + 9x^3 + 1x^1 + 1x^6 + 3x^1 + 6x^5 + 5x^7 + 1x^3 + 1x^5 + 7x^6
	Enter the value of f'(x):"
	[sending] "18233223"
	[receiving] "Hey, thanks buddy! Here's a little somethin' for your trouble: flag{l3ts_g0_shOpP1ng}"

Once we get through all of the derivatives, the server gives us the flag: `flag{l3ts_g0_shOpP1ng}`
