#include <iostream>
#include <sstream>
#include <algorithm>

#define UNEXPECTED_INPUT throw std::runtime_error("unexpected input: " + input.str())

typedef double number;

number _eval(std::stringstream &input);

number _eval_operand(std::stringstream &input) {
	int ch = input.get();
	switch (ch) {
	case '0' ... '9':
	case '.':
		input.putback(ch);
		number num;
		input >> num;
		
		return num;
		
	case '+':
		return _eval(input);
	case '-':
		return -_eval(input);
	case '(':
		std::string inside_brackets;
		getline(input, inside_brackets, ')');
		std::stringstream ss(inside_brackets);
		return _eval(ss);
	}
		
	UNEXPECTED_INPUT;
}

number _eval(std::stringstream &input) {
	number num = _eval_operand(input);

	int ch=input.get();

	switch (ch) {
	case EOF:
		return num;
	case '+':
		return num + _eval(input);
	case '-':
		return num - _eval(input);
	case '*':
		return num * _eval(input);
	case '/':
		return num / _eval(input);
	}
		
	UNEXPECTED_INPUT;		
}

number eval(const std::string &input) {
	std::string no_spaces;
	copy_if(input.begin(), input.end(), back_inserter(no_spaces), 
		[] (char ch) { return !isspace(ch);} );

	std::stringstream ss(no_spaces);
	
	return _eval(ss);
}

int main() {
	std::string input;
	while(getline(std::cin, input)) {
		if (input.length() == 0) {
			return 0;
		}
		try {
			std::cout << eval(input) << std::endl;
		}
		catch(std::runtime_error(e)) {
			std::cout << e.what() << std::endl;
		}
	}
	return 0;
}