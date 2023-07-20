import sys
from progress.bar import FillingSquaresBar
from time import sleep
from colored import fg, bg, attr, fore, style
from colored import stylize
from functools import wraps
from colored import fg, bg, attr, fore, style

def prefix(item):
    '''
    This function decorates the other functions with bars
    '''    
    def decorator(fun):
        @wraps(fun)
        def wrapper(*args):
            print('\n')
            d = (stylize(item, fg("green_1")))
            with FillingSquaresBar(d) as bar:
                for _ in range(100):
                    sleep(0.01)
                    bar.next()
                print('\n')
            return fun(*args)
        return wrapper
    return decorator

def sub_prefix(item):   
    '''
    This function decorates the other functions with bars
    '''   
    def decorator(fun):
        @wraps(fun)
        def wrapper(*args):
            d = (stylize(item, fg("dodger_blue_1")))
            with FillingSquaresBar(d) as bar:
                for _ in range(100):
                    sleep(0.005)
                    bar.next()
            return fun(*args)
        return wrapper
    return decorator


def service_open(item,file_obj=None):
    '''
    This function decorates the open functions with bars
    '''  
    print (fore.ORANGE_1 + '            [+] ' + f' {item}' + ' Endpoint Identified' + style.RESET)
    if file_obj:
        print('            [+] '+item + ' Endpoint Identified',file=file_obj)


def resource_available(item,file_obj=None):
    '''
    This function decorates the available resources with bars
    '''  
    print (fore.ORANGE_1 + '            [+] ' + f' {item}' + ' Identified in the cluster' + style.RESET)
    if file_obj:
        print('            [+] '+item + ' Identified in the cluster',file=file_obj)

def scan_status(item):
    '''
    This function decorates items being scanned with bars
    '''  
    d = (stylize(item, fg("dodger_blue_1")))
    with FillingSquaresBar(d) as bar:
        for _ in range(100):
            sleep(0.005)
            bar.next()


borderpadding = 2

def getLines(text):
    '''
    cowsay stuff
    '''  
    lines = []
    lines.append(text.strip())
    return lines

def getMaxLineLength(lines):
    '''
    cowsay stuff
    '''  
    maxLength = 0
    for line in lines:
        length = len(line)
        if length > maxLength:
            maxLength = length

    return maxLength

def padLine(line, maxlinelength):
    '''
    cowsay stuff
    '''  
    paddingLength = maxlinelength - len(line) - borderpadding
    padding = ""
    if paddingLength > 0:
        padding = " " * paddingLength
    return line + padding


def drawTextBox(lines):
    '''
    cowsay stuff
    '''  
    maxlinelength = getMaxLineLength(lines) + borderpadding 
    horizontal_border = " " + ('-' * maxlinelength)
    print(horizontal_border)    
    if len(lines) == 1:
        print("< " + padLine(lines[0], maxlinelength) + " >")
    else:
        print("/ " + (" " * (maxlinelength - borderpadding)) + " \\")
        for line in lines:
            print("| " + padLine(line, maxlinelength) + " |")
        print("\\ " + (" " * (maxlinelength - borderpadding)) + " /")
    print(horizontal_border)

cow = [ fore.MAGENTA_1 + 
   "          \\  ^__^",
   "           \\ (oo)\\________",
   "             (__)\\        )\\/\\",
   "                  ||----W |",
   "                  ||     ||"
+ style.RESET]

def drawAnimal():
   """Draws a cow in the terminal with ascii art"""
   for line in cow:
       print(line)


def cowsay(text):
    '''
    cowsay stuff
    '''  
    lines = getLines(text)
    drawTextBox(lines)
    drawAnimal()

def print_msg_box(msg, indent=1, width=None, title=None, file_obj=None):
    """Print message-box with optional title."""
    lines = msg.split('\n')
    space = " " * indent
    if not width:
        width = max(map(len, lines))
    box = f'╔{"═" * (width + indent * 2)}╗\n'  # upper_border
    if title:
        box += f'║{space}{title:<{width}}{space}║\n'  # title
        box += f'║{space}{"-" * len(title):<{width}}{space}║\n'  # underscore
    box += ''.join([f'║{space}{line:<{width}}{space}║\n' for line in lines])
    box += f'╚{"═" * (width + indent * 2)}╝'  # lower_border
    if file_obj:
        print(box, file=file_obj)
