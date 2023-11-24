#!/usr/bin/env python3
"""
[+] Json Hasher [+]

_< Encrypt Requests Data by hash >_

DEV#Host1let => R3D\|/R00m


License :

Copyright (c) 2023 R3D\|/R00m Host1let: jsonHasher

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import requests
import hashlib
import random
import time
import pystyle
import base64

baseTypes = ['b85', 'b64', 'b32', 'b16']

# This Function I Pasted from https://github.com/Zrexer/BrupRocket

hashlist = ['sha1', 'sha256', 'sha224', 'sha512', 'sha384', 'sha3_256', 'sha3_224', 'sha3_512', 'sha3_384']

def createHasher(text : str, type_of_encrypt : str):
        """
        Hash Creator
        ~~~~~~~~~~~~~
        ```
        from BrupRocket import BrupRocket as br
        
        app = br()
        data = app.createHasher(text="Hello world", type_of_encrypt="md5")
        print(data)
        ```
        
        Available Type of hash: 
        
        `md5`
        `sha1`
        `sha256`
        `sha224`
        `sha512`
        `sha384`
        `sha3_256`
        
        or you can select a random type , just use "random" on parameter.
        
        """
        
        t = type_of_encrypt
        
        if t == "md5":
            md5 = hashlib.md5()
            md5.update(text.encode())
            return md5.hexdigest()
        
        elif (
            t == "sha1"
            ):
            sha1 = hashlib.sha1()
            sha1.update(
                text.encode()
                )
            return (
                sha1.hexdigest()
                )
        
        elif (
            t == "sha256"
            ):
            sha256 = hashlib.sha256()
            sha256.update(
                text.encode()
                )
            return (
                sha256.hexdigest()
                )
        
        elif (
            t == "sha224"
            ):
            sha224 = hashlib.sha224()
            sha224.update(
                text.encode()
                )
            return (
                sha224.hexdigest()
                )
        
        elif (
            t == "sha512"
            ):
            sha512 = hashlib.sha512()
            sha512.update(
                text.encode()
                )
            return (
                sha512.hexdigest()
                )
        
        elif (
            t == "sha384"
            ):
            sha384 = hashlib.sha384()
            sha384.update(
                text.encode()
                )
            return (
                sha384.hexdigest()
                )
        
        elif (
            t == "sha3_256"
            ):
            sha3_256 = hashlib.sha3_256()
            sha3_256.update(
                text.encode()
                )
            return (
                sha3_256.hexdigest()
                )
        
        elif (
            t == "sha3_224"
            ):
            sha3_224 = hashlib.sha3_224()
            sha3_224.update(
                text.encode()
                )
            return (
                sha3_224.hexdigest()
                )
        
        elif (
            t == "sha3_512"
            ):
            sha3_512 = hashlib.sha3_512()
            sha3_512.update(
                text.encode()
            )
            return (
                sha3_512.hexdigest()
            )
            
        elif (
            t == "sha3_384"
        ):
            sha3_384 = hashlib.sha3_384()
            sha3_384.update(
                text.encode()
            )
            return (
                sha3_384.hexdigest()
            )
            
        elif (
            t == "random"
        ):
            result = (
                random.choice(hashlist)
            )
            
            return createHasher(text=text, type_of_encrypt=result)
        

def encrypt(text : str):
    
    if text.startswith("b64"):
        new_text = text.replace("b64 ", "")
        return base64.b64encode(new_text.encode("ascii"))
        
    elif text.startswith("b32"):
        new_text = text.replace("b32 ", "")
        return base64.b32encode(new_text.encode("ascii"))
        
    elif text.startswith("b16"):
        new_text = text.replace("b16 ", "")
        return base64.b16encode(new_text.encode("ascii"))
        
    elif text.startswith("b85"):
        new_text = text.replace("b85 ", "")
        return base64.b85encode(new_text.encode("ascii")) 

class Box:
    def __init__(self,
                 msg: str = None
                 ) -> None:
        
        self.msg = msg
        self.writer = pystyle.Write.Print
        self.colors = pystyle.Colors
    
    @property
    def infoMessageBox(self):
        
        self.writer('[{}] [{}] {}'.format(time.strftime('%H:%M:%S'), "INFO", self.msg), self.colors.red_to_purple, 0)
        print()
    
    @property
    def errorMessageBox(self):
        
        self.writer('[{}] [{}] {}'.format(time.strftime('%H:%M:%S'), "ERROR", self.msg), self.colors.red_to_yellow, 0)
        print()
     
    @property   
    def warningMessageBox(self):
        
        self.writer('[{}] [{}] {}'.format(time.strftime('%H:%M:%S'), "WARNING", self.msg), self.colors.yellow_to_green, 0)
        print()
    
    @property
    def bannerMode(self):
        
        self.writer(self.msg, self.colors.red_to_purple, 0)
        print()
    
    @property
    def createDash(self):
        
        self.writer('--------------------------------------------', self.colors.yellow_to_red, 0)
        print()
    
    def nullPrint():
        print("")
        


banner = """
 ___ ___             __               
|   Y   .---.-.-----|  |--.-----.----.
|.  1   |  _  |__ --|     |  -__|   _|
|.  _   |___._|_____|__|__|_____|__|  
|:  |   |                             
|::.|:. |                             
`--- ---'           

            {}

""".format('{DEV#Host1let}')

writer = pystyle.Write.Print
colors = pystyle.Colors

def HelpUsage(numD):
    
    dictX = {
        'command' : [
            {
                'command' : 'help',
                'info' : 'show message',
                'usage' : 'type " help "'
            },
            {
                'command' : 'hash',
                'info' : 'json to hash',
                'usage' : 'hash #<URL> ... type #<TYPE> : type is optional' 
            },
            {
                'command' : 'base',
                'info' : 'json to base family',
                'usage' : 'hash #<URL> ... type #<TYPE> : type is optional' 
            },
            {
                'command' : 'hash-types',
                'info' : 'show types of hash family',
                'usage' : 'type " hash-types "'
            },
            {
                'command' : 'base-types',
                'info' : 'show types of base family',
                'usage' : 'type " base-types "'
            },
            {
                'command' : 'exit',
                'info' : 'exit the program',
                'usage' : 'type " exit "'
            }
        ]
    }
    
    return dictX['command'][numD]


class MainActivity:
    
    def Main():
        
        Box(banner).bannerMode
        
        while 1:
            
            u = writer('\nJsonHasher > ', colors.red_to_purple, 0)
            user = str(input(""))
            text = user.split()
            
            if user == "help":
                l = [0, 1, 2, 3, 4, 5]
                
                for ls in l:
                    
                    com = HelpUsage(ls).get('command')
                    info = HelpUsage(ls).get('info')
                    usage = HelpUsage(ls).get('usage')
                    writer('{}'.format(f"""\n[+] Command: {com}
[+] Info: {info}
[+] Usage: {usage}"""), colors.red_to_purple, 0)
                    print()
            
            
            if user == 'exit':
                exit(Box('EXIT').warningMessageBox)
            
            
            if "hash" in text:
                if 'type' in text:
                    type_ = str(text[text.index('type')+1])
                    url = str(text[text.index('hash')+1])
                    
                    try:
                        req = str(requests.get(url).json())
                        Box(createHasher(req, type_)).infoMessageBox
                    
                    except Exception as E:
                        Box('Faild To Process: {}'.format(E)).errorMessageBox
                        Box('Check Environments and try Again').warningMessageBox
                        pass
                    
                else:
                    urlx = str(text[text.index('hash')+1])
                    
                    try:
                        req = str(requests.get(urlx).json())
                        Box(createHasher(req, 'random')).infoMessageBox
                    
                    except Exception as E:
                        Box('Faild To Process: {}'.format(E)).errorMessageBox
                        Box('Check Environments and try Again').warningMessageBox
                        pass
                    
            if "base" in text:
                if 'type' in text:
                    type_ = str(text[text.index('type')+1])
                    url = str(text[text.index('base')+1])
                    
                    try:
                        req = str(requests.get(url).json())
                        Box(encrypt(f'{type_}'+req)).infoMessageBox
                    
                    except Exception as E:
                        Box('Faild To Process: {}'.format(E)).errorMessageBox
                        Box('Check Environments and try Again').warningMessageBox
                        pass
                    
                else:
                    urlx = str(text[text.index('base')+1])
                    
                    try:
                        req = str(requests.get(urlx).json())
                        ty = str(random.choice(baseTypes))
                        Box(encrypt(f"{ty}"+req)).infoMessageBox
                    
                    except Exception as E:
                        Box('Faild To Process: {}'.format(E)).errorMessageBox
                        Box('Check Environments and try Again').warningMessageBox
                        pass
                    
            if "base-types" in text:
                Box(baseTypes).infoMessageBox
                
            if "hash-types" in text:
                Box(hashlist).infoMessageBox

if __name__ == "__main__":
    MainActivity.Main()
