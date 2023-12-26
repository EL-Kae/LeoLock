"""	
Description:
    This application Leo's Lock. Please read the README for more information 
    and installation steps. The database uses only one table, the username is 
    the primary key and must be unique.

Usage:
    python leolock.py
    
Todo:
    Implement sqlite database --DONE
    Read in user input and turn into tuple --DONE
    export tuples to the database --DONE
    create the game loop --DONE
    Given a (Username, Password) pair in ASCII; store the pair to a file --DONE
    Given a username, retrieve the password. --DONE
    Implement cbc and ctr mode --DONE
    Given a (Username, Password) pair in ASCII; check if the username exists 
    	and if the password matches the one stored in a file. --DONE
    add bells and whistles --DONE
    finish the "what this does" section --DONE
    add more print statements so the user knows whats going on. --DONE
    add comments --DONE
    Implement hashing based key system --DONE
    Implement commands: 
    	-search, 
    	-create, 
    	-login, 
    	-delete, 
    	-deleteall, 
    	-help 
	
About:
    By Leo Kaestner
"""

import pyaes
import os
import sqlite3
import pbkdf2

'''
The main function greets the user with a prompt, creates a master key, IV and a
sqlite3 database to store the username/password entry. Passwords are checked, 
decrypted, and retrieved here. /delete and /quit are implemented here as well. 
When the user quits the application, the table is dropped and the database is 
deleted. All current entries will be deleted. The prompt run in an infinite
loop until /quit is typed.
'''
def main():
    connDB = sqlite3.connect('leolock.db')	#Establishes connection to db.
    masterKey = os.urandom(32)	#Creates a random masterkey.
    myIV = os.urandom(16)	#Creates a random IV.
    myCursor = connDB.cursor() #Creates a cursor and a table afterwards.
    createTable(myCursor)

    #Greeting prompt.
    print 
    print "====================== Welcome to Leo's Lock! ======================"
    print 
    print "Type in a new username/password to create a new entry."
    print "Type in an existing username to retrieve its password."
    print "Type in an existing username & password to check that password."
    print 
    print "These built-in commands can be typed in at the username/password"
    print "prompt at anytime:"
    print "\t\"/delete\": Deletes all entry in the database."
    print "\t\"/quit\": Quits the application."
    print 
    
    #game loop starts here
    while (1):
        userInput = raw_input("Please enter <username> [password]: ")

        if userInput == "/quit":	#Implements the /quit command.
            print "Quitting application...."
            break

        if userInput == "/delete":	#Implements the /delete command.
        	print "Deleting all entries...."
        	myCursor.execute(''' DROP TABLE USERS''')
        	connDB.commit()
        	createTable(myCursor)
        	continue

		#Allows the user to retrieve a password.
        if len(userInput.split(" ")) == 1:	
        	tupleSearch = (userInput,)
        	print "Searching for existing username...."
        	myCursor.execute('''SELECT * FROM USERS 
        						WHERE userName = ?''', tupleSearch)
        	userRow = myCursor.fetchone()

        	if userRow is not None: #If the password matches.
        		print "Username found!"
        		print "Password is: " + decryptPassword(userRow[2], userRow[1],\
        											    masterKey, myIV)
        	else:
        		print "Username does not exist." #If not match is found.

        #Allows user to add a username/password combination into the database.	
        else:
        	#Checks for existing username.	
        	print "Searching for existing username...."
        	myCursor.execute('''SELECT * FROM USERS 
        					WHERE userName = ?''', (userInput.split(" ")[0],))
        	userRow = myCursor.fetchone()

        	if userRow is not None:
        		print "Username matched!"
        		print "Checking for password...."
        		decryptee = decryptPassword(userRow[2], userRow[1], \
        			masterKey, myIV)

        		#print userInput.split(" ")[1]
        		#print decryptee

        		#Checks if the password matches.
        		if decryptee.rstrip("\0") == userInput.split(" ")[1]:
        			print "Passwords matched!"
        		else:
        			print "Incorrect Password."

	        else: #If the username/password doesn't exist, create a new entry.
	        	print "Username does not exist."
	        	print "Creating new username/password entry...."

	        	#Prompts the user to specify mode of operation.
		        flagType = raw_input \
		        	("Which type of AES encryption would you like to use: ")

		        #Checks for valid flag.
		        if flagType!="ecb" and flagType != "cbc" and flagType != "ctr":
		        	print "Error! Valid flags are: \"ecb\", \"cbc\", \"ctr\""
		        	print "Failed to create new entry."
		        	continue

		        if flagType == "ecb" and userInput.split(" ")[1].len() > 16:
		        	print "Error! password to long for ecb mode."
		        	print ""

		        #Encrypts the user's password.
		        encryptPW = encryptPassword(flagType, userInput.split(" ")[1], \
		        							masterKey, myIV)

		        #Inserts the username, password and flag into the db.
		        currentTuple = [userInput.split(" ")[0], \
		        				sqlite3.Binary(encryptPW), flagType]

		        #print "%s\n" % (currentTuple)

		        myCursor.execute(''' INSERT into USERS(userName, passWord, flag) 
		                                VALUES (?,?,?) ''', currentTuple)
		        connDB.commit()
		        print "New entry created."

    #game loop ends here

    #Deletes the database and closes the connection.
    myCursor.execute(''' DROP TABLE USERS''')
    connDB.commit()
    connDB.close()
    os.remove("leolock.db")


'''
Creates a table for the database.
'''
def createTable(currentCursor):
	currentCursor.execute('''CREATE TABLE IF NOT EXISTS USERS(
                        	userName TEXT PRIMARY KEY   NOT NULL,
                        	passWord    TEXT            NOT NULL,
                        	flag        TEXT            NOT NULL);''')


'''
Encrypts the password according the mode of operation using the pyaes library.
The encrypted password is then returned.
'''
def encryptPassword(currentFlag, currentPW, currentKey, currentIV):
	if currentFlag == "ecb":	#Encrypts in ECB mode.
		aes = pyaes.AESModeOfOperationECB(currentKey)
		plaintext = currentPW.ljust(16,"\0")
		return aes.encrypt(plaintext)

	if currentFlag == "cbc":	#Encrypts in CBC mode.		
		aes = pyaes.AESModeOfOperationCBC(currentKey, iv = currentIV)
		plaintext = currentPW.ljust(16, "\0")
		return aes.encrypt(plaintext)

	if currentFlag == "ctr":	#Encrypts in CTR mode.
		aes = pyaes.AESModeOfOperationCTR(currentKey)
		return aes.encrypt(currentPW)


'''
Decrypts the password according the mode of operation using the pyaes library.
The decrypted password is then returned.
'''
#Decrypts the user's password using the pyaes library
def decryptPassword(currentFlag, ciphertext, currentKey, currentIV):
	if currentFlag == "ecb":	#Decrypts in ECB mode.
		aes = pyaes.AESModeOfOperationECB(currentKey)
		return aes.decrypt(ciphertext)

	if currentFlag == "cbc":	#Decrypts in CBC mode.
		aes = pyaes.AESModeOfOperationCBC(currentKey, iv = currentIV)
		return aes.decrypt(ciphertext)

	if currentFlag == "ctr":	#Decrypts in CTR mode.
		aes = pyaes.AESModeOfOperationCTR(currentKey)
		return aes.decrypt(ciphertext)

def cmdCreate():
	userInput = raw_input("Please enter <username> <password>: ")

def cmdSearchPassword():
	userInput = raw_input("Please enter <username> <password>: ")

def cmdDelete():
	userInput = raw_input("Please enter <username>: ")

if __name__ == '__main__':
    main()
