#######################################################

# Python Password Manager

### Usage: `main.py [OPTIONS] COMMAND [ARGS]`...

####  Password Manager - Secure credential storage

##### Options:
 - `--help` - Show this message and exit.

##### Commands:
 
 - `login` - Login and access your credentials

 - `register` - Create a new account

#######################################################




This program allows you to encrypt a slew of login credentials in a database to keep track of your account information across multiple different platforms.




[REGISTERING A USER]
___________________________________________________________________

When running the program using the "register" command, you will be presented with three input fields, appearing one after another once an input is provided for each:
-----------------
Name:
Username:
Master Password:
-----------------
For "Name," enter your actual name. For "Username," enter what you would like to be identified as in the program. "Master Password" serves as your account's password.

You may have multiple accounts on the database, each stories their own seperate credentials that are inaccessible to other users.



[LOGGING IN]
___________________________________________________________________

When running the program using the "login" command, you will be presented with fields for your username and password. To login, enter the account information that you have created using the "register" command.

Once logged in, you will be presented with 8 seperate options:
------------------------
1. List all services
2. View credentials
3. Add credentials
4. Edit credentials
5. Delete credentials
6. Search credentials
7. Account settings
8. Logout
------------------------

Simply enter a number 1-8 corresponding with whichever option you desire.


[1. LIST ALL SERVICES]
___________________________________________________________________




[2. VIEW CREDENTIALS]
___________________________________________________________________




[3. ADD CREDENTIALS]
___________________________________________________________________

This option will present you with the following fields:
-----------------
Website:
Custom Name:
Username:
Password:
Private? [y/N]:
-----------------

The website field is simply the name of the website. The custom name field allows you to have a different name for it as opposed to the website's name. This way, you can save multiple logins for the same service and have them distinguished by their custom names. The username and password fields are simply the login credentials for the service. For the private field, choose yes if you would like an extra layer of security when viewing this credential's information later on. If you do, it will require the master password once again to view it.


[4. EDIT CREDENTIALS]
___________________________________________________________________




[5. DELETE CREDENTIALS]
___________________________________________________________________




[6. SEARCH CREDENTIALS]
___________________________________________________________________




[7. ACCOUNT SETTINGS]
___________________________________________________________________




[8. LOGOUT]
___________________________________________________________________



