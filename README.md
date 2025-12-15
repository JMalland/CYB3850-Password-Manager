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

This will list all services that there exists credentials for, using their custom name. Usernames for the credentials are included next to the service's custom name. Private credentials will display [LOCKED] next to them.


[2. VIEW CREDENTIALS]
___________________________________________________________________

Here, you will enter a service's custom name or website name. If there are multiple matches for your search query, each appropriate result will be displayed. Private credentials will require that you type in your master password to view.

Upon viewing the selected credentials, you may press [v] to reveal the password, [h] to hide it, and [esc] to head back to the main option screen.


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

Here, you will select the credentials you wish to edit by searching for its name. Upon selecting the desired credentials, you will then be asked to re-enter the credential information, where you may enter the new information instead.

For each segment of the login, the old information will be enclosed in square brackets (example: Website [OldName]: <enter new name>)

Upon reaching the password re-entry, you may choose to keep the old password by pressing enter. You may also re-configure its private status.


[5. DELETE CREDENTIALS]
___________________________________________________________________

Here, you will simply be prompted for the name of the service you wish to delete. Upon entering [y] when prompted, the entry for the selected service will be deleted.



[6. SEARCH CREDENTIALS]
___________________________________________________________________

Here, you will be given four methods to search for credentials by:
-----------------
1. By website
2. By custom name
3. By username
4. All fields
-----------------

Upon searching using one of the options, all matching results will be provided; each will adhere to the following format:
- [CUSTOM NAME] (Web: [WEBSITE NAME], User: [USERNAME])


[7. ACCOUNT SETTINGS]
___________________________________________________________________

Here, you may edit information about your password manager account. The following options are given:
-----------------
1. Change Username
2. Change Password
3. Customize Keybindings
4. Delete Account
5. Back
-----------------

For customize keybindings, you may change the keybindings for reveal, hide, and exit when viewing credentials. By default, reveal is [v], hide is [h], and exit is [esc].


[8. LOGOUT]
___________________________________________________________________

This option simply logs you out of your master account.

