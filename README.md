# Password-Manager


Features:
Master Password Setup: Users can set up a master password to access the password manager.
Credential Storage: Stores service names, usernames, and passwords in an encrypted format.
Credential Retrieval: Allows users to retrieve stored credentials by entering the service name.
Encryption: Uses the cryptography library for encryption, ensuring secure storage of credentials.
Usage:

Setting up Master Password:
Run the script.
If it's the first time running the script, it will prompt you to set up a master password. Enter a master password and click "Create". The master password will be securely encrypted and stored.

Logging In:

After setting up the master password, run the script again.
Enter the master password to access the password manager interface.

Managing Credentials:

Once logged in, you can add, retrieve, and manage credentials using the provided interface.
Enter the service name, username, and password, then click "Save Credentials" to store them securely.
To retrieve stored credentials, enter the service name and click "Retrieve Credentials".

Dependencies:

Python 3.x
cryptography library (Install using pip install cryptography)
tkinter library (Usually included with Python installation)

Notes:

Ensure that you remember your master password as it will be required to access stored credentials.
For enhanced security, avoid using easily guessable passwords as your master password and for stored credentials.
