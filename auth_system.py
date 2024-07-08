# Import required libraries and modules
import hashlib
import os
import csv
import re

# Constants
SALT_SIZE = 16  # Define length of the SALT
PEPPER = b"secret-pepper-set-in-code"  # Define PEPPER
pass_file = "./users.txt"  # Password file

# Create empty lists
swear_words = []  # Bad words
weak_passwords = []  # Weak passwords
breached_passwords = []  # Breached passwords

# Read words from a file and append them to the provided list.
# param filename: The name of the file to read.
# param words_list: The list to append the words to.
def read_words_from_file(filename, words_list):
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as csvfile:
                reader = csv.reader(csvfile)
                for row in reader:
                    for word in row:
                        words_list.append(word)
        except Exception as e:
            print(f"Error: An error occurred while opening and reading the file {filename}: {e}")
            return False


#Populate the lists of swear_words, weak_passwords, and breached_passwords by reading the corresponding files.
def populate_lists():
    #Use global variables for swear_words, weak_passwords, and breached_passwords
    global swear_words
    global weak_passwords
    global breached_passwords
    
    # Fill the list of the bad words
    # Source of swear words are from https://www.cs.cmu.edu/~biglou/resources/bad-words.txt
    print('populating swear words list')
    read_words_from_file(filename='./bad_words_list.txt', words_list=swear_words)
    
    # Fill the list of the weak passwords
    print('populating week passwords list')
    read_words_from_file(filename='./weakpasswords.txt', words_list=weak_passwords)
    
    # Fill the list of the breached password
    print('populating breached passwords list')
    read_words_from_file(filename='./breachedpasswords.txt', words_list=breached_passwords)


#   Generate a random salt using the global SALT_SIZE.
#   return: A random salt of length SALT_SIZE.
def generate_salt():
    # Use global variable SALT_SIZE
    global SALT_SIZE
    return os.urandom(SALT_SIZE)


#  Hash a password using the provided salt and the global PEPPER.
#  param password: The password to hash.
#  param salt: The salt to use in the hashing process.
#  return: The hashed password.
def hash_password(password, salt):
    # Use global variable PEPPER
    global PEPPER
    password_pepper = password.encode("utf-8") + PEPPER
    # Reference: https://readthedocs.org/projects/lmctvpynacl/downloads/pdf/changelog_for_481_and_485/
    return hashlib.scrypt(password_pepper, salt=salt, n=2**14, r=8, p=1, dklen=64)



# Check if the file at the given path exists and if it is empty.   
# :param file_path: The path of the file to check.
# :return: True if the file exists and is empty, otherwise False.
def is_file_exists_empty(file_path):
    # Check if file exists
    if os.path.exists(file_path):
        # Check if file size is zero
        if os.stat(file_path).st_size == 0:
            return True
        else:
            return False
    else:
        # Create the file if it doesn't exist
        with open(file_path, "w"):
            pass
        return True



# Check if the username contains any swear words with common character substitutions (Leet).
# :param username: The username to check.
# :param swear_words: A list of swear words.
# :return: True if a swear word is found after substitutions, otherwise False.
def check_swear_substitution(username, swear_words):
    # Reference: https://en.wikipedia.org/wiki/Leet
    swear_substitutions = {"i": ["1", "!", "l"], "e": ["3"], "a": ["4", "@"], "s": ["5", "$"], "o": ["0"], "t": ["7"]}
    for word in swear_words:
        for letter, substitutions in swear_substitutions.items():
            pattern = f"{letter}|" + "|".join(substitutions)
            if re.search(pattern, word, flags=re.IGNORECASE):
                for substitution in substitutions:
                    modified_word = word.replace(letter, substitution)
                    if modified_word in username:
                        print('\n\n***************************************\nSwear word has been found after Leet chars substitution.\n\n***************************************\n')
                        return True
    return False


# Add a new user with the provided username and password to the password file.
# :param username: The username of the new user.
# :param password: The password of the new user.
# :return: True if the user was added successfully, otherwise False.
def add_user(username, password):
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    try:
        with open(pass_file, "a") as f:
            f.write(f"{username}:{salt.hex()}${hashed_password.hex()}\n")
        print("User added successfully")
        return True
    except FileNotFoundError:
        print(f"Error: Unable to open or find the file {pass_file}")
        return False
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")
        return False


# Check if the provided username exists in the password file.
# :param username: The username to check for.
# :return: True if the username exists, otherwise False.
def username_exists(username):
    # Use global variable pass_file
    global pass_file
    if is_file_exists_empty(pass_file):
        return False
    else:
        try:
            with open(pass_file, 'r') as csvfile:
                reader = csv.reader(csvfile, delimiter=':')
                for row in reader:
                    if username == row[0]:
                        return True
                return False
        except Exception as e:
            print(f"Error: An error occurred while opening and reading the file {pass_file}: {e}")
            return False


# Check if the provided username and password match the stored credentials.
# :param username: The username to check.
# :param password: The password to check.
# :return: A string indicating the result of the credentials check.
def check_credentials(username, password):
    # Use global variable pass_file
    global pass_file
    try:
        with open(pass_file, "r") as f:
            for line in f:
                line = line.strip()
                parts = line.split(":")
                if parts[0].casefold() == username.casefold():
                    salt_hex, hashed_password_hex = parts[1].split("$")
                    salt = bytes.fromhex(salt_hex)
                    hashed_password = bytes.fromhex(hashed_password_hex)
                    if hash_password(password, salt) == hashed_password:
                        print("\n\n***************************************\nLogin successful.\n\n***************************************\n")
                        return 'Login successful'
                    else:
                        print("\n\n***************************************\nIncorrect username or password.\n\n***************************************\n")
                        return 'Incorrect password'
                
            print("\n\n***************************************\nUsername does not exist\n\n***************************************\n")
            return 'Username does not exist'
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")
        return 'Error Occured'


# Check if the provided username is valid according to the specified rules.
# :param username: The username to check.
# :return: True if the username is valid, otherwise False.
def check_username(username):
    # Use global variable which is a list swear_words
    global swear_words
    # Convert username to lowercase
    username = username.lower()

    # Check that the username length
    if len(username) < 6 or len(username) > 31:
        print('\n\n***************************************\nUsername number of chars needs to be in between 7 and 30.\n\n***************************************\n')
        return False

    # Check that the username only contains characters from the set [a-zA-Z0-9_]
    if not re.match("^[a-zA-Z0-9_]*$", username):
        print('\n\n***************************************\nUsername chars needs to be in "a-zA-Z0-9_"\n\n***************************************\n')
        return False

    # Check that the username does not contain any swear words
    if any(word in username for word in swear_words):
        print('\n\n***************************************\nUsername has a swear word.\n\n***************************************\n')
        return False

    if check_swear_substitution(username, swear_words):
        return False

    return True


# Register a new user with the provided username and password.
# :param username: The username of the new user.
# :param password: The password of the new user.
# :param password2: The confirmation password of the new user.
# :return: A string indicating the result of the registration.
def register(username, password, password2):
    # Use global variables for PEPPER and SALT_SIZE
    global PEPPER
    global SALT_SIZE
    # Convert the username to lowercase    
    username = username.lower()
    if not check_username(username):
        print('\n\n***************************************\nUsername is not allowed.\n\n***************************************\n')
        return "Username is not allowed."
    
    if username_exists(username):
        print(f'\n\n***************************************\n{username} username already exist in the system.\n\n***************************************\n')
        return f"{username} username already exist in the system."
    if password.strip() == "":
        print("\n\n***************************************\nPassword cannot be empty.\n\n***************************************\n")
        return "Password cannot be empty."
    elif password.casefold() != password2.casefold():
        print("\n\n***************************************\nPassword and Retyped password do not match.\n\n***************************************\n")
        return "Password and Retyped password do not match."
    elif username.casefold() == password.casefold():
        print("\n\n***************************************\nUsername and password cannot be same.\n\n***************************************\n")
        return "Username and password cannot be same."
    # Check that password is not in weak passwords list.
    elif any(word.casefold() == password.casefold() for word in weak_passwords):
        print('\n\n***************************************\nA weak password has been set. Please try other password.\n\n***************************************\n')
        return "A weak password has been set. Please try other password."
    # Check that password is not in breached passwords list.
    elif any(word.casefold() == password.casefold() for word in breached_passwords):
        print('\n\n***************************************\nA breached password has been set. Please try other password.\n\n***************************************\n')
        return "A breached password has been set. Please try other password."

    if add_user(username, password):
        print("\n\n***************************************\nRegistration successful.\n\n***************************************\n")
        return "Registration successful."
    else:
        return "Some issue in saving the credentials. please contact system admin"

# Login a user with the provided username and password.
# :param username: The username of the user.
# :param password: The password of the user.
# :return: A string indicating the result of the login.

# Login function
def login(username, password):
    # Use global variables for PEPPER and pass_file
    global PEPPER
    global pass_file
    
    # Check if the username is empty
    if username.strip() == "":
        print("\n\n***************************************\nUsername cannot be empty.\n\n***************************************\n")
        return "Username cannot be empty."
    
    # Check if the password is empty
    if password.strip() == "":
        print("\n\n***************************************\nPassword cannot be empty.\n\n***************************************\n")
        return "Password cannot be empty."
    
    # Check if the password file exists and is not empty
    if is_file_exists_empty(pass_file):
        print(f"\n\n***************************************\n password file does not exist in system\n\n***************************************\n")
        return "Incorrect username or password."

    # Check the user credentials for a match
    login_status = check_credentials(username, password)

    # Return the appropriate message based on the login status
    if login_status == 'Login successful':
        return "Login successful."
    elif login_status == 'Incorrect password' or login_status == 'Username does not exist':
        return 'Incorrect username or password.'
    elif login_status == 'Error Occured':
        return 'Some issue in checking the credentials. please contact system admin.'
    else:
        return "Incorrect username or password."

#Call the function to populate the lists for swear words, weak passwords, and breached passwords
populate_lists()