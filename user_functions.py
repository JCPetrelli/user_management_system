import sqlite3
import hashlib
import re

def create_database(db_path):
    """
    Create a SQLite database with a specific schema for user management.

    This function establishes a connection to a SQLite database located at the specified path. If the database 
    does not exist, it is created. The function then defines and executes a SQL query to create a 'users' table 
    if it doesn't already exist. The 'users' table includes fields for id, email, password, activation status, 
    registration date, and activation date. The email field is unique for each user. The function commits these 
    changes to the database and then closes the connection.

    Parameters:
    db_path (str): The file path where the SQLite database is stored or will be created.

    Note:
    This function does not perform error handling for database connection issues or SQL execution errors.
    """

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Define schema
    CREATE_TABLE_QUERY = '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT FALSE,
            registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            activation_date TIMESTAMP NULL
        )
    '''

    # Create table with proper schema
    cursor.execute(CREATE_TABLE_QUERY)
    conn.commit()
    conn.close()

def is_valid_password(password):
    """
    Check if the provided password meets certain complexity requirements.

    This function validates a password by checking if it contains at least one numeral and one special character.
    Special characters are defined as any of the following: !@#$%^&*(),.?":{}|<>.
    The function returns True if the password contains at least one of these special characters and at least one numeral.
    Otherwise, it returns False. This validation helps ensure that the password is complex enough to provide better security.

    Parameters:
    password (str): The password to be validated.

    Returns:
    bool: True if the password meets the complexity requirements, False otherwise.
    """

    # Check for at least one number and one special character
    if re.search(r"[0-9]", password) and re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return True
    return False

def is_valid_email(email):
    """
    Check if the provided email address is valid.

    This function uses a regular expression pattern to validate the format of an email address.
    The pattern checks for a standard email format: one or more characters that can include
    letters (a-z, A-Z), numbers (0-9), periods (.), underscores (_), percent signs (%), plus signs (+),
    and hyphens (-), followed by an '@' symbol, then more characters including letters and numbers, 
    periods, and hyphens, and finally, a period followed by a domain suffix of two or more letters.

    Parameters:
    email (str): The email address to be validated.

    Returns:
    bool: True if the email is valid, False otherwise.
    """

    # Regex pattern for validating an email
    pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    if re.match(pattern, email):
        return True
    return False

def hash_password(password):
    """
    Hash a password using SHA-256 encryption.

    This function takes a plaintext password and returns its hashed version using the SHA-256 hashing algorithm.
    Hashing is a one-way process, useful for storing passwords securely. The output is a hexadecimal string
    representation of the hashed password. As a security best practice, passwords should be hashed rather than
    stored in plaintext.

    Parameters:
    password (str): The plaintext password to be hashed.

    Returns:
    str: The hashed password as a hexadecimal string.
    """

    return hashlib.sha256(password.encode()).hexdigest()

def register_user(db_path, email, password):
    """
    Register a new user in the database with their email and password.

    This function first validates the email and password using `is_valid_email` and `is_valid_password` functions.
    If either is invalid, it returns False with an appropriate error message. If both are valid, it connects to 
    the SQLite database at the specified path and checks if the email is already registered. If the email is unique, 
    it inserts a new record into the 'users' table with the hashed password and sets 'is_active' to False by default.
    Finally, it commits the changes to the database and closes the connection.

    Parameters:
    db_path (str): The file path of the SQLite database.
    email (str): The email address of the user to register.
    password (str): The password of the user to register.

    Returns:
    tuple: A tuple containing a boolean and a string message. The boolean is True if registration is successful,
        False otherwise. The string contains a success message or an error message.
    """

    if not is_valid_email(email):
        return False, "Invalid email format"

    if not is_valid_password(password):
        return False, "Password should contain at least one digit and one special character."
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Check if email already exists
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return False, "Email already registered"

    # Insert new user into db
    hashed_password = hash_password(password)
    cursor.execute(f"INSERT INTO users (email, password, is_active) VALUES (?, ?, ?)",
                   (email, hashed_password, False))
    
    conn.commit()
    conn.close()
    return True, "Registration successful"

def activate_user(db_path, email):
    """
    Activate a user's account in the database based on their email.

    This function connects to the SQLite database and checks if a user with the given email exists. If the user
    exists, it updates the 'is_active' field to True and sets the 'activation_date' to the current timestamp, 
    indicating that the user's account is now active. It then commits these changes to the database and closes 
    the connection.

    Parameters:
    db_path (str): The file path of the SQLite database.
    email (str): The email address of the user whose account is to be activated.

    Returns:
    tuple: A tuple containing a boolean and a string message. The boolean is True if the activation is successful,
        False otherwise. The string contains a success message or an error message.
    """

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Check if the user exists
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    if cursor.fetchone() is None:
        conn.close()
        return False, "User not found"

    # Update the is_active field and set activation_date to current timestamp
    cursor.execute("UPDATE users SET is_active = ?, activation_date = CURRENT_TIMESTAMP WHERE email = ?",
                   (True, email))
    conn.commit()
    conn.close()
    return True, "User activated"

def authenticate_user(db_path, email, password):
    """
    Authenticate a user by verifying their email and password.

    This function connects to the SQLite database to retrieve the stored hashed password and the activation status
    for the given email. It then compares the provided password, after hashing it, with the stored hashed password.
    If they match and the account is activated ('is_active' is True), the authentication is successful. The function
    closes the database connection before returning.

    Parameters:
    db_path (str): The file path of the SQLite database.
    email (str): The email address of the user to authenticate.
    password (str): The password provided by the user for authentication.

    Returns:
    tuple: A tuple containing a boolean and a string message. The boolean is True if authentication is successful,
        False otherwise. The string contains a success message or an error message.
    """

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT password, is_active FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    if result and hash_password(password) == result[0] and result[1]:
        return True, "Authentication successful"
    
    conn.close()
    return False, "Invalid credentials or account not activated"

def reset_password(db_path, email, new_password):
    """
    Reset the password for a user in the database.

    This function connects to the SQLite database and checks if a user with the specified email exists. If the user
    exists, it updates their password with the new password provided, after hashing it. The function then commits
    these changes to the database and closes the connection.

    Parameters:
    db_path (str): The file path of the SQLite database.
    email (str): The email address of the user whose password is to be reset.
    new_password (str): The new password to set for the user.

    Returns:
    tuple: A tuple containing a boolean and a string message. The boolean is True if the password reset is successful,
        False otherwise. The string contains a success message or an error message.
    """

    if not is_valid_password(new_password):
        return False, "Password should contain at least one digit and one special character."

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Check if the user exists
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    if cursor.fetchone() is None:
        conn.close()
        return False, "User not found"

    # Update the password
    hashed_password = hash_password(new_password)
    cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
    conn.commit()
    conn.close()
    return True, "Password reset successfully"

if __name__ == '__main__':
    DB_PATH = 'users.db'
    create_database(DB_PATH)
    register_user(DB_PATH, "jacksparrow@gmail.com", "myweakpassword$12")
    activate_user(DB_PATH, "jacksparrow@gmail.com")
    print("The next should be False:")
    print(authenticate_user(DB_PATH, "jackiechan@gmail.com", "myveryweakpass&12"))
    print("The next should be True:")
    print(authenticate_user(DB_PATH, "jacksparrow@gmail.com", "myweakpassword$12"))
    print("The following user will not be registered:")
    result = register_user(DB_PATH, "myemail@dd.com", "pass")
    print(result)