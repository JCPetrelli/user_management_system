import os
import sqlite3
import pytest
from user_functions import create_database
from user_functions import is_valid_password
from user_functions import is_valid_email
from user_functions import hash_password
from user_functions import register_user
from user_functions import activate_user
from user_functions import authenticate_user
from user_functions import reset_password


@pytest.fixture
def temp_db_path(tmp_path):
    """Fixture to create a temporary database path."""
    return tmp_path / "tests.db"

@pytest.fixture
def db_connection(temp_db_path):
    """Fixture to create a database and provide a connection to it."""
    create_database(temp_db_path)
    conn = sqlite3.connect(temp_db_path)
    yield conn
    conn.close()

def test_database_created(temp_db_path):
    """Test if the database file is created."""
    create_database(temp_db_path)
    assert os.path.exists(temp_db_path)

def test_users_table_created(db_connection):
    """Test if the users table is created with the correct schema."""
    cursor = db_connection.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    table_exists = cursor.fetchone()
    assert table_exists is not None

def test_is_valid_password():
    """Test if passwords are validated correctly"""
    # Check if password is correct
    assert is_valid_password("validpass%1")
    # Check if password without digit is invalid
    assert not is_valid_password("notvalidpass&")
    # Check if password without special character is invalid
    assert not is_valid_password("notvalidpass1")
    # Check if empty password is invalid
    assert not is_valid_password("")

def test_is_valid_email():
    """Test if emails are validated correctly"""
    # Check if email is correct
    assert is_valid_email("info@correct.com")
    # Check if a wrong email is invalid
    assert not is_valid_email("info.notcorrect.com")
    # Check if empty email is invalid
    assert not is_valid_email("")
    
def test_hash_password_behavior():
    """Test various behaviors of the hash_password function."""
    password = "my_password123!"
    another_password = "different_password456@"

    # Test that hashing a password returns a string
    hashed_password = hash_password(password)
    assert isinstance(hashed_password, str)

    # Test that hashing the same password twice results in the same hash
    hash1 = hash_password(password)
    hash2 = hash_password(password)
    assert hash1 == hash2

    # Test that hashing different passwords results in different hashes
    different_hash = hash_password(another_password)
    assert hashed_password != different_hash

def test_register_user(temp_db_path):
    """Test user registration."""

    valid_email = "newuser@example.com"
    valid_password = "Password123!"
    invalid_email = "invalidemail"
    invalid_password = "password"

    create_database(temp_db_path)

    # Test successful registration
    success, message = register_user(temp_db_path, valid_email, valid_password)
    assert success, "Registration should be successful for valid credentials"
    assert message == "Registration successful"

    # Test registration with invalid email
    success, message = register_user(temp_db_path, invalid_email, valid_password)
    assert not success, "Registration should fail with invalid email"
    assert message == "Invalid email format"

    # Test registration with invalid password
    success, message = register_user(temp_db_path, valid_email, invalid_password)
    assert not success, "Registration should fail with invalid password"
    assert message == "Password should contain at least one digit and one special character."

    # Test registration with an already registered email
    success, message = register_user(temp_db_path, valid_email, valid_password)
    assert not success, "Registration should fail with an already registered email"
    assert message == "Email already registered"

def test_activate_user(temp_db_path):
    """Test user activation."""
    valid_email = "user@example.com"
    invalid_email = "nonexistent@example.com"

    # Pre-setup: Register a new user
    create_database(temp_db_path)
    register_user(temp_db_path, valid_email, "Password123!")

    # Test activation of non-existent user
    success, message = activate_user(temp_db_path, invalid_email)
    assert not success, "Activation should fail for a non-existent user"
    assert message == "User not found"

    # Test successful activation
    success, message = activate_user(temp_db_path, valid_email)
    assert success, "Activation should be successful for an existing user"
    assert message == "User activated"

def test_authenticate_user(temp_db_path):
    """Test user authentication."""
    valid_email = "authuser@example.com"
    valid_password = "Password123!"
    invalid_email = "nonexistent@example.com"
    invalid_password = "WrongPassword"

    # Pre-setup: Register and activate a new user
    create_database(temp_db_path)
    register_user(temp_db_path, valid_email, valid_password)
    activate_user(temp_db_path, valid_email)

    # Test authentication with invalid email
    success, message = authenticate_user(temp_db_path, invalid_email, valid_password)
    assert not success, "Authentication should fail with invalid email"
    assert message == "Invalid credentials or account not activated"

    # Test authentication with wrong password
    success, message = authenticate_user(temp_db_path, valid_email, invalid_password)
    assert not success, "Authentication should fail with wrong password"
    assert message == "Invalid credentials or account not activated"

    # Test authentication with correct credentials
    success, message = authenticate_user(temp_db_path, valid_email, valid_password)
    assert success, "Authentication should be successful with correct credentials"
    assert message == "Authentication successful"

def test_reset_password(temp_db_path):
    """Test password reset."""
    valid_email = "resetuser@example.com"
    old_password = "OldPassword123!"
    new_password = "NewPassword123!"
    invalid_password = "newpassword"
    non_existent_email = "nonexistent@example.com"

    # Pre-setup: Register and activate a new user
    create_database(temp_db_path)
    register_user(temp_db_path, valid_email, old_password)
    activate_user(temp_db_path, valid_email)

    # Test reset with non-existent email
    success, message = reset_password(temp_db_path, non_existent_email, new_password)
    assert not success, "Reset should fail for a non-existent user"
    assert message == "User not found"

    # Test reset with invalid new password
    success, message = reset_password(temp_db_path, valid_email, invalid_password)
    assert not success, "Reset should fail with invalid new password"
    assert message == "Password should contain at least one digit and one special character."

    # Test successful password reset
    success, message = reset_password(temp_db_path, valid_email, new_password)
    assert success, "Reset should be successful with valid new password"
    assert message == "Password reset successfully"


