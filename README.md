# User Management System Documentation

## Overview

This User Management System provides a simple, yet effective way to manage user registrations, authentications, and password resets. Designed in Python, it leverages SQLite for database interactions, ensuring a lightweight and efficient management system.

### Features

- User Registration with email and password
- Email Validation and Password Complexity Checks
- Account Activation Mechanism
- User Authentication
- Password Reset Functionality

### Requirements

- Python 3
- SQLite3
- No external libraries required

## Database Schema

The system uses an SQLite database to store user information. The `users` table includes the following fields:

- `id`: Primary Key, Autoincrement
- `email`: Unique Identifier
- `password`: Hashed for security
- `is_active`: Boolean, indicates if the account is activated
- `registration_date`: Timestamp of registration
- `activation_date`: Timestamp of account activation

## Installation

1. Clone the repository.
2. Ensure Python 3 is installed on your system.
3. The database file (`users.db`) will be automatically created in the project directory upon running the script.

## Usage

### Creating the Database

pythonCopy code

`create_database(db_path)`

Initializes the SQLite database at the specified path.

### Registering a User

pythonCopy code

`register_user(db_path, email, password)`

Registers a new user with an email and password.

### Activating a User

`activate_user(db_path, email)`

Activates the user's account.

### Authenticating a User

`authenticate_user(db_path, email, password)`

Authenticates a user by verifying their email and password.

### Resetting a Password

`reset_password(db_path, email, new_password)`

Resets the user's password.

## Implementation Notes

- Passwords are hashed using SHA-256 for security.
- Email and password validations are performed before database interactions.
- The system is designed using only Python 3 standard libraries.

## Contributions

Contributions to this project are welcome. Please ensure that any pull requests maintain the existing coding style and include appropriate tests.
