# Password Manager with Encryption

This is a final project for CS50, an easy-to-use password manager with encryption for secure password storage. The password manager allows users to register an account, log in, and store their passwords securely in a password vault. The passwords are encrypted using a high-security encryption algorithm that derives the encryption key from the hashed master password and salt, ensuring that even if someone gains access to the password vault, they won't be able to read the passwords without the master password.

## Features

- Registration process with password strength requirements
- Password vault to securely store passwords
- View, delete, or edit saved passwords
- High-security encryption algorithm to encrypt passwords
- Change master password anytime
- Easy-to-use and reliable solution

## Files

Here's a description of the files in this project:

- **static:** This folder contains the static files for the project, including the logo and CSS file.

    - `logo.ico`: The icon file for the website.

    - `logo.png`: The logo image for the website.

    - `pm.png`: Another version of the logo.

    - `styles.css`: The CSS file that defines the website's style.

- **templates:** This folder contains the HTML files for the website.

    - `add-password.html`: The HTML file for adding a password.

    - `apology.html`: The HTML file for displaying error messages.

    - `index.html`: The HTML file for the home page.

    - `layout.html`: The base template that other templates extend.

    - `login.html`: The HTML file for logging in.

    - `password.html`: The HTML file for changing the master password.

    - `passwords-vault.html`: The HTML file for displaying the user's password vault.

    - `register.html`: The HTML file for registering.

- `app.py`: The main file for the Flask application.

- `helpers.py`: A file containing helper functions used by `app.py`.

- `passwords.db`: The SQLite database file used to store the passwords.

- `requirements.txt`: A file containing the required packages for the project.

## Design Choices

The registration process ensures that the password is strong and meets the necessary requirements, such as a minimum length of 8 characters, one uppercase letter, one lowercase letter, one digit, and one symbol. This ensures that the password is secure from the get-go.

Once the user has registered, they can add passwords to the password vault. This is where the passwords are securely stored, all protected by a master password. The user can view their password vault, where they can check the passwords they have saved, and also delete or edit them.

To ensure that the passwords are always safe and secure, the password manager encrypts them using a high-security encryption algorithm that derives the encryption key from the hashed master password and salt. This means that even if someone gains access to the password vault, they won't be able to read the passwords without the master password.

Speaking of the master password, the user can change it anytime they want. When they do, the password manager re-encrypts all their passwords again with the new master password, ensuring that the account remains safe and secure.

Lastly, I chose to use Flask and SQLite to develop the application, as they are both lightweight and easy to use, making it easier for others to understand and modify the code if they choose to.

Thank you for checking out my final project for CS50. If you have any questions or feedback, feel free to reach out to me.

## Links

Check out this [video](https://youtu.be/glCj3vRRAys) where I explain the project.

You can also try the live demo [here](http://matheudev.pythonanywhere.com).

## About CS50

CS50 is a popular introductory computer science course offered by Harvard University. The course is designed to teach students the fundamentals of computer science and programming, covering topics such as algorithms, data structures, web development, and more.

The course is taught by David J. Malan and his team of educators and is offered online for free through edX. CS50 has become popular for its engaging lectures, challenging problem sets, and supportive online community.

This project was developed as the final project for the CS50 course. The course provided a strong foundation in computer science and programming concepts that were necessary to build this password manager with encryption.

Thank you for your interest in this project!
