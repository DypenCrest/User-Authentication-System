from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.core.validators import validate_email as email_validation
import re

# Validate the username
def validate_username(value):
    if not value.isalnum() and "_" not in value:
        raise ValidationError(
            _("Username can only contain letters, numbers, and underscores.")
        )
    
# Validate that the email address is valid.
def validate_email(value):    
    try:
        email_validation(value)
    except ValidationError:
        raise ValidationError(_("Invalid email address."))
    if not value.endswith('@gmail.com'):
        raise ValidationError("Email address must be '@gmail.com' domain.")

# Validate the password
def validate_password(password, CustomUser):
    # minimum password length
    min_length = 8
    username = CustomUser.username.lower()
    email = CustomUser.email
    # password requirement
    uppercase_regex = re.compile(r'[A-Z]')
    lowercase_regex = re.compile(r'[a-z]')
    special_char_regex = re.compile(r'[!@#$%^&*(),.?":{}|<>]')

    # Check if password meets minimum length requirement
    if len(password) < min_length:
        raise ValidationError("Password must be at least {} characters long.".format(min_length))

    # Check if password contains at least one uppercase letter
    if not uppercase_regex.search(password):
        raise ValidationError("Password must contain at least one uppercase letter.")

    # Check if password contains at least one lowercase letter
    if not lowercase_regex.search(password):
        raise ValidationError("Password must contain at least one lowercase letter.")

    # Check if password contains at least one special character
    if not special_char_regex.search(password):
        raise ValidationError("Password must contain at least one special character.")

    # Define a list of common passwords that should not be used
    common_passwords = ["password", "12345678", "00000000", "admin"]

    # Check if the password is a common password
    if password.lower() in common_passwords:
        raise ValidationError("This password is too common.")
    
    if password.lower() == username:
        raise ValidationError(
            _("The password is too similar to the username."),
            code='password_contains_username',
        )

    if password.lower() == email:
        raise ValidationError(
            _("The password is too similar to the email."),
            code='password_contains_email',
        )
