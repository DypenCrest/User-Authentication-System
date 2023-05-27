from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin, Group, Permission
from django.db import models
from django.utils.crypto import get_random_string
from django.core.exceptions import ValidationError
from django.utils import timezone
from .validation import validate_username, validate_email, validate_password


class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, first_name=None, last_name=None):
        if not email:
            raise ValueError('Users must have an email address')
        if not username:
            raise ValueError('The Username field must be set')

        user = self.model(
            username=username,
            email=self.normalize_email(email),
            first_name=first_name,
            last_name=last_name,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, username, email, password=None):
        user = self.create_user(
            username=username,
            email=email,
            password=password,
            first_name='Admin',
            last_name='User',
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class CustomUser(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=50, unique=True, validators=[validate_username])
    email = models.EmailField(max_length=254, unique=True, validators=[validate_email])
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)
    password = models.CharField(max_length=128, validators=[validate_password])
    confirm_password = models.CharField(max_length=128, validators=[validate_password])
    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = ['email']

    is_verified = models.BooleanField(default=False)

    objects = CustomUserManager()
    groups = models.ManyToManyField(Group, blank=True, related_name='customuser_set')
    user_permissions = models.ManyToManyField(Permission, blank=True, related_name='customuser_set')

    def clean(self):
        super().clean()
        if self.password != self.confirm_password:
            raise ValidationError('Passwords do not match.')

    def validate_password(self):
        validate_password(self.password, self)

    def __str__(self):
        return self.username

class UserVerification(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    token = models.CharField(max_length=100)

    def __str__(self):
        return f'{self.user.email} - {self.token}'

class PasswordReset(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    token = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = get_random_string(length=32)
        return super().save(*args, **kwargs)