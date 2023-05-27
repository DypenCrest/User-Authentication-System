from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.core.exceptions import ValidationError
from .models import CustomUser
from .validation import validate_password
from captcha.fields import ReCaptchaField
from django.contrib.auth import get_user_model

User = get_user_model()
class RegistrationForm(UserCreationForm):
    email = forms.EmailField(max_length=254, help_text="'@gmail.com' Only.", required=True, widget=forms.EmailInput(
        attrs={'class': 'form-control','style':'max-width: 25em', 'placeholder': 'example@gmail.com'}))
    first_name= forms.CharField(max_length=50,required=True, widget=forms.TextInput(
        attrs={'class': 'form-control','style':'max-width: 25em', 'placeholder': 'First name'}))
    last_name= forms.CharField(max_length=50, required=True, widget=forms.TextInput(
        attrs={'class': 'form-control','style':'max-width: 25em', 'placeholder': 'Last name'}))
    password1 = forms.CharField(label='Password', required=True, widget=forms.PasswordInput(
        attrs={'id': 'password1', 'class': 'form-control','style':'max-width: 25em', 'placeholder': 'Password'}))
    password2 = forms.CharField(label='Confirm Password',required=True, widget=forms.PasswordInput(
        attrs={'class': 'form-control','style':'max-width: 25em', 'placeholder': 'Confirm Password'}))
    captcha = ReCaptchaField()
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'first_name', 'last_name', 'password1', 'password2']
        widgets = {'username': forms.TextInput(attrs={'class': 'form-control','style':'max-width: 25em', 'placeholder': 'Username'}),}

    error_css_class = 'has-error'
    required_css_class = 'required'
    
    def clean_password1(self):
        password = self.cleaned_data.get('password1')
        user = User(username=self.cleaned_data.get('username'), email=self.cleaned_data.get('email'))
        try:
            validate_password(password, user)
        except ValidationError as e:
            self.add_error('password1', e)
        return password

    def save(self, commit=True):
        user = super().save(commit=False)
        if commit:
            user.save()
        return user
    
class LoginForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control','style':'max-width: 25em', 'placeholder': 'Username', 'autofocus': True}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control','style':'max-width: 25em', 'placeholder': 'Password', 'autofocus': True}))
    class Meta:
        model = CustomUser
        fields = ['username', 'password']

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(max_length=254, widget=forms.EmailInput(attrs={'placeholder': 'Email Address'}))

    def clean_email(self):
        email = self.cleaned_data.get('email')
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise forms.ValidationError('The email address you entered does not match our records. Please try again.')
        return email

class ResetPasswordForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("Passwords do not match")