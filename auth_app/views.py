from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from .models import *
import uuid
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.http import HttpResponse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.urls import reverse
from .forms import RegistrationForm, LoginForm, ForgotPasswordForm, ResetPasswordForm
from django.contrib.auth.decorators import login_required
from django.template.loader import render_to_string
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist

User = get_user_model()

#Login
def custom_login(request):
    if request.method == 'POST':
        form = LoginForm(data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                if user.is_verified:
                    login(request, user)
                    return redirect('dashboard')
                else:
                    # Check if the user verification instance exists
                    try:
                        user_verification = UserVerification.objects.get(user=user)
                        messages.info(request,'User not verified.')
                    except ObjectDoesNotExist:
                        # If the user verification instance doesn't exist, create a new one
                        verification_token = str(uuid.uuid4())
                        user_verification = UserVerification(user=user, token=verification_token)
                        user_verification.save()
                    # Send the verification email
                    verification_link = request.build_absolute_uri(
                        reverse('verify_email', kwargs={'token': user_verification.token})
                    )
                    subject = 'Verify your email address'
                    from_email = 'Auth_app@gmail.com'
                    recipient_list = [user.email]
                    email_html = render_to_string('email.html', {'verification_link': verification_link})
                    send_mail(subject, message=None, html_message=email_html, from_email=from_email, recipient_list=recipient_list)
                    messages.info(request, 'Please check your email to verify your account.')
            else:
                messages.info(request,'Invalid Credentials')
                return render(request, 'login.html', {'form': form})
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})

#Registration
def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()

            # generate verification token
            verification_token = str(uuid.uuid4())

            # save verification token and email address in database
            user_verification = UserVerification(user=user, token=verification_token)
            user_verification.save()

            # send verification email
            verification_link = request.build_absolute_uri(
                reverse('verify_email', kwargs={'token': verification_token})
            )
            subject = 'Verify your email address'
            from_email = 'Auth_app@gmail.com'
            recipient_list = [user.email]

            # Get the cleaned form data
            form_data = form.cleaned_data

            # Render the email template with the verification link and form data
            email_html = render_to_string('email.html', {'verification_link': verification_link, 'form_data': form_data})

            send_mail(subject, message=None, html_message=email_html, from_email=from_email, recipient_list=recipient_list)
            messages.success(request, 'Email Verification Required! Please check your email to verify your account.')
            return redirect('login')
        else:
            messages.error(request, 'Failed to create account. Please check the form below.')
    else:
        form = RegistrationForm()
    return render(request, 'register.html', {'form': form})

#Email verification
def verify_email(request, token):
    try:
        user_verification = UserVerification.objects.get(token=token)
    except UserVerification.DoesNotExist:
        return HttpResponse('Invalid verification link')

    user = user_verification.user
    user.is_verified = True
    user.is_active = True
    user.save()
    user_verification.delete()

    return HttpResponse('Email has been verified. You can now close this tab and log in.')

#Forgot Password
def forgot_password(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                user = None
            if user is not None:
                # Generate a unique token for password reset
                token_generator = PasswordResetTokenGenerator()
                token = token_generator.make_token(user)
                # Create a verification instance
                PasswordReset.objects.create(user=user, token=token)
                # Send the password reset link via email
                subject = 'Password Reset Link'
                context = {
                    'reset_link': f'{request.build_absolute_uri("/reset-password/")}{urlsafe_base64_encode(force_bytes(user.pk))}/{token}/',
                    'user': user,
                }
                email_html = render_to_string('password_reset_email.html', context)
                from_email = 'Auth_app@gmail.com'
                recipient_list = [user.email]
                send_mail(subject, message=None, html_message=email_html, from_email=from_email, recipient_list=recipient_list, fail_silently=False)
            messages.success(request, 'Please check your email for the password reset link.')
            return redirect('forgot-password')
    else:
        form = ForgotPasswordForm()
    context = {'form': form}
    return render(request, 'forgot_password.html', context)

#Reset Password
from django.utils import timezone
from datetime import timedelta

def reset_password(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = CustomUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        user = None

    if user is not None and PasswordReset.objects.filter(user=user, token=token).exists():
        password_reset = PasswordReset.objects.get(user=user, token=token)
        # token expiration
        if password_reset.created_at + timedelta(hours=24) < timezone.now():
            password_reset.delete()
            messages.error(request, 'The reset password link has expired.')
            return redirect('login')
        else:
            form = ResetPasswordForm(request.POST or None)

            if form.is_valid():
                new_password = form.cleaned_data['password']
                confirm_password = form.cleaned_data['confirm_password']

                if len(new_password) < 8:
                    form.add_error('password', 'New password should be at least 8 characters long.')
                elif new_password == confirm_password:
                    if user.check_password(new_password):
                        form.add_error('password', 'New password cannot be the same as old password.')
                    else:
                        user.set_password(new_password)
                        user.save()
                        password_reset.delete()
                        messages.success(request, 'Warning! your password has been changed recently.')
                        return redirect('login')
                else:
                    messages.error(request, 'Passwords do not match.')

            return render(request, 'reset_password.html', {'form': form})
    else:
        messages.error(request, 'The reset password link is invalid.')
        return redirect('login')



class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (str(user.pk) + str(timestamp) + str(user.is_active))

password_reset_token = TokenGenerator()


#Dashboard
def dashboard_view(request):
    return render(request,'dashboard.html')

#Logout
@login_required(login_url="login")
def log_out(request):
    logout(request)
    return redirect('login')

#About
@login_required(login_url="login")
def about(request):
    return render(request,'about.html')
