from rest_framework_simplejwt.tokens import RefreshToken, OutstandingToken, TokenError
from rest_framework.exceptions import AuthenticationFailed
from django.core.mail import EmailMessage
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_bytes, force_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from secrets import token_urlsafe
from os import getenv
from .models import User, OneTimePassword


def get_tokens(self):
    """Returns a dict of access and refresh tokens"""
    refresh = RefreshToken.for_user(self)
    return {
        "refresh_token": str(refresh),
        "access_token": str(refresh.access_token),
    }


def get_user_id_by_uidb64(uidb64):
    """
    Get the user id from the uidb64 string.
    uidb64 is the base64 encoded user id.
    Returns the user id as an integer.
    """
    return force_str(urlsafe_base64_decode(uidb64))


def _get_verification_code(user):
    """Generate a unique verification token for a user"""
    code = token_urlsafe(16)
    OneTimePassword.objects.create(user=user, code=code).save()
    return code


def _get_password_reset_code(user):
    """Generate a unique password reset token for a user"""
    return (
        urlsafe_base64_encode(smart_bytes(user.id)),
        PasswordResetTokenGenerator().make_token(user),
    )


def set_email(subject: str, message: str, to_email: str):
    """Send an email with the given subject, message, and recipient."""
    if getenv('DEBUG') == 'True':
        print(f"\nSUBJECT: {subject}, MESSAGE: {message}, DESTINATIONS: {[to_email]}\n")
        return
    email = EmailMessage(subject, message, to=[to_email])
    email.send(fail_silently=True)
    return


def set_verification_email(context, user_email):
    """Send a verification email to the user with the given email."""
    user = User.objects.get(email=user_email)
    code = _get_verification_code(user)
    set_email(
        subject="Commerce: Activate your account.",
        message=f"Hi {user.get_full_name()}.\n\tThank you for registering at 'Commerce'. Use the follow code to activate your account.\n\t{code}",
        to_email=user.email,
    )
    return


def set_password_reset_email(context, user):
    codes = _get_password_reset_code(user)
    set_email(
        subject="Commerce: Reset your password.",
        message=f"Hi {user.get_full_name()}.\n\tThank you for registering at 'Commerce'. Use the follow code to reset your password.\n\tBase: {codes[0]}\n\tCode: {codes[1]}",
        to_email=user.email,
    )
    return


def check_for_password_reset_user_token(user, token):
    return PasswordResetTokenGenerator().check_token(user, token)


def delete_outstanding_token(user_id, refresh_token):
    """Delete one outstanding tokens for a given user"""
    try:
        token = OutstandingToken.objects.get(user_id=user_id, token=refresh_token)
        token.delete()
        return

    except OutstandingToken.DoesNotExist:
        raise AuthenticationFailed("Invalid refresh token!")

    except TokenError:
        raise AuthenticationFailed("Invalid refresh token!")


def delete_all_outstanding_tokens(user_id):
    """Deletes all outstanding tokens for a given user"""
    tokens = OutstandingToken.objects.filter(user_id=user_id)
    for token in tokens:
        token.delete()
    return
