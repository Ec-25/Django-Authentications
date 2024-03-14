from rest_framework_simplejwt.tokens import RefreshToken, OutstandingToken, TokenError
from rest_framework.exceptions import AuthenticationFailed
from django.core.mail import EmailMessage
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import smart_bytes
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from secrets import token_urlsafe
from .models import User, OneTimePassword


def get_tokens(self):
    """Returns a dict of access and refresh tokens"""
    refresh = RefreshToken.for_user(self)
    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


def set_path(context, path, extra: list = []):
    """Set the path of the request"""
    url = _get_base_url(context) + _get_actually_path(context) + path
    if extra:
        for item in extra:
            if item[0] == "?":
                url += item
            else:
                url += "/" + item
    return url


def delete_all_outstanding_tokens(user_id):
    """Deletes all outstanding tokens for a given user"""
    tokens = OutstandingToken.objects.filter(user_id=user_id)
    for token in tokens:
        token.delete()
    return


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


def _get_base_url(request):
    """Get the base URL of the request."""
    return f"{request.scheme}://{request.get_host()}"


def _get_actually_path(request):
    """Get the path of the request."""
    return request.path_info.split("/", 2)[0]


def send_email(subject: str, message: str, to_email: str):
    """Send an email with the given subject, message, and recipient."""
    email = EmailMessage(subject, message, to=[to_email])
    email.send(fail_silently=True)
    return


def _generate_verification_code(user):
    """Generate a unique verification token for a user"""
    code = token_urlsafe(16)
    OneTimePassword.objects.create(user=user, code=code).save()
    return code


def send_verification_email(context, user_email):
    """Send a verification email to the user with the given email."""
    user = User.objects.get(email=user_email)
    code = _generate_verification_code(user)
    url = set_path(context, "/auth/register/verify", ["?code=" + code])
    send_email(
        subject="Django: Activate your account.",
        message=f"Hi {user.get_full_name()}.\n\tThank you for registering at 'Django'. Follow the link below to activate your account and start using the product.\n\t{url}",
        to_email=user.email,
    )
    return


def _generate_password_reset_code(user):
    """Generate a unique password reset token for a user"""
    return (
        urlsafe_base64_encode(smart_bytes(user.id)),
        PasswordResetTokenGenerator().make_token(user),
    )


def send_password_reset_email(context, user):
    """Send a verification email to the user with the given email."""
    codes = _generate_password_reset_code(user)
    url = set_path(context, "/auth/password/verify", [codes[0], codes[1]])
    send_email(
        subject="Django: Reset your password.",
        message=f"Hi {user.get_full_name()}.\n\tThank you for registering at 'Django'. Follow the link below to reset your password.\n\t{url}",
        to_email=user.email,
    )
    return


def get_user_id_by_uidb64(uidb64):
    """
    Get the user id from the uidb64 string.
    uidb64 is the base64 encoded user id.
    Returns the user id as an integer.
    """
    return force_str(urlsafe_base64_decode(uidb64))


def check_for_password_reset_user_token(user, token):
    return PasswordResetTokenGenerator().check_token(user, token)
