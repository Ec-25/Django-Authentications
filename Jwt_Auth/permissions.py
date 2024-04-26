from rest_framework.permissions import BasePermission
from rest_framework_simplejwt.tokens import (
    RefreshToken,
    AccessToken,
    OutstandingToken,
    TokenError,
)
from datetime import datetime, timezone


class IsAuthenticatedAndTokenValid(BasePermission):
    """
    Allows access only to authenticated users.
    """
    def has_permission(self, request, view):
        if not bool(request.user and request.user.is_authenticated):
            return (
                False  # User is not authenticated, token cannot be verified.
            )

        # Get the Authorization header token
        authorization_header = request.headers.get("Authorization")
        if not authorization_header or not authorization_header.startswith("Bearer "):
            return False  # Authorization header is invalid

        try:
            bearer_token = authorization_header.split(" ")[1]
            access_token = AccessToken(bearer_token)

            iat = datetime.fromtimestamp(access_token.get("iat"), tz=timezone.utc)
            exp = datetime.fromtimestamp(access_token.get("exp"), tz=timezone.utc)

            outstanding_tokens = OutstandingToken.objects.get_queryset().filter(
                user_id=access_token.get("user_id")
            )
            outstanding_token = None

            for token in outstanding_tokens:
                if (
                    token.expires_at.strftime("%Y-%m-%d %H:%M:%S")
                    == exp.strftime("%Y-%m-%d %H:%M:%S")
                ) and (
                    token.created_at.strftime("%Y-%m-%d %H:%M:%S")
                    == iat.strftime("%Y-%m-%d %H:%M:%S")
                ):
                    # Check if the token is valid and has not expired.
                    if token.expires_at <= datetime.now(tz=timezone.utc):
                        return False

                    outstanding_token = token
                    break  # Valid token found.

            if not outstanding_token:
                return False  # The token does not exist or has expired.

            refresh_token = RefreshToken(outstanding_token.token)
            refresh_token.check_blacklist()

            return True  # The token is valid and the user is authenticated.

        except TokenError:
            return False  # The token is invalid

        except Exception as e:
            return False


class IsStaffOrAdmin(BasePermission):
    """
    Allows access only to admin users.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_staff or request.user.is_superuser)
