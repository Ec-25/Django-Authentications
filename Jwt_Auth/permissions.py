from rest_framework.permissions import BasePermission
from rest_framework_simplejwt.tokens import (
    RefreshToken,
    AccessToken,
    OutstandingToken,
    TokenError,
)
from datetime import datetime, timezone


class IsAuthenticatedAndTokenValid(BasePermission):
    def has_permission(self, request, view):
        if not bool(request.user and request.user.is_authenticated):
            return (
                False
            )

        authorization_header = request.headers.get("Authorization")
        if not authorization_header or not authorization_header.startswith("Bearer "):
            return False

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
                    if token.expires_at <= datetime.now(tz=timezone.utc):
                        return False

                    outstanding_token = token
                    break

            if not outstanding_token:
                return False

            refresh_token = RefreshToken(outstanding_token.token)
            refresh_token.check_blacklist()

            return True

        except TokenError:
            return False

        except Exception as e:
            return False
