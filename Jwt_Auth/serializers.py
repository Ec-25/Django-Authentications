from rest_framework import serializers
from .models import User
from Server.common_utilities import send_email
from Server.settings import EMAIL_HOST_USER
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from secrets import token_urlsafe


class UserSignUpSerializer(serializers.ModelSerializer):
    # Additional field to confirm the password during registration
    passConfirm = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'first_name', 'last_name', 'password', 'passConfirm']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        # Validate that the password and its confirmation match
        password = attrs.get('password')
        passConfirm = attrs.pop('passConfirm')

        if password != passConfirm:
            raise serializers.ValidationError({'password': 'Passwords do not match'})

        # Generate a unique verification token
        verification_token = token_urlsafe(16)

        # Store the verification token in the user instance
        attrs['verification_token'] = verification_token

        # Build the verification link using the context
        request = self.context.get('request')
        verify_link = f'{request.scheme}://{request.get_host()}{request.path_info.split("/", 2)[0]}/auth/verify-email/{verification_token}/'

        # Send the verification token via email
        # DEBUG: Print the link to the console during development
        # print(verify_link)
        # PRODUCTION: Uncomment the following line to send a real email
        send_email(contact='Verify Email', subject='Verify your email address',
                   recipients=[attrs['email']],
                   message=f"Enter the following link to validate your Portfolio service account: {verify_link}",
                   host=EMAIL_HOST_USER)

        return attrs

    def create(self, validated_data):
        # Create a new user using the custom user manager
        return User.objects.create_user(**validated_data)


class UserSingInSerializer (serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password']


class UserProfileSerializer (serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'username', 'first_name', 'last_name']


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        try:
            # Extract the email from the input data
            email = attrs.get('email')

            # Check if a user with the given email exists
            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)

                # Generate a unique UID for the user
                uidb64 = urlsafe_base64_encode(force_bytes(user.id))
                
                # Generate a token for password reset
                token = PasswordResetTokenGenerator().make_token(user)
                
                # Build the password reset link using the context
                request = self.context.get('request')
                link = f'{request.scheme}://{request.get_host()}{request.path_info.split("/", 2)[0]}/auth/password-reset/{uidb64}/{token}/'

                # DEBUG: Print the link to the console during development
                # print({'link': link})
                
                # PRODUCTION: Uncomment the following line to send a real email
                send_email('Portfolio System', 'Reset Your Password',
                           f'Click Following Link to Reset Your Password {link}',
                           EMAIL_HOST_USER, [user.email], [])

                # Ensure that the request is passed to the context
                return {'uidb64': uidb64, 'token': token, 'link': link, 'request': request}

            else:
                # Raise an error if the email doesn't exist
                raise serializers.ValidationError("Email doesn't exist")

        except Exception as e:
            # Raise an error if any exception occurs
            raise serializers.ValidationError(str(e))


class UserPasswordResetSerializer(serializers.Serializer):
    newPassword = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    newPassword2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['newPassword', 'newPassword2']

    def validate(self, attrs):
        try:
            # Extract data from input
            newPassword = attrs.get('newPassword')
            newPassword2 = attrs.get('newPassword2')
            uidb64 = self.context.get('uidb64')
            token = self.context.get('token')

            # Check if newPassword and newPassword2 are the same
            if newPassword != newPassword2:
                raise serializers.ValidationError("Password and Confirm Password don't match")

            # Decode the UID to retrieve the user
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            # Check if the token is valid
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError('Token is not valid or has expired')

            # Set the new password for the user
            user.set_password(newPassword)
            user.save()

            return attrs

        except Exception as e:
            # Handle any exceptions that might occur
            raise serializers.ValidationError(str(e))
