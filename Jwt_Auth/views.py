from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User
from .renderers import UserRenderer
from .serializers import SendPasswordResetEmailSerializer, UserPasswordResetSerializer, UserProfileSerializer, UserSignUpSerializer, UserSingInSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework import status

from Server.common_utilities import send_email
from Server.settings import EMAIL_HOST_USER


# Generate Token Manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class SignUpView (APIView):
    renderer_classes = [UserRenderer]
    permission_classes = []

    def post(self, request):
        # Initialize the serializer with request data and context
        serializer = UserSignUpSerializer(data=request.data, context={'request': request})

        # Check if the serializer is valid
        if serializer.is_valid():
            # Save the user and generate tokens
            user = serializer.save()
            token = get_tokens_for_user(user)

            # Return a success response with user token and a message
            return Response({'token': token, 'message': 'User registered successfully. Verification code successfully sent to your email'}, status=status.HTTP_201_CREATED)

        # If the serializer is not valid, return detailed error messages
        return Response({'errorDetails': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = []

    def post(self, request, verification_token):
        try:
            # Attempt to retrieve a user with the provided verification token
            user = User.objects.get(verification_token=verification_token)

            # Update user fields to confirm email verification
            user.verification_token = None
            user.is_active = True
            user.save()

            # Return a success response
            return Response({'message': 'Correo electrónico verificado correctamente'}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            # Handle the case where the verification token is invalid
            return Response({'errorDetail': 'Invalid verification token'}, status=status.HTTP_400_BAD_REQUEST)


class ResendVerifyEmailView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = []

    def post(self, request):
        # Obtain the authorization token or email and password from the request body
        serializer = UserSingInSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Get the user referenced by the provided email
        user = get_object_or_404(User, email=serializer.data.get('email'))

        # Check if the user is not already verified
        if not user.is_active:
            # Construct the verification link using the request context
            verify_link = f'{request.scheme}://{request.get_host()}{request.path_info.split("/", 2)[0]}/auth/verify-email/{user.verification_token}/'

            # Send the verification token via email
            # DEBUG
            # print(verify_link)
            # PRODUCTION
            send_email(contact='Verify Email', subject='Verify your email address', recipients=[user.email], message=f" Enter the following link to validate your Portfolio service account: {verify_link}", host=EMAIL_HOST_USER)

            # Return a success response
            return Response({'message': 'Verification code successfully sent to your email'}, status=status.HTTP_200_OK)

        # Return an error response if the user is already verified
        return Response({'errorDetail': 'User already verified'}, status=status.HTTP_400_BAD_REQUEST)


class SignInView (APIView):
    renderer_classes = [UserRenderer]
    permission_classes = []

    def post(self, request):
        # Get and validate data using the UserSignInSerializer
        serializer = UserSingInSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Authenticate user using email and password
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = authenticate(email=email, password=password)

        if user:
            # Generate tokens for the authenticated user
            token = get_tokens_for_user(user)
            # Return a success response with the generated token
            return Response({'token': token, 'message': 'User logged in successfully'}, status=status.HTTP_200_OK)

        # Return an error response for invalid credentials
        return Response({'errorDetail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Create a UserProfileSerializer instance with the authenticated user's data
        serializer = UserProfileSerializer(request.user)
        
        # Return a success response with the serialized user profile data
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        # Create a UserProfileSerializer instance with the authenticated user's data
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        # Return a success response with the serialized user profile data
        return Response(serializer.data, status=status.HTTP_200_OK)


class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = []

    def post(self, request):
        # Create a SendPasswordResetEmailSerializer instance with the provided data and request context
        serializer = SendPasswordResetEmailSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        
        # Return a success response indicating that the password reset email was sent successfully
        return Response({'message': 'Password reset email sent successfully'}, status=status.HTTP_200_OK)


class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = []

    def post(self, request, uidb64, token):
        # Create a UserPasswordResetSerializer instance with the provided data and context
        serializer = UserPasswordResetSerializer(data=request.data, context={'uidb64': uidb64, 'token': token, 'request': request})
        serializer.is_valid(raise_exception=True)
        
        # Return a success response indicating that the password reset was successful
        return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)


class LogoutView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Retrieve the refresh token from the request data
            refresh_token = request.data["refresh_token"]

            # Create a RefreshToken instance using the provided refresh token
            token = RefreshToken(refresh_token)

            # Blacklist the token to invalidate it
            token.blacklist()

            # Return a success response with HTTP status 205 Reset Content
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            # Return a failure response with HTTP status 400 Bad Request
            return Response(status=status.HTTP_400_BAD_REQUEST)


class DeleteUserView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        # Delete the authenticated user
        request.user.delete()

        # Return a success response with HTTP status 204 No Content
        return Response(status=status.HTTP_204_NO_CONTENT)
