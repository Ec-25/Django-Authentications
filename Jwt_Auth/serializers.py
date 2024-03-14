from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import authenticate
from .models import User, OneTimePassword
from .utils import (
    send_password_reset_email,
    get_user_id_by_uidb64,
    check_for_password_reset_user_token,
    get_tokens,
    delete_outstanding_token,
    delete_all_outstanding_tokens,
)


class UserProfileSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        return {"email": instance.email, "full_name": instance.get_full_name()}


class UserRegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=63)
    last_name = serializers.CharField(max_length=63)
    password = serializers.CharField(max_length=100, min_length=8, write_only=True)
    password2 = serializers.CharField(max_length=100, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ["email", "first_name", "last_name", "password", "password2"]

    def validate(self, data):
        password = data.get("password")
        password2 = data.pop("password2")
        if password != password2:
            raise serializers.ValidationError("Passwords do not match")
        return data

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class VerifyEmailSerializer(serializers.Serializer):
    code = serializers.CharField()

    def validate(self, data):
        code = data.get("code")

        if not code:
            raise serializers.ValidationError("Code is required!")

        try:
            user_code_obj = OneTimePassword.objects.get(code=code)
            user = user_code_obj.user

            if user.is_active:
                raise serializers.ValidationError("Email already verified!")

            user.is_active = True
            user.save()
            user_code_obj.delete()

        except User.DoesNotExist:
            raise serializers.ValidationError(f"Invalid verification code 1!  - {code}")

        except OneTimePassword.DoesNotExist:
            raise serializers.ValidationError(f"Invalid verification code 2! - {code}")

        return data


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(max_length=100, min_length=8, write_only=True)
    full_name = serializers.CharField(max_length=100, read_only=True)
    tokens = serializers.DictField(read_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "full_name", "tokens"]

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")
        request = self.context.get("request")

        user = authenticate(request=request, email=email, password=password)

        if not user:
            raise AuthenticationFailed("Invalid credentials!")
        if not user.is_active:
            raise AuthenticationFailed("Account is not active!")

        return {
            "email": user.email,
            "full_name": user.get_full_name(),
            "tokens": get_tokens(user),
        }


class UserChangePasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):
        email = attrs.get("email")

        if not User.objects.filter(email=email).exists():
            raise AuthenticationFailed("Invalid credentials!")

        user = User.objects.get(email=email)
        request = self.context.get("request")

        send_password_reset_email(request, user)

        return super().validate(attrs)


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=100, min_length=8, write_only=True)
    password2 = serializers.CharField(max_length=100, min_length=8, write_only=True)
    uidb64 = serializers.CharField(max_length=100, write_only=True)
    token = serializers.CharField(max_length=100, write_only=True)
    user_id = None
    new_password = None

    class Meta:
        fields = ["password", "password2", "uidb64", "token"]

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")

        if password != password2:
            raise AuthenticationFailed("Passwords do not match!")

        try:
            user = User.objects.get(id=get_user_id_by_uidb64(attrs.get("uidb64")))

            if not check_for_password_reset_user_token(user, attrs.get("token")):
                raise AuthenticationFailed("Invalid credentials!")

            self.new_password = password
            self.user_id = user.id

            return True

        except User.DoesNotExist:
            raise AuthenticationFailed("Invalid credentials!")

        except Exception as e:
            raise AuthenticationFailed(str(e))

    def save(self, **kwargs):
        if not (self.user_id and self.new_password):
            raise AuthenticationFailed("Invalid credentials!")

        user = User.objects.get(id=self.user_id)

        user.set_password(self.new_password)
        user.save()

        delete_all_outstanding_tokens(self.user_id)
        return


class UserLogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, attrs):
        self.refresh_token = attrs.get("refresh_token")
        return attrs

    def save(self, user_id, delete_all: bool = False, **kwargs):
        if delete_all:
            delete_all_outstanding_tokens(user_id)
            return
        delete_outstanding_token(user_id, self.refresh_token)
        return


class UserDeleteSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(max_length=100, min_length=8, write_only=True)

    class Meta:
        fields = ["email", "password"]

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")
        request = self.context.get("request")

        user = authenticate(request=request, email=email, password=password)

        if not user:
            raise AuthenticationFailed("Invalid credentials!")
        if not user.is_active:
            raise AuthenticationFailed("Account is not active!")

        return data

    def save(self, user_id, **kwargs):
        user = User.objects.get(id=user_id)
        user.delete()
        return


class UserUpdateSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=False)
    first_name = serializers.CharField(max_length=63)
    last_name = serializers.CharField(max_length=63)

    class Meta:
        model = User
        fields = ["email", "first_name", "last_name"]

    def validate(self, attrs):
        new_email = attrs.get("email")

        if User.objects.filter(email=new_email).exists():
            raise AuthenticationFailed("Email already exists!")

        return super().validate(attrs)

    def update(self, instance, validated_data):
        instance.email = validated_data.get("email", instance.email)
        instance.first_name = validated_data.get("first_name", instance.first_name)
        instance.last_name = validated_data.get("last_name", instance.last_name)
        delete_all_outstanding_tokens(instance.id)
        instance.save()
        return instance

    def to_representation(self, instance):
        return {"email": instance.email, "full_name": instance.get_full_name()}
