from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password

UserModel = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        # TODO: Update fields
        fields = ['username', 'email', 'password']
    def create(self, data):
        user = UserModel.objects.create_user(username=data['username'], email=data['email'], password=data['password'])
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, data):
        # Check if a user with this email exists
        if not UserModel.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError("A user with this email does not exist.")

        # Authenticate the user
        user = authenticate(email=data['email'], password=data['password'])
        if user is None:
            raise serializers.ValidationError("Invalid password.")

        # Generate JWT token
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'username': user.username
        }
    