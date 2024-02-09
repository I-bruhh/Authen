import os
import requests
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.http import JsonResponse, HttpResponseRedirect
from django.urls import reverse
from urllib.parse import urlencode
from .models import User, GoogleProfile  # Import your custom User and UserProfile models
from .forms import UserCreationForm
from django.views.decorators.csrf import csrf_exempt
import hashlib
import time

# Your project's settings
from config import settings

# View to render the login page
def login_view(request):
    if request.method == 'GET':
        context = {
            'google_client_id': settings.GOOGLE_CLIENT_ID,
            # Include other context variables if necessary
        }
        return render(request, 'user/login.html', context)  # Adjust the template path as needed
    elif request.method == 'POST':
        # Handle login form submission using JSON
        data = json.loads(request.body)  # Parse the JSON data from the request body
        email = data.get('email')  # Get email from parsed JSON data
        password = data.get('password')  # Get password from parsed JSON data

        user = authenticate(request, email=email, password=password)

        if user is not None:
            login(request, user)
            # Return a JSON response indicating success
            return JsonResponse({'detail': 'Successfully logged in!', 'redirect_url': '/api/user/dashboard'})
        else:
            # Return a JSON response indicating failure
            return JsonResponse({'detail': 'Invalid email or password.'}, status=401)

# View to handle user logout
def logout_view(request):
    logout(request)
    return redirect('/') 

# View to handle Google OAuth2 login
def google_login(request):
    # Configuration
    client_id = settings.GOOGLE_CLIENT_ID
    redirect_uri = settings.GOOGLE_REDIRECT_URI
    scope = 'email profile'

    # Generate the Google Authorization URL
    base_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    query_params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': scope,
        'access_type': 'offline',  # This is important to receive a refresh token
        'include_granted_scopes': 'true',
        'state': 'random_string_for_csrf_protection',  # Generate a secure random string
    }
    auth_url = f'{base_url}?{urlencode(query_params)}'

    return redirect(auth_url)

# View to handle the callback from Google
def auth_callback(request):
    # Get the authorization code from the response
    auth_code = request.GET.get('code')
    if not auth_code:
        return render(request, 'auth_failed.html')  # Create this template

    # Exchange the authorization code for an access token
    token_url = 'https://oauth2.googleapis.com/token'
    data = {
        'code': auth_code,
        'client_id': settings.GOOGLE_CLIENT_ID,
        'client_secret': settings.GOOGLE_CLIENT_SECRET,
        'redirect_uri': settings.GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code',
    }
    token_response = requests.post(token_url, data=data).json()
    access_token = token_response.get('access_token')
    refresh_token = token_response.get('refresh_token')
    
    # Fetch user information from Google
    user_info_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    user_info_params = {'access_token': access_token}
    user_info_response = requests.get(user_info_url, params=user_info_params).json()
    
    # Authenticate or register the user
    email = user_info_response.get('email')
    google_id = user_info_response.get('id')
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        # Create a new user
        user = User.objects.create_user(username=email, email=email)
        user.set_unusable_password()
        user.save()
        GoogleProfile.objects.create(
            user=user, 
            google_id=google_id, 
            access_token=access_token, 
            refresh_token=refresh_token
        )
    
    # Authenticate and login the user
    user.backend = 'django.contrib.auth.backends.ModelBackend'  # Specify the authentication backend
    login(request, user)
    return redirect('home')  # Replace 'home' with your desired redirect view

# View to render the registration page and handle user registration
def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('dashboard')  # Redirect to dashboard
    else:
        form = UserCreationForm()
    return render(request, 'user/register.html', {'form': form})

# View to handle user logout
def logout_view(request):
    logout(request)
    return redirect('/') 


def dashboard(request):
    return render(request, 'user/dashboard.html')

@csrf_exempt
def telegram_auth(request):
    if request.method == 'POST':
        # Telegram data comes as POST request
        auth_data = request.POST
        
        # Retrieve the authentication hash and check the data
        check_hash = auth_data.pop('hash')
        data_check_arr = sorted(["{}={}".format(k, v) for k, v in auth_data.items()])
        data_check_string = "\n".join(data_check_arr)
        secret_key = hashlib.sha256(TOKEN.encode('utf-8')).digest()
        hmac_string = hashlib.sha256(data_check_string.encode('utf-8')).hexdigest()

        # Check the authentication hash
        if hmac_string == check_hash:
            # Check that the data is fresh
            if time.time() - auth_data['auth_date'] <= 86400:
                # Authenticate the user
                # ... (login or register the user in your system)
                return JsonResponse({'detail': 'Successfully logged in!'})
            else:
                return JsonResponse({'detail': 'Authentication data is outdated.'}, status=401)
        else:
            return JsonResponse({'detail': 'Invalid authentication hash.'}, status=401)
    else:
        return JsonResponse({'detail': 'Invalid request'}, status=400)