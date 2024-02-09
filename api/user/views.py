import os
import requests, secrets, hmac, json
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
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
    # Generate a secure random state for CSRF protection
    state = secrets.token_urlsafe()
    request.session['oauth_state'] = state

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
        'access_type': 'offline',  # Important for receiving a refresh token
        'include_granted_scopes': 'true',
        'state': state,
    }
    auth_url = f'{base_url}?{requests.utils.quote(query_params, safe="")}'

    return redirect(auth_url)

# View to handle the callback from Google
def auth_callback(request):
    # Verify the state to protect against CSRF
    state = request.GET.get('state')
    if not state or state != request.session.pop('oauth_state', None):
        return HttpResponseForbidden('State mismatch, possible CSRF detected.')

    # Get the authorization code from the response
    auth_code = request.GET.get('code')
    if not auth_code:
        return HttpResponseBadRequest('Authorization code missing in the request.')

    # Exchange the authorization code for an access token
    token_url = 'https://oauth2.googleapis.com/token'
    data = {
        'code': auth_code,
        'client_id': settings.GOOGLE_CLIENT_ID,
        'client_secret': settings.GOOGLE_CLIENT_SECRET,
        'redirect_uri': settings.GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code',
    }

    token_response = requests.post(token_url, data=data)
    if token_response.status_code != 200:
        return HttpResponseBadRequest('Failed to obtain access token.')

    token_json = token_response.json()
    access_token = token_json.get('access_token')
    refresh_token = token_json.get('refresh_token')

    # Fetch user information from Google
    user_info_url = 'https://www.googleapis.com/oauth2/v3/userinfo'
    user_info_response = requests.get(user_info_url, params={'access_token': access_token})
    if user_info_response.status_code != 200:
        return HttpResponseBadRequest('Failed to obtain user information.')

    user_info = user_info_response.json()

    # Process user information (authenticate or register the user)
    email = user_info.get('email')
    google_id = user_info.get('sub')  # Use 'sub' as the user ID

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        # Optionally, create a new user if one does not exist
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
    user.backend = 'django.contrib.auth.backends.ModelBackend'  # Specify the auth backend
    login(request, user)
    return redirect('home')  # Redirect to a post-login page

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
    
    TELEGRAM_BOT_TOKEN = settings.TELEGRAM_BOT_TOKEN

    if request.method == 'POST':
        try:
            # Load the data sent by Telegram
            auth_data = json.loads(request.body)
            
            # Extract the check_hash from incoming data
            check_hash = auth_data.pop('hash')
            
            # Reconstruct the data check string
            data_check_arr = sorted(["{}={}".format(k, v) for k, v in auth_data.items()])
            data_check_string = "\n".join(data_check_arr).encode('utf-8')
            
            # Create a secret key from the bot token
            secret_key = hashlib.sha256(TELEGRAM_BOT_TOKEN.encode('utf-8')).digest()
            
            # Generate a hash based on incoming data using HMAC
            hmac_hash = hmac.new(secret_key, data_check_string, hashlib.sha256).hexdigest()
            
            # Constant-time comparison of the computed HMAC hash with the check_hash from Telegram
            if not hmac.compare_digest(hmac_hash, check_hash):
                return JsonResponse({'detail': 'Invalid authentication hash.'}, status=401)
            
            # Ensure the data is fresh (within 86400 seconds = 24 hours)
            if time.time() - float(auth_data['auth_date']) > 86400:
                return JsonResponse({'detail': 'Authentication data is outdated.'}, status=401)
            
            # At this point, authentication is successful. Implement user login or registration logic.
            # Example: Retrieve or create a user based on the Telegram ID
            user_id = auth_data['id']
            # User retrieval/creation logic here...
            
            # Return success response
            return JsonResponse({'detail': 'Successfully logged in!'})
        
        except json.JSONDecodeError:
            return JsonResponse({'detail': 'Invalid JSON.'}, status=400)
        except KeyError as e:
            return JsonResponse({'detail': f'Missing key: {str(e)}'}, status=400)
        except Exception as e:
            # Log the error for debugging
            print(f'Error in Telegram auth: {str(e)}')
            return JsonResponse({'detail': 'An error occurred.'}, status=500)
    else:
        return JsonResponse({'detail': 'Invalid request method.'}, status=405)
