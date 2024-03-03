
from django.shortcuts import render

# Create your views here.
from django.shortcuts import render,HttpResponse,redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from django.urls import reverse
import re
from django.core.validators import RegexValidator,validate_email
from django.core.exceptions import ValidationError

# Create your views here.

def HomePage(request):
    return render (request,'s.html')

def SignupPage(request):
    if request.method=='POST':
        uname=request.POST.get('username')
        email=request.POST.get('email')
        pass1=request.POST.get('password1')
        pass2=request.POST.get('password2')
        
    try:
            email = request.POST.get('email')
            validate_email(email)  # Validate email using built-in Django validator
            uname_validator = RegexValidator(
                regex=r'^[a-zA-Z0-9_-]{4,20}$',
                message='Enter a valid username'
            )
            pass_validator = RegexValidator(
                regex=r'^(?=.*\d)(?=.*[a-zA-Z])[a-zA-Z0-9!@#$%^&*()-_=+,.?":{}|<>]{8,}$',
                message='Enter a valid password'
            )

            uname_validator(uname)
            pass_validator(pass1)
            pass_validator(pass2)

            if pass1 != pass2:
                password_errors = "Passwords do not match"
                return render(request, 'register.html', {'password_errors': password_errors})
            else:
                my_user = User.objects.create_user(username=uname, email=email, password=pass1)
                my_user.save()
                return redirect('login')
    except ValidationError as e:
            pass1=request.POST.get('pass1')
            if 'Enter a valid password' in e.messages:
                password_errors = "Enter a valid password"
            else:
                password_errors = None
            return render(request, 'register.html', {'password_errors': password_errors})

    except ValidationError as e:
            if 'Enter a valid username' in e.messages:
                username_errors = "Enter a valid username"
            else:
                username_errors = None
            return render(request, 'register.html', {'username_errors': username_errors})

    return render(request, 'register.html') 

         
         
            
               
              
        


                 
        



    return render (request,'register.html')
    

def LoginPage(request):
    if request.method=='POST':
        username=request.POST.get('username')
        pass1=request.POST.get('pass')
        user=authenticate(request,username=username,password=pass1)
        if user is not None:
                user.is_active
                login(request,user)
                return redirect('shop')
        
        else:
                  error_message='Username or password Invalid Try Again'
                  return render (request,'login.html',{'error_message':error_message})
    else:   
         return render (request,'login.html')

@login_required
def profile(request):
    currennt_user=request.user
    context={
        'username': currennt_user.username
    }
    return render(request,'shop.html',context)
def k (request):
     return render(request,'k.html')





