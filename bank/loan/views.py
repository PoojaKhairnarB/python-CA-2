from urllib import request
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout

# Create your views here.
def home(request):
    return render(request, "loan/index.html")

def signup(request):
    
    if request.method == "POST":
        Username = request.POST.get('Username')
        fname = request.POST.get('fname')
        lname = request.POST.get('lname')
        email = request.POST.get('email')
        pass1 = request.POST.get('pass1')
        pass2 = request.POST.get('pass2')
        
        user = User.objects.create_user(Username , email, pass1)
        user.cust_first_name =fname
        user.cust_last_name =lname
        
        user.save()
        
        messages.success(request, "Account Created Successfully ")
        
        return redirect('signin')
    
    return render(request, "loan/signup.html")

def signin(request):
    
     if request.method == 'POST':
         username = request.POST.get('Username')
         pass1 = request.POST.get('pass1')
         
         user = authenticate(username=username, password=pass1)
         
         
         if user is not None:
             login(request, user)
             fname = user.first_name
             messages.success(request, "Logged In Sucessfully!!")
             return render(request , "loan/index.html", {"fname": fname})
         else:
             messages.error(request,"Incorrect Credentials")
             return redirect('home')
         
     return render(request, "loan/signin.html")


def signout(request):
    logout(request)
    messages.success(request, "logged out successfully")
    return redirect('home')