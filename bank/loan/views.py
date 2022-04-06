from base64 import urlsafe_b64decode, urlsafe_b64encode
from lib2to3.pgen2.tokenize import generate_tokens
from readline import get_current_history_length
from urllib import request
from django.conf import settings
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.conf import settings
from django.core.mail import send_mail, EmailMessage
from bank.info import EMAIL_HOST_USER
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode , urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from bank.tokens import generate_token

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
        
        if User.objects.filter(username=Username):
            messages.error(request, "Customer already exist!")
            return redirect('home')
        
        if User.objects.filter(email=email):
            messages.error(request, "Customer email already exist!")
            return redirect('home')   
        
        if len(Username)>10:
            messages.error(request, "Username cannot exceed 10 characters")
            return redirect('home')
        
        if pass1 != pass2:
            messages.error(request,"Incorrect password")   
            return redirect('home')
        
        if not Username.isalnum():
            messages.error(request, "Username cannot contain special characters")    
            return redirect('home')
        
    
        user = User.objects.create_user(Username , email, pass1)
        user.cust_first_name =fname
        user.cust_last_name =lname
        user.is_active = False
        user.save()
        
        messages.success(request, "Account Created Successfully.\bConfirmation mail is been sent.\b Kindly confirm to to activate your account")
        
        # Welcome message
        
        subject = "Welcome to DBS Bank"
        message = "Hello " + user.first_name + "!!\nWelcome to DBS Bank \nSent the confirmation mail, please confirm it to activate your account. \n\n Thanks and Regards,\n DBS Bank."
        from_email = settings.EMAIL_HOST_USER
        to_list = [user.email]
        send_mail(subject, message, from_email, to_list, fail_silently= True)
        
        #Confirmation mail
        
        current_site = get_current_site(request)
        email_subject = "Confirmation mail from DBS Bank"
        message2 = render_to_string('email_confirm.html',{
            'name': user.cust_first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user),                         
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [user.email],
        )
        email.fail_silently = True
        email.send()
        
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


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and generate_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        messages.success(request, "Account is activated!!!")
        return redirect('signin')
    else:
        return render(request,'activation_failed.html')
        