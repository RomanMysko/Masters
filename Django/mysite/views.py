from django.shortcuts import render

# Create your views here.

#----------
from django.shortcuts import render, redirect, HttpResponseRedirect
from .models import Member  # models.py
from django.contrib.auth import logout as auth_logout
from cryptography.fernet import Fernet
from django.urls import reverse
from django.contrib import messages
import os
# Create your views here.
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from django.shortcuts import render
from django.http import HttpResponse

import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP


def rsa_encrypt_decrypt():
    key = RSA.generate(2048)
    private_key = key.export_key('PEM')
    public_key = key.publickey().exportKey('PEM')
    message = input('plain text for RSA encryption and decryption:')
    message = str.encode(message)

    rsa_public_key = RSA.importKey(public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    encrypted_text = rsa_public_key.encrypt(message)
    #encrypted_text = b64encode(encrypted_text)

    print('your encrypted_text is : {}'.format(encrypted_text))


    rsa_private_key = RSA.importKey(private_key)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    decrypted_text = rsa_private_key.decrypt(encrypted_text)

    print('your decrypted_text is : {}'.format(decrypted_text))
import ast

def generate_rsa_key_pair():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Get public key in PEM format
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,

    )

    # Convert bytes to string
    public_key_str = public_key_pem.decode('utf-8')

    return private_key, public_key_str

def index(request):
    private_key_pem, public_key = generate_rsa_key_pair()

    if request.method == 'POST':
        username = request.POST['hashed_username']
        password = request.POST['hashed_password']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']

        key = RSA.generate(2048)
        private_key = key.export_key('PEM')
        public_key = key.publickey().exportKey('PEM')
        message = str.encode(firstname)

        rsa_public_key = RSA.importKey(public_key)
        rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
        usernameRSA = rsa_public_key.encrypt(message)
        # encrypted_text = b64encode(encrypted_text)

        print('your encrypted_text is : {}'.format(usernameRSA))
        # message to encrypt is in the above line 'encrypt this message'
        #
        # print('username', username)
        # print('private_key_pem ', private_key_pem)
        # username = base64.b64decode(username)
        # # Decrypt username using OAEP padding
        # #encrypted_bytes = base64.b64decode(username)
        # #print('username2', encrypted_bytes)
        #
        # private_key_bytes = private_key_pem.private_bytes(
        #     encoding=serialization.Encoding.PEM,
        #     format=serialization.PrivateFormat.TraditionalOpenSSL,
        #     encryption_algorithm=serialization.NoEncryption()
        # )
        # private_key_obj = serialization.load_pem_private_key(
        #     private_key_bytes,
        #     password=None,
        #     backend=default_backend()
        # )
        #
        # # Base64 decode the encrypted data
        # encrypted_data = base64.b64decode(username)
        #
        # # Decrypt the data using PKCS#1 v1.5 padding
        # decrypted_data = private_key_obj.decrypt(
        #     encrypted_data,
        #     padding.PKCS1v15()
        # )
        #
        # # Decode the decrypted bytes to get the original string
        # username = decrypted_data.decode('utf-8')
        #
        # if username is None:
        #     messages.error(request, 'Decryption failed. Check logs for details.', extra_tags='error')
        #     return redirect('index')

        # Check if the username already exists in the database
        if Member.objects.filter(username=username).exists():
            messages.error(request, 'Username is already taken.', extra_tags='error')
            return redirect('index')  # Redirect back to the registration page

        key = os.environ.get('AES_KEY')
        if not key:
            messages.error(request, 'AES key not found in environment variables.', extra_tags='error')
            return redirect('index')

        cipher = Fernet(key.encode())
        encrypted_firstname = cipher.encrypt(firstname.encode()).decode()

        # Process the form data as needed
        # For example, you can hash the username and password here if required

        member = Member(username=username, password=password, firstname=firstname, lastname=lastname,
                        firstnameAES=encrypted_firstname, usernameRSA=usernameRSA)
        member.save()

        messages.success(request, 'Registration successful! You can now login.', extra_tags='success')
        return redirect('index')  # Redirect to the index page after successful registration

    else:
        private_key, public_key = generate_rsa_key_pair()

        context = {
            'public_key': public_key,
        }
        return render(request, 'index.html', context)


def login(request):
    return render(request, 'login.html')

def logout(request):
    auth_logout(request)
    return redirect('index')

def home(request):
    if request.method == 'POST':
        #print('username:' , request.POST['hashed_username'], ' password:', request.POST['hashed_password'])
        if Member.objects.filter(username=request.POST['hashed_username'], password=request.POST['hashed_password']).exists():
            member = Member.objects.get(username=request.POST['hashed_username'], password=request.POST['hashed_password'])
            return render(request, 'home.html', {'member': member})
        else:
            context = {'msg': 'Invalid username or password'}
            return render(request, 'login.html', context)


