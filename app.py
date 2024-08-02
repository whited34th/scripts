#simple web scaper 

""" 
helps in geting the title, heading and div content of the html pages

"""
import requests 
from bs4 import BeautifulSoup
#from selenium import webdriver

r = requests.get("https://www.w3schools.com")
#soup = BeautifulSoup(r.content, 'html.parser')
#dvr = webdriver.Firefox()

if r.status_code == 200:
    print(f"{r.headers}-{r.status_code} Success")
elif r.status_code == 404:
    print(f"{r.status_code} Not Found")