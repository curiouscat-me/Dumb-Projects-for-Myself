## Personal Assisstance AI assembled

import speech_recognition as sr
import pyaudio
import pyttsx3
from datetime import date, datetime
import requests


##Activate AI's functionalities
ear = sr.Recognizer()
mouth = pyttsx3.init()
robot_brain = ""

while True:

#Listen
    with sr.Microphone() as mic:
        ear.adjust_for_ambient_noise(mic, duration = 1)
        print("I'm listening...")
        audio = ear.listen(mic)
    print("...")

    ## Handling error when it can't understand
    try:
        you = ear.recognize_google(audio)
    except:
        you = "..."

    print("You: ", you.capitalize())


    ##Analyse 
    if you == "":
        robot = "I can't understand that, please try again!"
    elif "hello" or "hi" in you:
        brain = "Hi there!"
    elif "date" in you:
        today = date.today()
        robot_brain = today.strftime("%B %d, %Y")
    elif "time" in you:
        now = datetime.now()
        robot_brain = now.strftime("It's %H %M")
    #elif "weather" in you:
        ##url for current weather based on location 
        # url = "https://wttr.in/melbourne"
        # res = requests.get(url)
        # robot_brain = res...()
        ##### Still have a hard time with this haha
    elif "bye" in you:
        robot_brain = "See you again!"
        voice = mouth.getProperty('voices')
        mouth.setProperty('voice', voice[0].id)
        mouth. setProperty("rate", 180)
        mouth.say(robot_brain)
        mouth.runAndWait()
        break
    else:
        robot_brain = "I can't understand that, please try again!"
    print("Robot: ", robot_brain)

    ##Speak 
    voice = mouth.getProperty('voices')
    mouth.setProperty('voice', voice[0].id)
    mouth. setProperty("rate", 180)
    mouth.say(robot_brain)
    mouth.runAndWait()






