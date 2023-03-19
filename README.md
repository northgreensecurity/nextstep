# nextstep

When you are looking at nmap output and trying to decide where to start or what to focus on **nextstep.py** can help

nextstep is a python script designed to take an nmap xml file (-oX outputfile) and help give testers quick visibility of all open ports, which are potentially worth looking into, and to decide what the next step of their test should be

This tool works especially well when assessing a large network and you want quick visibility of services and hosts

Once a port has been selected, get quick oversight of the potential targets, tools, and commands that can get you through a test faster

![image](https://user-images.githubusercontent.com/108965118/226145346-fa0af492-e04c-4dac-85ac-716ebfacf813.png)

# Using nextstep

To use nextstep run the following command:

python nextstep.py **nmap-xml-output-file.xml**


![nextstep](https://user-images.githubusercontent.com/108965118/226146451-3aaf4109-dd16-47cc-80f0-cb8ef6b1b462.gif)





