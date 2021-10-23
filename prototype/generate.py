#!/usr/bin/python
#
# prereq:
# sudo apt-get install python-pip -y
# sudo pip install jinja2
#
import sys
import json
import os
import jinja2

def render(tpl_path, context):
    path, filename = os.path.split(tpl_path)
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(path or './')
    ).get_template(filename).render(context)

# load json from file
jsonConfigName = "example_driver.json"
print("jsonConfigName: " + jsonConfigName)
with open(jsonConfigName) as json_file:
    json_data = json.load(json_file)

templateFileName = "driver_wrapper_sample.conf"
configFileName = "sample_config.h"
# iterate through each json filter entry
# put entire json entry into jinja context for merging
context = json_data

print("\n================================================")
print("============ generate config ===================")
jsonClassifName = "driver_capability_config.json"
print("jsonClassifName: " + jsonClassifName)
with open(jsonClassifName) as json_Classiffile:
    json_Classifdata = json.load(json_Classiffile)

outFile = open(configFileName,"w+")

for driver in json_data["drivers"]:
    for capability in driver["capabilities"]:
       if "fallback" not in capability or capability["fallback"] == False:
# This will need to be extended to key types too.
# Need to check for complex types
         if "algorithms" in capability:
            for algo in capability["algorithms"]:
               outFile.write("#include " + json_Classifdata[algo] + "\n")                
outFile.close()
            
print("============ config generation complete ========\n")

print("================================================")
print("============ render template ===================")
# get template name, output file name
outputFileName = "driver_wrapper_sample.c" 
print("outputFileName: " + outputFileName)

# merge template with data
result = render(templateFileName,context)

# write output to file
outFile = open(outputFileName,"w")
outFile.write(result)
outFile.close()

print("============ render template complete ==========\n")
