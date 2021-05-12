import re
import fileinput
import glob
import pprint
import os
import xml.etree.ElementTree as ET


files_to_visit = {}

struct_files = glob.glob("apidoc/xml/structmbedtls*.xml") + glob.glob("apidoc/xml/structpsa*.xml")

for struct_file in struct_files:
  struct_file_tree = ET.parse(struct_file)
  all_struct_members_definitions = struct_file_tree.getroot().findall(".//memberdef[@kind='variable']")

  # Create dictionary with following structre
  # "filepath" : { "variable_name1": (1, 2, 40, 61),  # line numbers
  #                "variable_name2": (60, 64),
  #              }
  for struct_member_def in all_struct_members_definitions:
    # find file path for this variable
    member_id = struct_member_def.attrib["id"]
    location = struct_member_def.find("location")
    file_path = location.attrib["file"]
    variable_name = struct_member_def.find("name").text
    # if path not yet in dictionary, create empty record to initialize
    if file_path not in files_to_visit:
      files_to_visit[file_path] = {}
    # if variable is not yet in this file's dictionary, create empty set to initialize
    if variable_name not in files_to_visit[file_path]:
      files_to_visit[file_path][variable_name] = set()

    # add variable definition
    files_to_visit[file_path][variable_name].add(int(location.attrib["line"]))

    # check where the variable was referenced
    references = struct_member_def.findall("referencedby")
    for reference in references:
      refid = reference.attrib["refid"]
      # assuming that compound name is related to header's xml file
      header_file = "apidoc/xml/" + reference.attrib["compoundref"] + ".xml"
      header_file_tree = ET.parse(header_file)
      # check if this reference is created by static inline function
      static_inline_function_definition = header_file_tree.getroot().find(f".//memberdef[@id='{refid}'][@kind='function'][@static='yes'][@inline='yes']")
      if static_inline_function_definition:
        static_inline_function_file_path = static_inline_function_definition.find("location").attrib["file"]
        # if path not yet in dictionary, create empty record to initialize.
        # This could happen if reference is inside header file which was not yet processed in search for variable definitions
        if static_inline_function_file_path not in files_to_visit:
          files_to_visit[static_inline_function_file_path] = {}
        # if variable is not yet in this file's dictionary, create empty set to initialize
        if variable_name not in files_to_visit[static_inline_function_file_path]:
          files_to_visit[static_inline_function_file_path][variable_name] = set()
        # function block scope
        function_lines_from = int(reference.attrib["startline"])
        function_lines_to = int(reference.attrib["endline"])
        # find codelines referencing struct's variable
        codelines_xml = header_file_tree.getroot().findall(f".//ref[@refid='{member_id}']/../..")
        # filter by function's scope
        codelines = [int(line.attrib["lineno"]) for line in codelines_xml if int(line.attrib["lineno"]) >= function_lines_from and int(line.attrib["lineno"]) <= function_lines_to]
        # add variable reference
        files_to_visit[static_inline_function_file_path][variable_name].update(codelines)

pp = pprint.PrettyPrinter(indent=4)
pp.pprint(files_to_visit)

for file_path, variables in files_to_visit.items():
  with fileinput.FileInput(file_path, inplace=True) as file:
    output_line_number = 1
    re_include_guard = re.compile(r"^#define.*{name}$".format(name=os.path.basename(file_path).replace('.','_').upper()))
    for line in file:
      insert_allow_private_include = False
      if re_include_guard.match(line):
        insert_allow_private_include = True
      for variable, var_lines in variables.items():
        for var_line in var_lines:
          if output_line_number == var_line:
            line = re.sub(r"(^.*?\W+)({var})(\W+.*$)".format(var=variable), r"\1MBEDTLS_PRIVATE(\2)\3", line)
      output_line_number += 1
      print(line, end='') # fileinput redirects stdout to the target file
      if insert_allow_private_include:
        insert_allow_private_include = False
        print("#include \"mbedtls/private_access.h\"")
