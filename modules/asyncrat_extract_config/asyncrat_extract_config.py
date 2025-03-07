"""
Config Extractor For Asyncrat and variants (dcrat/Venomrat)

Author: Matthew
Twitter: @Embee_Research

Samples:
Async: 4b63a22def3589977211ff8749091f61d446df02cfc07066b78d3302c034b0cc
Venom: 2941774e26232818b739deff45e59a32247a4a5c8d1d4e4aca517a6f5ed5055f
Dcrat: ed7cd05b950c11d49a3a36f6fe35e672e088499a91f7263740ee8b79f74224e9

The portion of this code that obtains the byte-based aes256.salt was heavily inspired 
by the OALabs StormKitty post. 
https://research.openanalysis.net/dot%20net/static%20analysis/stormkitty/dnlib/python/research/2021/07/14/dot_net_static_analysis.html


Usage: `asyncrat-config-extractor.py asyncrat.bin`
(Ensure that you have a copy of dnlib.dll in the same directory as this script)

"""

import clr,os,base64,binascii,hmac,hashlib,sys
current_dir = os.getcwd()
os.chdir("../modules/asyncrat_extract_config/")
current_dir = os.getcwd()
#Open dlib.dll from current directory
clr.AddReference(current_dir + "dnlib.dll")
from dnlib.DotNet import ModuleDefMD
from dnlib.DotNet.Emit import OpCodes
from Crypto.Cipher import AES
from backports.pbkdf2 import pbkdf2_hmac

#read the 1st argument containing filename to open
try:
    #filename = current_dir + "\\" + sys.argv[1]
    filename = sys.argv[1]
    print("Loading File: " + filename)
    module = ModuleDefMD.Load(filename)
except Exception as e:
    print("Unable to open file. Please ensure you have entered a filename as an argument")
    sys.exit(1)

#Temporarily read file so that sha256 can be calculated. 
try: 
    f = open(filename, "rb")
    data = f.read()
    f.close()
    sha_256 = "".join(x for x in str(hashlib.sha256(data).hexdigest()))
    print("SHA256: " + sha_256)
except:
    pass

# Name of Class containing configuration values
class_name = "Client.Settings"
# placeholders for storing data
values = []
name_mappings = {}
in_field = False

target_type = module.Find(class_name, isReflectionName=True)
if target_type:
    # Enumerate methods looking for constructors
    constructors = [m for m in target_type.Methods if m.Name in (".cctor", ".ctor")]
    for constructor in constructors:
        if constructor.HasBody:
            # Enumerate constructor instructions (IL)
            instructions = list(constructor.Body.Instructions)
            ################## ORIGINAL CODE FROM embee-research #############################
            #for instruction in constructor.Body.Instructions:
            #    print(instruction)
            #    #get encrypted string
            #    if "ldstr" in str(instruction):
            #        field_value = str(instruction).split(" ")[-1]
            #        field_value = field_value.strip("\"")
            #        in_field = True
            #    #Get field name from IL instructions
            #    if "stsfld" in str(instruction) and in_field:
            #        fieldname = str(instruction).split()[-1]
            #        name_mappings[fieldname] = field_value
            #        in_field = False
            ################################################################################
            i = 0
            for instruction in list(reversed(instructions)):
                if "stsfld" in str(instruction):
                    if "ldstr" in str(list(reversed(instructions))[i+1]):
                        field_name = str(f"{str(instruction).split(': stsfld')[1]}".strip("\n"))
                        field_value = str(list(reversed(instructions))[i+1]).split('"')[1].strip('"')
                        name_mappings[field_name] = field_value
                i += 1

#Get AES encryption key from settings
for i in name_mappings.keys():
    if "key" in i.lower():
        settings_key = name_mappings[i]

def get_salt_from_bin():
    #extract salt from "Client.Algorithm.Aes256" Class
    #This is needed to properly decrypt data
    salt = ""
    class_name = "Client.Algorithm.Aes256"
    target_type = module.Find(class_name, isReflectionName=True)
    #Enumerate constructors for string based salt (Dcrat,Venomrat)
    if target_type:
        constructors = [m for m in target_type.Methods if m.Name in (".cctor", ".cctor")]
        #for m in constructors:
        #    print(m)
        for constructor in constructors:
            #Enumerate constructor IL for "ldstr" operation, extract the argument
            #containing the salt value
            if constructor.HasBody:
                for instruction in constructor.Body.Instructions:
                    if "ldstr" in str(instruction):
                        salt = str(instruction).replace("\"","").split(" ")[-1]
                        return salt.encode('utf-8')
    #For asyncrat, extract the byte array based salt
    #this is heavily based on the StormKitty analysis by OALabs
    for mtype in module.GetTypes():
        #Skip type in no methods or no Body
        if not mtype.HasMethods:
            continue
        for method in mtype.Methods:
            if not method.HasBody:
                continue
            if not method.Body.HasInstructions:
                continue
            #If valid body, enumerate instructions for reference to salt (typically stsfld)
            for ptr in range(len(method.Body.Instructions)):
                instruction = method.Body.Instructions[ptr]
                if "stsfld" in str(instruction):
                    #If stsfld found, walk backwards to find ldtoken refernence to byte array salt
                    if "Aes256::Salt" in str(instruction):
                        for i in range(1,5):
                            if method.Body.Instructions[ptr-i].OpCode == OpCodes.Ldtoken:
                                #print(method.Body.Instructions[ptr-i])
                                mm = method.Body.Instructions[ptr-i]
                                token = mm.Operand.MDToken
    #If token found, locate the initial value of the byte array token
    #This is also borrowed from StormKitty analysis by OALabs
    for mtype in module.GetTypes():
        if mtype.get_HasFields:
            for field in mtype.get_Fields():
                if field.get_MDToken() == token:
                    try:
                        out = bytes(field.get_InitialValue())
                        #print(out)
                        return out
                    except:
                        continue
    return None

#Function for deriving AES Key from salt
def derive_aes_key(key,salt,keysize):
    key = bytearray(base64.b64decode(key))
    salt = bytes(salt)
    key = pbkdf2_hmac("SHA1", key, salt, 50000, keysize)
    return key

#Function for deriving IV from initial authkey
def generate_iv(authkey, enc):
    data = base64.b64decode(enc)
    data = data[32:]
    out = hmac.new(authkey, data,hashlib.sha256).hexdigest()
    return out[0:32]

#Function for performing primary encryption
def aes_decrypt(enc,key,iv):
    iv = bytes.fromhex(iv)
    enc = base64.b64decode(enc)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(enc)

#Generate AES Keys from salt. 
salt = get_salt_from_bin()
this_key = derive_aes_key(settings_key,salt,32)
auth_key = derive_aes_key(settings_key,salt,96)
auth_key = auth_key[32:]

#Enumerate encrypted config and decrypt/print as appropriate
for name in reversed(name_mappings.keys()):
    try: 
        enc = name_mappings[name]
        iv = generate_iv(auth_key,enc)
        result = aes_decrypt(enc,this_key, iv)
        inlen = len(base64.b64decode(enc))
        out = ""
        for i in result[48:]:
            out += chr(i)
        out2 = "".join(letter for letter in out if letter.isprintable())
        if len(out) < 100:
            print(name.split("::")[1] + ": " + out2)
    except:
        continue