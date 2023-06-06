import os
import shutil
import ast
import json

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.hash_module import Hash,int2Bytes,integer
from charm.toolbox.IBEnc import IBEnc
from ibenc.ibenc_bf01 import IBE_BonehFranklin
from charm.toolbox.msp import MSP
from AES_encryptor import encryption

class ibe_file_encryption(object):

    def __init__(self):
        self.FORMAT = 'utf-8'
        self.initialize_ibe()
        self.user_function()


    def initialize_ibe(self):
        # instantiate a bilinear pairing map
        self.pairing_group = PairingGroup('MNT224')

        # IBE Boneh Franklin Scheme Bilinear group pairing
        self.ibe = IBE_BonehFranklin(self.pairing_group)


    def create_master_parameters(self):

        # run the set up
        (self.pk, self.msk) = self.ibe.setup()


    def save_master_parameters(self):

        filename = 'masterfile.txt'
        curr_dir = os.getcwd()
        file = os.path.join(curr_dir, filename)
        with open(file, 'wb') as f:
            print((self.pk, self.msk))
            pk = {'P': self.pairing_group.serialize(self.pk['P']), 'P2': self.pairing_group.serialize(self.pk['P2'])}
            msk = {'s': self.pairing_group.serialize(self.msk['s'])}
            f.write(str((pk, msk)).encode(self.FORMAT))
        f.close()
        return


    def get_pk(self):

        filename = 'masterfile.txt'
        curr_dir = os.getcwd()
        file = os.path.join(curr_dir, filename)

        with open(file, 'rb') as f:
            data = f.read()
            pp = ast.literal_eval(data.decode(self.FORMAT))
            pk = {'P': self.pairing_group.deserialize(pp[0]['P']), 'P2': self.pairing_group.deserialize(pp[0]['P2'])}
        f.close()
        return pk

    
    def get_msk(self):
        
        filename = 'masterfile.txt'
        curr_dir = os.getcwd()
        file = os.path.join(curr_dir, filename)

        with open(file, 'rb') as f:
            data = f.read()
            pp = ast.literal_eval(data.decode(self.FORMAT))
            msk = {'s': self.pairing_group.deserialize(pp[1]['s'])}
        f.close()
        return msk


    def encrypt(self, file, id):

        if os.path.isdir(file):
            folder = file
            shutil.make_archive(file, "zip", file)
            file = file + ".zip"
            shutil.rmtree(folder)

        try:
            dir, filename = os.path.split(file)
        except:
            filename = file
            dir = os.getcwd()
            file = os.path.join(dir, filename)


        ## create master parameters

        #self.create_master_parameters()
        pk = self.get_pk()

        chunksize = 64 * 1024
        outfilename = "encrypted_" + filename
        outputfile = os.path.join(dir, outfilename)
        if os.path.exists(outputfile):
            print("File already exists")
            return
        filesize = str(os.path.getsize(file)).zfill(
            16
        )  ## adds 0 to make it a 16 digit number

        with open(file, "rb") as infile:
            with open(outputfile, "wb") as outfile:
                outfile.write(filesize.encode(self.FORMAT))
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b" " * (16 - (len(chunk) % 16))
                    #print(chunk)
                    ctxt = self.ibe.encrypt(pk, id, chunk)
                    #print(ctxt)
                    #print(ctxt['V'])
                    #print(int2Bytes(ctxt['V']))
                    #print(ctxt['W'])
                    #print(int2Bytes(ctxt['W']))
                    bytestring_ctxt = str({'U': self.pairing_group.serialize(ctxt['U']), 'V': int2Bytes(ctxt['V']), 'W': int2Bytes(ctxt['W'])}).encode(self.FORMAT)
                    #print(bytestring_ctxt)
                    outfile.write(bytestring_ctxt)
            outfile.close()
        infile.close()
        os.remove(file)
        return

    def ibe_keygen(self, id):

        msk = self.get_msk()
        key = self.ibe.extract(msk, id)
        return key


    def decrypt(self, file, id, masterkey):

        file = file.strip(" ")  ## remove quotations

        try:
            dir, filename = os.path.split(file)
        except:
            filename = file
            dir = os.getcwd()
            file = os.path.join(dir, filename)

        outfile = filename[10:]  ## after "encrypted_"
        outputfile = os.path.join(dir, outfile)
        if os.path.exists(outputfile):
            print("File already exists")       
            return

        
        if id != masterkey:
            if self.check_password(outputfile, id, masterkey) == False:
                print("Wrong password")
                print("Decryption Unsuccessful")
                return 0
        
        chunksize = 64 * 1024
        pk = self.get_pk()
        key = self.ibe_keygen(id)
        with open(file, "rb") as infile:
            filesize = int(infile.read(16))
            with open(outputfile, "wb") as of:
                while True:
                    chunk = infile.read(chunksize)

                    if len(chunk) == 0:
                        break
                    #print(f"Printing decryption\n")
                    #print(chunk)                    
                    ctxt = ast.literal_eval(chunk.decode(self.FORMAT))
                    #print(ctxt)
                    #print(ctxt['V'])
                    #print(ctxt['W'])
                    ct = {'U': self.pairing_group.deserialize(ctxt['U']), 'V': integer(ctxt['V']), 'W': integer(ctxt['W'])}
                    #print(ct)
                    pt = self.ibe.decrypt(pk, key, ct)
                    #print(pt)
                    of.write(pt)
                    of.truncate(filesize)
            of.close()
        infile.close()
        os.remove(file)

        try:
            shutil.unpack_archive(outputfile, os.path.join(dir, outfile[:-3]), "zip")
            os.remove(outputfile)
        except:
            pass
        return 1


    def create_password_vault(self, masterkey):

        filename = "password_vault.txt"
        cwd = os.getcwd()
        pass_file = os.path.join(cwd, filename)
        if os.path.exists(pass_file):
            return
        with open(pass_file, "w") as pf:
            pf.write(str(("Filename", "password-ID")))
            pf.write("\n")
        pf.close()

        encryption().encrypt(pass_file, masterkey)
        try:
            os.remove(pass_file)
        except:
            print("could not remove it\n")
            pass
        return

    def check_password(self, filename, password, masterkey):

        enc_pass_file = "encrypted_password_vault.txt"
        pass_file = enc_pass_file[10:]
        password_file = encryption().decrypt(enc_pass_file, masterkey, masterkey)
        tup = (filename, password)
        with open(pass_file, "r") as pfile:
            data = []
            for line in pfile.readlines():
                data.append(ast.literal_eval(line))
        pfile.close()
        encryption().encrypt(pass_file, masterkey)
        if tup in data:
            return True
        return False

    def update_password_vault(self, filename, password, masterkey):

        enc_pass_file = "encrypted_password_vault.txt"
        pass_file = enc_pass_file[10:]
        password_file = encryption().decrypt(enc_pass_file, masterkey, masterkey)
        tup = (filename, password)
        with open(pass_file, "r") as rfile:
            data = []
            for line in rfile.readlines():
                data.append(ast.literal_eval(line))
        rfile.close()

        found = [item for item in data if item[0] == filename]
        if found == []:
            with open(pass_file, "a") as pfile:
                pfile.write(str(tup))
                pfile.write("\n")
            pfile.close()
        else:
            data.remove(found[0])
            data.append((filename, password))
            with open(pass_file, "w") as wfile:
                for item in data:
                    wfile.write(str(item))
                    wfile.write("\n")
            wfile.close()
        encryption().encrypt(pass_file, masterkey)
        return


    def check_password_vault(self, masterkey):
        enc_pass_file = "encrypted_password_vault.txt"
        encryption().decrypt(enc_pass_file, masterkey, masterkey)
        pass_file = os.path.join(os.getcwd(), enc_pass_file[10:])
        with open(pass_file, "r") as pfile:
            for line in pfile.readlines():
                print(line)
        pfile.close()
        encryption().encrypt(pass_file, masterkey)


    def user_function(self):
        cwd = os.getcwd()
        masterkey = input("Enter masterkey to use password vault or press Enter to skip: "
        )
        default_masterkey = str(1)
        if masterkey:
            self.create_password_vault(masterkey)
        else:
            masterkey = default_masterkey  ## default masterkey
            self.create_password_vault(masterkey)
        
        mstfname  = 'masterfile.txt'
        masterfile  = os.path.join(cwd, mstfname)
        if os.path.exists(masterfile):
            print('masterfile exists')
        else:
            print('creating new masterfile')
            self.create_master_parameters()
            self.save_master_parameters()
        while True:
            prompt = int(
                input(
                    "Press 1 to encrypt file(s) or directory(s)\nPress 2 to decrypt file(s) or directory(s)\nPress 3 to view password vault\nPress 4 to refresh secrets\nPress 5 to exit: "
                )
            )
            if prompt == 1:
                filename = input(
                    "Enter / Drag file(s) or directory(s) (Separate by space ' '): "
                )
                file_list = filename.split('" "')
                loop_breaker_flag = 0
                for item in file_list:
                    if str(item).count(".") == 1:
                        continue
                    elif str(item).count(".") == 0:
                        loop_breaker_flag = 1
                        break
                    else:
                        file_list.remove(item)
                        file_list.extend(item.split())
                if loop_breaker_flag == 1:
                    print("Sorry something went wrong with files entered\n")
                    break
                for i, item in enumerate(file_list):
                    print(f"File {i+1}: {item}")
                    filename = item.replace('"', "")
                    file = os.path.join(cwd, filename)
                    if os.path.exists(file):
                        id = input("Enter id to encrypt with: ")
                        encrypted_file = self.encrypt(filename, id)
                        print("Encryption successful")
                        
                        if masterkey:
                            print("Saving ID into password vault\n")
                            self.update_password_vault(filename, id, masterkey)
                        else:
                            pass
                        
                    else:
                        print("File does not exist\n")
                        print("Encryption unsuccessful")

            elif prompt == 2:
                filename = input("Enter / Drag file(s): ")
                file_list = filename.split('" "')
                loop_breaker_flag = 0
                for item in file_list:
                    if str(item).count(".") == 1:
                        continue
                    elif str(item).count(".") == 0:
                        loop_breaker_flag = 1
                        break
                    else:
                        file_list.remove(item)
                        file_list.echunkxtend(item.split())
                if loop_breaker_flag == 1:
                    print("Sorry something went wrong with files entered\n")
                    break
                for i, item in enumerate(file_list):
                    print(f"File {i+1}: {item}")
                    filename = item.replace('"', "")
                    file = os.path.join(cwd, filename)
                    if os.path.exists(file):
                        id = input("Enter the decryption id to get key: ")
                        decrypted_file = self.decrypt(filename, id, masterkey)
                        if decrypted_file == 1:
                            print("Decryption Sucessful")
                        else:
                            print(decrypted_file)
                            print("Decryption unsuccessful")
                    else:
                        print("File does not exist")
                        print("Decryption unsuccessful")

            elif prompt == 3:
                if masterkey != default_masterkey:
                    self.check_password_vault(masterkey)
                elif masterkey == default_masterkey:
                    input_masterkey = input("Enter masterkey: ")
                    if input_masterkey == masterkey:
                        self.check_password_vault(masterkey)
                    else:
                        print("Wrong masterkey inserted")
            
            elif prompt == 4:
                print('creating new masterfile')
                self.create_master_parameters()
                self.save_master_parameters()
            elif prompt == 5:
                break
            else:
                print("Wrong Prompt. Enter again: ")
        return


def main():

    
    # instantiate a bilinear pairing map    bytestring_ctxt = str({'U': pairing_group.serialize(ctxt['U']), 'V': int2Bytes(ctxt['V']), 'W': int2Bytes(ctxt['W'])}).encode('utf-8')
    '''
    pairing_group = PairingGroup('MNT224')elf.FORMAT))
                    of.truncate(filesize)

    # AC17 CP-ABE under DLIN (2-linear)
    ibe = IBE_BonehFranklin(pairing_group)

    # run the set up
    (pk, msk) = ibe.setup()

    # generate a key
    id = 'user1'
    key = ibe.extract(msk, id)

    # choose a random message
    msg = b'Hello'

    # generate a ciphertext
    ctxt = ibe.encrypt(pk, id, msg)
    print(f"Ciphter text is: {ctxt}")
    print(type(ctxt))
    print(type(ctxt['V']))
    bytestring_ctxt = str({'U': pairing_group.serialize(ctxt['U']), 'V': int2Bytes(ctxt['V']), 'W': int2Bytes(ctxt['W'])}).encode('utf-8')
    print(f"bytesring is: {bytestring_ctxt}")
    # decryption

    ct = ast.literal_eval(bytestring_ctxt.decode(encoding='utf-8'))
    ct = {'U': pairing_group.deserialize(ct['U']), 'V': integer(ct['V']), 'W': integer(ct['W'])}
    print(f"Ciphter text is: {ctxt}")
    print(type(ct))
    print(type(ct['U']))
    print(type(ct['V']))
    rec_msg = ibe.decrypt(pk, key, ct)
    print(msg)
    if rec_msg == msg:
        print ("Successful decryption.")
    else:
        print ("Decryption failed.")
    print(rec_msg)
    '''
    enc = ibe_file_encryption()



main()