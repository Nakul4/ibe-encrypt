import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import shutil
import ast


class encryption(object):
    def __init__(self):
        #self.user_function()
        pass

    def encrypt(self, file, password):

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

        chunksize = 64 * 1024
        key = self.keygen(password)
        outfilename = "encrypted_" + filename
        outputfile = os.path.join(dir, outfilename)
        if os.path.exists(outputfile):
            print("File already exists")
            return
        filesize = str(os.path.getsize(file)).zfill(
            16
        )  ## adds 0 to make it a 16 digit number
        nonce = Random.new().read(16)

        encryptor = AES.new(key, AES.MODE_CBC, nonce)

        with open(file, "rb") as infile:
            with open(outputfile, "wb") as outfile:
                outfile.write(filesize.encode("utf-8"))
                outfile.write(nonce)

                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b" " * (16 - (len(chunk) % 16))
                    outfile.write(encryptor.encrypt(chunk))
            outfile.close()
        infile.close()
        os.remove(file)
        return

    def decrypt(self, file, password, masterkey):

        file = file.strip(" ")  ## remove quotations

        try:
            dir, filename = os.path.split(file)
        except:
            filename = file
            dir = os.getcwd()
            file = os.path.join(dir, filename)

        outfile = filename[10:]  ## after "encrypted_"
        outputfile = os.path.join(dir, outfile)
        if password != masterkey:
            if self.check_password(outputfile, password, masterkey) == False:
                print("Wrong password")
                print("Decryption Unsuccessful")
                return 0
        chunksize = 64 * 1024
        key = self.keygen(password)

        if os.path.exists(outputfile):
            print("File already exists")
            return

        with open(file, "rb") as infile:
            filesize = int(infile.read(16))
            nonce = infile.read(16)
            decryptor = AES.new(key, AES.MODE_CBC, nonce)
            with open(outputfile, "wb") as of:
                while True:
                    chunk = infile.read(chunksize)

                    if len(chunk) == 0:
                        break

                    of.write(decryptor.decrypt(chunk))
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

    def keygen(self, password):
        hasher = SHA256.new(password.encode("utf-8"))
        return hasher.digest()

    def create_password_vault(self, masterkey):

        filename = "password_vault.txt"
        cwd = os.getcwd()
        pass_file = os.path.join(cwd, filename)
        if os.path.exists(pass_file):
            return
        with open(pass_file, "w") as pf:
            pf.write(str(("Filename", "password")))
            pf.write("\n")
        pf.close()

        self.encrypt(pass_file, masterkey)
        try:
            os.remove(pass_file)
        except:
            pass
        return

    def check_password(self, filename, password, masterkey):

        enc_pass_file = "encrypted_password_vault.txt"
        pass_file = enc_pass_file[10:]
        password_file = self.decrypt(enc_pass_file, masterkey, masterkey)
        tup = (filename, password)
        with open(pass_file, "r") as pfile:
            data = []
            for line in pfile.readlines():
                data.append(ast.literal_eval(line))
        pfile.close()
        self.encrypt(pass_file, masterkey)
        if tup in data:
            return True
        return False

    def update_password_vault(self, filename, password, masterkey):

        enc_pass_file = "encrypted_password_vault.txt"
        pass_file = enc_pass_file[10:]
        password_file = self.decrypt(enc_pass_file, masterkey, masterkey)
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
        self.encrypt(pass_file, masterkey)
        return

    def check_password_vault(self, masterkey):
        enc_pass_file = "encrypted_password_vault.txt"
        self.decrypt(enc_pass_file, masterkey, masterkey)
        pass_file = os.path.join(os.getcwd(), enc_pass_file[10:])
        with open(pass_file, "r") as pfile:
            for line in pfile.readlines():
                print(line)
        pfile.close()
        self.encrypt(pass_file, masterkey)

    def user_function(self):
        cwd = os.getcwd()
        masterkey = input(
            "Enter masterkey to use password vault or press Enter to skip: "
        )
        if masterkey:
            self.create_password_vault(masterkey)
        else:
            default_masterkey = str(1)
            masterkey = default_masterkey  ## default masterkey
            self.create_password_vault(masterkey)
        while True:
            prompt = int(
                input(
                    "Press 1 to encrypt file(s) or directory(s)\nPress 2 to decrypt file(s) or directory(s)\nPress 3 to view password vault\nPress 4 to exit: "
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
                        password = input("Enter password: ")
                        encrypted_file = self.encrypt(filename, password)
                        print("Encryption successful")
                        if masterkey:
                            print("Saving password into password vault\n")
                            self.update_password_vault(filename, password, masterkey)
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
                        file_list.extend(item.split())
                if loop_breaker_flag == 1:
                    print("Sorry something went wrong with files entered\n")
                    break
                for i, item in enumerate(file_list):
                    print(f"File {i+1}: {item}")
                    filename = item.replace('"', "")
                    file = os.path.join(cwd, filename)
                    if os.path.exists(file):
                        password = input("Enter password: ")
                        decrypted_file = self.decrypt(filename, password, masterkey)
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
                break
            else:
                print("Wrong Prompt. Enter again: ")
        return

'''
def main():

    enc = encryption()


main()
'''