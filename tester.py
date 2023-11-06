import os

def check_file_path():
    base_dir = os.getcwd()
    target_file = os.path.join(base_dir, 'apps', 'templates', 'home', 'index.html')
    print(f"Checking path: {target_file}")
    
    if os.path.isfile(target_file):
        print("The file exists!")
    else:
        print("The file does not exist!")

if __name__ == '__main__':
    check_file_path()