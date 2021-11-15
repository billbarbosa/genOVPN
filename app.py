import PySimpleGUI as sg
from pathlib import Path
from openvpn import make_new_ovpn_file

# Add a touch of color
sg.theme('LightBlue')

def create_ovpn():
    folder_path = values['-FOLDERPATH-']
    common_file = values['-COMMONFILE-']
    cacert = values['-CAPATH-']
    cakey = values['-CAKEYPATH-']
    username = values['-NAME-'].lower() + values['-LASTNAME-'].lower()
    file_path = str(Path(folder_path, username + ".ovpn"))
    
    make_new_ovpn_file(cacert, cakey, username, common_file, file_path)
    print("Done")

sg.set_options(element_padding=((5,5),(5,5)), text_justification="right", element_size=(36,1))

# All the stuff inside your window.
layout = [ [sg.Text('Choose Folder to save OVPN file', size=(30,1)), sg.InputText(key="-FOLDERPATH-"), sg.FolderBrowse()],
        [sg.Text('Common OVPN file path', size=(30,1)), sg.InputText(key="-COMMONFILE-"), sg.FileBrowse()],
        [sg.Text('Load Certificate Authority', size=(30,1)), sg.InputText(key="-CAPATH-"), sg.FileBrowse()],
        [sg.Text('Load Key Certificate Authority', size=(30,1)), sg.InputText(key="-CAKEYPATH-"), sg.FileBrowse()],
        [sg.Text('Name', size=(30,1)), sg.InputText(key="-NAME-")],
        [sg.Text('Last Name', size=(30,1)), sg.InputText(key="-LASTNAME-")],
        [sg.Button("Create File", key="-CREATE-", enable_events=True)]
        ]

# Create the Window
window = sg.Window('openVPN config files Generator', layout)
# Event Loop to process "events" and get the "values" of the inputs
while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Cancel': # if user closes window or clicks cancel
        break
    elif event == '-CREATE-':
        create_ovpn()
    
window.close()