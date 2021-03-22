# color-dissector
Wireshark dissector for CoLoR protocol.

CoLoR dissector is capable of dissecting the following packet
- ANN packet
- GET packet
- DATA packet

Support for CONTROL packet will be added later.
  
## Setup
1. Go to Help –> About Wireshark –> Folders. 
2. Choose either the Personal Lua Plugins, Global Lua Plugins or Personal configuration folder. E.g. C:\Program Files\Wireshark\plugins\2.6 on Windows. 
3. Copy color.lua to the folder you choose in step 2. For developers you may like to clone this repository directly to the folder.
4. The script will be active when Wireshark is started. You have to restart Wireshark after you do changes to the script, or reload all the Lua scripts with **Ctrl+Shift+L**.