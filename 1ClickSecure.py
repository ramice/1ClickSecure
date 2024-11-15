import tkinter as tk
from tkinter import messagebox
import subprocess

def execute_command(command):
    try:
        subprocess.run(["powershell", "-Command", command], check=True)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to execute command:\n{e}")

def secure_system():
    # Apply the security settings
    commands = [
        # Set DNS servers
        "Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses 1.1.1.3,1.0.0.3",
        
        # Turn on firewall and block incoming connections
        "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block",
        
        # Create outbound rules for well-known protocols
        (
            "New-NetFirewallRule -DisplayName 'OutgoingTCP_ERAMIC' -Direction Outbound "
            "-Protocol TCP -RemotePort 25,53,80,443,465,587,993,995"
        ),
        (
            "New-NetFirewallRule -DisplayName 'OutgoingUDP_ERAMIC' -Direction Outbound "
            "-Protocol UDP -RemotePort 53,123,443"
        ),
        # Disable other outbound rules
        "Get-NetFirewallRule | Where-Object {$_.Direction -eq 'Outbound'} | Disable-NetFirewallRule",
        
        # Enable the custom rules
        "Enable-NetFirewallRule -DisplayName 'OutgoingTCP_ERAMIC'",
        "Enable-NetFirewallRule -DisplayName 'OutgoingUDP_ERAMIC'",
        
        # Enable Controlled Folder Access
        'Set-MpPreference -EnableControlledFolderAccess Enabled',
        
        # Set User Account Control to maximum
        'Set-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name ConsentPromptBehaviorAdmin -Value 2',
        
    ]

    for cmd in commands:
        execute_command(cmd)

    messagebox.showinfo("Success", "Security settings applied successfully.Sigurnosne postavke aktivne!")

def revert_system():
    # Revert settings to defaults
    commands = [
        # Revert DNS settings
        "Get-NetAdapter | Set-DnsClientServerAddress -ResetServerAddresses",
        
        # Enable all outbound firewall rules and disable all inbound blocks
        "Get-NetFirewallRule | Enable-NetFirewallRule",
        "Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Allow",
        
        # Disable Controlled Folder Access
        'Set-MpPreference -EnableControlledFolderAccess Disabled',
        
        # Set User Account Control to default
        'Set-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name ConsentPromptBehaviorAdmin -Value 5',
        
    ]

    for cmd in commands:
        execute_command(cmd)

    messagebox.showinfo("Reverted", "All changes have been reverted to defaults.Sve bi trebalo biti kao prije.")

def show_disclaimer():
    disclaimer_text = (
        "This program is provided as-is without any guarantees or warranty. The author is not responsible "
        "for any damage or data loss caused by using this tool. This program is intended for use in Workgroups "
        "only and should not be used in domains or enterprise environments. Please run the program as an administrator. "
        "It provides a one-click solution to enhance security on Windows systems by configuring DNS settings with no "
        "Adult content and Malware filtering, enabling firewalls with restrictive rules, activating Controlled Folder Access, "
        "maximizing User Account Control (UAC), and disabling Remote Desktop, with an option to revert all changes. Sretno!"
        "Please send feedback to: eramic@hotmail.com. This program will only work on Windows 10/11"
    )
    messagebox.showinfo("Disclaimer", disclaimer_text)

# Create the GUI
root = tk.Tk()
root.title("1 Click Secure")
root.geometry("300x250")
root.resizable(False, False)

# Title label
title_label = tk.Label(root, text="FAMILY SAFE SECURITY SETTING", font=("Arial", 12, "bold"))
title_label.pack(pady=10)

# Main button
secure_button = tk.Button(root, text="1 Click Secure", command=secure_system, bg="green", fg="white", font=("Arial", 10, "bold"))
secure_button.pack(pady=10, fill="x", padx=10)

# Additional buttons
button_frame = tk.Frame(root)
button_frame.pack(fill="x", pady=10)

disclaimer_button = tk.Button(button_frame, text="DISCLAIMER", command=show_disclaimer, bg="gray", fg="white", font=("Arial", 9))
disclaimer_button.pack(side="left", expand=True, fill="x", padx=5)

revert_button = tk.Button(button_frame, text="Revert all back", command=revert_system, bg="gray", fg="white", font=("Arial", 9))
revert_button.pack(side="left", expand=True, fill="x", padx=5)

# Footer with author info
footer = tk.Label(root, text="Author: www.linkedin.com/in/eramic", font=("Arial", 8), fg="blue", cursor="hand2")
footer.pack(side="bottom", pady=10)
footer.bind("<Button-1>", lambda e: subprocess.run(["start", "www.linkedin.com/in/eramic"], shell=True))

root.mainloop()
