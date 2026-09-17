import winrm        #   Access to Windows Remote Manager
import getpass      #   Hides Input Text


#   Define important connectivity 
SERVER_IP = "192.168.56.10"
WINRM_PORT = 5985


#   Create and Return WinRM Session to Windows Server VM
def create_session():

    username = input("Windows Server Username: ")
    password = getpass.getpass("Windows Server Password: ")

    #   Configuration to how Python reaches and authenticates to Window Server VM
    session = winrm.Session(
        f"http://{SERVER_IP}:{WINRM_PORT}/wsman",      #   Tells where WinRm Service is 
        auth = (username,password),                     #   Identity         
        transport = "ntlm"                              #   Authenticates Identity    
    )

    return session


#   Run Powershell Remotely on the Windows Server
def run_powershell(session, command):
    result_from_powershell = session.run_ps(command)

    #   Checks if remote command failed
    if result_from_powershell.status_code != 0:
        error = result_from_powershell.std_err.decode().strip()

        raise RuntimeError(
            f"Remote Powershell failed: {error}"
        )
    return result_from_powershell.std_out.decode().strip()


#   Tests the WinRM Connection by Retrieving the Remote hostname
def test_connection (session):
    hostname = run_powershell(session, "hostname")

    print("Connection Successful")
    print("Server: ", hostname)


if __name__ == "__main__":
   session = create_session()  #   session = username, password, auth, transport, IP, Port
   test_connection(session)  
   
    




    



