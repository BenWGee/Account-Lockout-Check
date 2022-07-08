from ldap3 import Server, Connection, SAFE_SYNC, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
import argparse, os

#==============================================================================
def isValid(username:str, basedn:str, conn:Connection):
	"""
	Overview: Check if the username exists in Active Directory
	"""
    search_filter = "(&(objectCategory=User)(samAccountName=" + username + "))"
    search_attribute = ["samAccountName"]
    if conn.search(basedn, search_filter, attributes=search_attribute)[0]:
        return True
    else:
        return False
#==============================================================================

#==============================================================================
def isLocked(username:str, basedn:str, conn:Connection):
	"""
	Check if the username is locked out by querying Active Directory
	"""
    search_filter = "(&(objectCategory=User)(samAccountName=" + username + ")(lockoutTime>=1))" #all users with same name as user
    search_attribute = ["samAccountName"]
    if conn.search(basedn, search_filter, attributes=search_attribute)[0]:
        print("Account " + username + " is locked out.")
        returnCode = 2
    else:
        print("Account " + username + " is not locked out")
        returnCode = 0

    return returnCode
#==============================================================================

# MAIN
if __name__ == "__main__":

	#GET COMMAND INPUT
    opts = argparse.ArgumentParser(prog="AD_Account_Lockout_Checker", formatter_class=argparse.ArgumentDefaultsHelpFormatter)


    opts.add_argument(
        "-u", "--username",
        required=True,
        default=None,
        type=str,
        help="String(username): Username credential to access server."
    )

    opts.add_argument(
        "-p", "--password",
        required=True,
        default=None,
        type=str,
        help="String(password): Password credential to access server."
    )

    opts.add_argument(
        "-l", "--LANID",
        required=True,
        default=None,
        type=str,
        help="String(LANDID): LAN ID to be tested."
    )

    opts.add_argument(
        "-s", "--server",
        required=True,
        default=None,
        type=str,
        help="String(server): Server to be checked against."
    )

    opts.add_argument(
        "-b", "--basedn",
        required=True,
        default=None,
        type=str,
        help="String(basedn): Base domain name."
    )

    # BUILD ARGS ARRAY
    args = opts.parse_args()
    
    returnCode = 3
    conn = Connection(
                    Server(args.server), 
                    user=args.username, 
                    password=args.password, 
                    client_strategy=SAFE_SYNC, 
                    auto_bind=True)

    if isValid(args.LANID, args.basedn ,conn):
        returnCode = isLocked(args.LANID, args.basedn ,conn)
    else:
        print(args.LANID + " is not a valid LAN ID.")
        returnCode = 2
