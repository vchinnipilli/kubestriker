from websocket import create_connection

import ssl


def cmd_exec(url, token):
    '''
    Receives response from web socket and streams to the terminal
    '''  
    auth = "Authorization: Bearer " + token
    ws = create_connection(url, sslopt={'cert_reqs': ssl.CERT_NONE}, header=[auth])

    output = ''
    while True:
        try:
            output += ws.recv().decode('utf-8')
        except:
            ws.close()
            break
    return output
