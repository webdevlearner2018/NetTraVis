import os
import re
import requests
import pandas as pd
from subprocess import call
from werkzeug.utils import secure_filename
from flask import Flask, jsonify, request, render_template, url_for, redirect, flash
from wtforms import validators
from flask_wtf.csrf import CSRFProtect, CSRFError 

app = Flask(__name__, template_folder="templates", static_folder='static') # instantiating the imported Flask class
app.config['TEMPLATES_AUTO_RELOAD'] = True 

app.secret_key = 'q/w3!4er5t6y78y9=cd?u' #assign a secret key used for csrf_token
csrf = CSRFProtect(app) #Enable CSRF protection globally for a Flask app.

#Lax prevents sending cookies with CSRF-prone requests from external sites, such as submitting a form. 
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

#Custom Error message for 404 Not Found
@app.errorhandler(404)
def error404(error):
    return '<h2>404: Page Not Found</h2>', 404

# Custom Error message for 500 Internal Server Errror 
@app.errorhandler(500)
def error500(error):
    return '<h2>Something Went Wrong!!!</h2>', 500
    
# Custom Error message for 405 Method Not Allowed 
@app.errorhandler(405)
def error405(error):
    return '<h2>Method is not allowed!!!</h2>', 405

#route() decorator tell Flask that when user type "/" in the address bar just after the "localhost:5000" it will 
#trigger the URL for "home" page. It binds the home() function to the URL "localhost:5000/"
@app.route('/')
 #home() is the function name which is also used to generate URL for that particular function, and returns
 # the message we want to display in the user’s browser. 
def home(): 
    return render_template("home.html") #render home.html template

#secure configuration
@app.after_request
def apply_caching(response):
    #set X-Frame-Options Header "SAMEORIGIN", so page can only be displayed in a frame on the same origin 
    #as the page itself to protect against 'ClickJacking' attacks.
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    #Set headers 'X-Content-Type-Options' to 'nosniff' to force the browser to honor the response content type instead 
    #of trying to detect it, which can be abused to generate a cross-site scripting (XSS) attack.
    response.headers['X-Content-Type-Options'] = 'nosniff'
    #The browser will try to prevent reflected XSS attacks by not loading the page if the request contains something 
    #that looks like JavaScript and the response contains the same data.
    response.headers['X-XSS-Protection'] = '1; mode=block'    
    return response

#create the route and function for "capture"
@app.route('/capture')
def capture():
    return render_template("capture.html")

#after user click on "Submit and Capture" button on the "Capture Live Network Traffic" form, this function will be triggered 
@app.route('/getinput', methods=['GET', 'POST'])
def getinput():
    if request.method == "POST":
        #when user selects the option "Number of packets"
        if request.values['useroption'] == 'packets':
            #tshark command will be used for capturing a number of packets
            tsharkcmd = "tshark -w userinputpackets.pcap -c {}"
            userinput_filename = "userinputpackets.pcap"
        #when user selects the option "Duration"
        if request.values['useroption'] == 'duration':
            #tshark command will be used for capturing in a set time
            tsharkcmd = "tshark -w userinputseconds.pcap -a duration:{}"
            userinput_filename = "userinputseconds.pcap"
        userinput = request.values['userinput']
        #filter the user's input to accept digits only 
        if not(re.findall("\d+[a-zA-Z]",userinput) or re.findall("[a-zA-Z]\d+",userinput)):
            #pass the userinput to tshark command and then execute the tshark command in the windows terminal
            os.system(tsharkcmd.format(userinput))
        #after the capturing finished, the network traffic data was saved in the file named userinput_filename as a pcap file
        #the following codes will read the pcap file with the tshark command and save the output as a csv file         
        tsharkCall = ["tshark", "-r", f"{userinput_filename}", "-T", "fields", "-e", "frame.number", "-e", "_ws.col.Time", "-e", "_ws.col.Source", "-e", "_ws.col.Destination", "-e", "_ws.col.Protocol", "-e", "_ws.col.Length", "-e", "_ws.col.Info", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
        with open("data.csv", "w") as tsharkOut:
            tsharkOut.write("\"Fnum\",\"Time\",\"Source\",\"Destination\",\"Protocol\",\"Length\",\"Info\"\n")
            tsharkOut.flush() #method cleans out the internal buffer.
            call(tsharkCall, stdout=tsharkOut) #take the tsharkCall as input and write output to the tsharkOut
            tsharkOut.close()
    #redirect the user to visualization page after data ready for visualizing
    return redirect("/visualization", code=302) 

#create URL and function for upload
@app.route('/upload')
def upload():
    return render_template("upload.html")
    
@app.route('/getupload', methods=['GET', 'POST'])
def getupload():
    if request.method == "POST":
        #get the uploaded file from the HTML form in the upload.html template
        f = request.files['file']
        # secure_filename(f.filename) function will change the malicious file name as meaningless name 
        f.save(secure_filename(f.filename))
        final_name = f.filename #assign the safe name
        tsharkCall = ["tshark", "-r", f"{final_name}", "-T", "fields", "-e", "frame.number", "-e", "_ws.col.Time", "-e", "_ws.col.Source", "-e", "_ws.col.Destination", "-e", "_ws.col.Protocol", "-e", "_ws.col.Length", "-e", "_ws.col.Info", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
        with open("data.csv", "w") as tsharkOut:
            tsharkOut.write("\"Fnum\",\"Time\",\"Source\",\"Destination\",\"Protocol\",\"Length\",\"Info\"\n")
            tsharkOut.flush()
            call(tsharkCall, stdout=tsharkOut)
            tsharkOut.close()
        #redirect the user to visualization page after data ready for visualizing
        return redirect("/visualization", code=302)

#create URL and function for filter
@app.route('/filter')
def filter():
    dataframe = pd.read_csv("data.csv") #read the data in data.csv file and store them in the dataframe object
    noofrows = len(dataframe.Fnum) #count number of rows in dataframe object
    return render_template("filter.html", title="Filter", dataframe=dataframe, noofrows=noofrows)

#create URL and function for visualization       
@app.route('/visualization')
def visualization():    
    return render_template("visualization.html", title="Chart")

#create URL and function for protocols       
@app.route('/protocols') # route('/protocols') decorator is to tell Flask the "/protocols" URL should trigger our function
def protocols():
    #read the data in data.csv file and store them in the dataframe object
    dataframe = pd.read_csv("data.csv")
    #calculate the frequency of each protocol in dataframe   
    profreq = dataframe.Protocol.value_counts()
    #count the number of different protocols or number of rows in profreq object
    numofpro = len(profreq)   
    #render the template protocols.html and pass the data stored in the objects profreq and numofpro
    return render_template("protocols.html", title="Chart", profreq=profreq, numofpro=numofpro)

#create URL and function for sourceport       
#Extract Source ports from the Info column 
@app.route('/sourceport')
def sourceport():
    dataframe = pd.read_csv("data.csv")
    info = dataframe.Info
        
    liststoresports=[] #the list of lists to store pairs of source port and destination port
    srccorrespondingtoport=[] #an array to store the source IP address corresponding to port 
    for row in range(len(info)):
        #if each word in each row of Info does not start with a digit and follow by a letter/letters
        #or does not start with a letter/letters and end with a digit
        if not(re.findall("\d+[a-zA-Z]",info[row]) or re.findall("[a-zA-Z]\d+",info[row]) or re.findall(r"\d+[.,?/\|#<>:;'@!£$%&()-]\b",info[row]) or re.findall(r"[.,?/\|#<>:;'@!£$%&()-]\d+",info[row])):
            rowcontainsnum=re.findall("\d+",info[row])
            if not(rowcontainsnum==[]): #if each time the array rowcontainsnum starts with a number 
                srccorrespondingtoport.append(dataframe.Source[row])                
                for n in range(1):
                    #append a pair of source port and destination port into liststoresports array
                    liststoresports.append([rowcontainsnum[n],rowcontainsnum[n+1]])
    
    #Store source ports and destination ports in seperated arrays 
    srcports=[] #the array to keep source ports
    dstports=[] #the array to keep destination ports
    for row in range(len(liststoresports)):
        for col in range(2):
            if col==0:
                srcports.append(liststoresports[row][col])
            else:
                dstports.append(liststoresports[row][col])  

    # create a dataframe for Source and Port
    SrcnPortDF = pd.DataFrame({'Source':srccorrespondingtoport, 'Port':srcports})
    groupbySrcPort = SrcnPortDF.groupby(['Source','Port'])['Source'].count().unstack().fillna(0)
    numofrows = len(groupbySrcPort)
    numofcolumns = len(groupbySrcPort.columns)

    return render_template("sourceport.html", title="Chart", groupbySrcPort=groupbySrcPort, numofrows=numofrows, numofcolumns=numofcolumns)

#create URL and function for dstport       
#Extract Destination ports from the Info column 
@app.route('/dstport')
def dstport():
    dataframe = pd.read_csv("data.csv")
    info = dataframe.Info #Extract the Info field and save it to the info object    
    
    liststoresports=[] #the list of lists to store pairs of source port and destination port    
    dstcorrespondingtoport=[] #an array to store the destination IP address corresponding to port 
    for row in range(len(info)):
        #if each group of characters in each row of Info field does not start with a digit/digits and follow by a letter/letters or 
        # ".,?/\|#<>:;'@!£$%&()-" or does not start with a letter/letters or ".,?/\|#<>:;'@!£$%&()-" and end with a digit/digits
        if not(re.findall("\d+[a-zA-Z]",info[row]) or re.findall("[a-zA-Z]\d+",info[row]) or re.findall(r"\d+[.,?/\|#<>:;'@!£$%&()-]\b",info[row]) or re.findall(r"[.,?/\|#<>:;'@!£$%&()-]\d+",info[row])):
            rowcontainsnum=re.findall("\d+",info[row]) #find all numbers in the Info field and return to rowcontainsnum list
            if not(rowcontainsnum==[]): #if each time the array rowcontainsnum contains a number                 
                dstcorrespondingtoport.append(dataframe.Source[row])
                for n in range(1):
                    #append a pair of source port and destination port into liststoresports list
                    liststoresports.append([rowcontainsnum[n],rowcontainsnum[n+1]])
       
    #Store source ports and destination ports in seperated arrays 
    srcports=[] #the array to keep source ports
    dstports=[] #the array to keep destination ports
    for row in range(len(liststoresports)):
        for col in range(2):
            if col==0:
                srcports.append(liststoresports[row][col])
            else:
                dstports.append(liststoresports[row][col])

    # create a dataframe for Destination and Port
    DstPortDF = pd.DataFrame({'Source':dstcorrespondingtoport, 'Port':dstports})
    groupbyDstPort = DstPortDF.groupby(['Source','Port'])['Source'].count().unstack().fillna(0)
    numofrows = len(groupbyDstPort)
    numofcolumns = len(groupbyDstPort.columns)    

    return render_template("dstport.html", title="Chart", groupbyDstPort=groupbyDstPort, numofrows=numofrows, numofcolumns=numofcolumns)


#create URL and function for lenininfo       
#Extract Len from the Info column 
@app.route('/lenininfo')
def lenininfo():
    dataframe = pd.read_csv("data.csv")
    #extract two fields in the dataframe object and save to Protocol_Info object    
    Protocol_Info = dataframe[["Protocol","Info"]]    
    ProtocolCorrespondingToLen = []
    LenInInfo = []
    for row in range(len(Protocol_Info)):
        #if Len in a specific row of Info column found
        if (re.findall("Len=\d*", Protocol_Info.Info[row])):
            #take the Len value found in a specific row of the Info column            
            y = re.search("Len=\d*", Protocol_Info.Info[row])
            #append the Protocol that correspoding to the Len found in a specific row to ProtocolCorrespondingToLen list
            ProtocolCorrespondingToLen.append(Protocol_Info.Protocol[row])
            #append the Len found in a specific row to LenInInfo list
            LenInInfo.append(y.group())
    #create a DataFrame for ProtocolCorrespondingToLen and LenInInfo
    ProtocolnLenDF = pd.DataFrame({'Protocol':ProtocolCorrespondingToLen, 'Len':LenInInfo})
    #group the ProtocolnLenDF and display Protocol as the row label and Len as column label
    groupbyLenInInfo = ProtocolnLenDF.groupby(['Protocol','Len'])['Protocol'].count().unstack().fillna(0)   
    numofrows = len(groupbyLenInInfo)
    numofcolumns = len(groupbyLenInInfo.columns)    
    # render lenininfo.html template and pass the objects to this template
    return render_template("lenininfo.html", title="Chart", groupbyLenInInfo=groupbyLenInInfo, numofrows=numofrows, numofcolumns=numofcolumns)


#create URL and function for extractflags       
#Extract flags from the Info column 
@app.route('/extractflags')
def extractflags():
    dataframe = pd.read_csv("data.csv")    
    Source_Info = dataframe[["Source","Info"]] #pull out the Source and Info fields in the dataframe object
    #The list of flags could be used in network traffic. The special characters [ and ] would be displayed as normal characters, so the 
    #\[ and \] are used to escape special characters [ ] to avoid the findall() method would return anything insides these [] as a list    
    flagList = ["\[SYN\]","\[SYN, ACK\]","\[ACK\]","\[PSH\]","\[PSH, ACK\]","\[FIN\]","\[FIN, ACK\]","\[RST\]","\[URG\]","\[ECE\]","\[CWR\]","\[NS\]"]
    SourceCorrespondingToFlag = [] # array/list to hold the Source IP addresses which related to flags  
    FlagInInfo = [] # list to store flags that extracted from the Info field 
    for flag in flagList: #Loop through each flag in the flagList 
        for row in range(len(Source_Info)): #each flag will be search through all rows in the Info column   
            if (re.findall(flag, Source_Info.Info[row])): #if a flag found in a specific row
                x = re.findall(flag, Source_Info.Info[row]) #then take this flag, x is a list stores the found flag
                #append the Source IP address that corresponding to found flag
                SourceCorrespondingToFlag.append(Source_Info.Source[row])
                FlagInInfo.append(x[0]) #append the found flag to the FlagInInfo list
    # create a DataFrame for Source and Flag
    SourcenFlagDF = pd.DataFrame({'Source':SourceCorrespondingToFlag, 'Flag':FlagInInfo})
    #group the Source and Flag, Source will be set as the row label and Flag as column label
    groupbyFlagInInfo = SourcenFlagDF.groupby(['Source','Flag'])['Source'].count().unstack().fillna(0)
    numofrows = len(groupbyFlagInInfo)
    numofcolumns = len(groupbyFlagInInfo.columns)

    return render_template("extractflags.html", title="Chart", groupbyFlagInInfo=groupbyFlagInInfo, numofrows=numofrows, numofcolumns=numofcolumns)

#create URL and function for source 
@app.route('/source')
def source():
    dataframe = pd.read_csv("data.csv")
    #Pull out the Source IP addresses and count the frequency of each one 
    source = dataframe.Source.value_counts()
    sumsrc = len(source)

    return render_template("source.html", title="Chart", sumsrc=sumsrc, source=source)

#create URL and function for destination 
@app.route('/destination')
def destination():
    dataframe = pd.read_csv("data.csv")
    #Pull out the Destination IP addresses and count the frequency of each one 
    destination = dataframe.Destination.value_counts()
    dstrows = len(destination)

    return render_template("destination.html", title="Chart", dstrows=dstrows, destination=destination)

#create URL and function for groupbysource 
@app.route('/groupbysource')
def groupbysource():
    dataframe = pd.read_csv("data.csv")
    #group the Source and Protocol, Protocol will be set as the row label and Source as column label    
    groupbySource = dataframe.groupby(['Source','Protocol'])['Source'].count().unstack(0).fillna(0)
    numofrows = len(groupbySource)
    numofcolumns = len(groupbySource.columns)

    return render_template("groupbysource.html", title="Chart", numofcolumns=numofcolumns, numofrows=numofrows, groupbySource=groupbySource)

#create URL and function for groupbyprotocol
@app.route('/groupbyprotocol') # The decorator tells Flask the "/groupbyprotocol" URL should trigger groupbyprotocol() function
def groupbyprotocol(): 
    dataframe = pd.read_csv("data.csv")
    # Group 'Source' and 'Protocol' together, count the Source IP address for each protocol, 
    #the method unstack() is to seperate Source IP addresses as row labels and protocols as column labels
    #the fillna(0) method fills all Nan with 0
    groupbyProtocol = dataframe.groupby(['Source','Protocol'])['Source'].count().unstack().fillna(0)
    #count the number of rows in groupbyProtocol object
    numofrows = len(groupbyProtocol)
    #count the number of columns in groupbyProtocol object
    numofcolumns = len(groupbyProtocol.columns)
    #display the result on a table and a chart by rendering the groupbyprotocol.html template
    return render_template("groupbyprotocol.html", title="Chart", numofcolumns=numofcolumns, numofrows=numofrows, groupbyProtocol=groupbyProtocol)

#create URL and function for tcp
@app.route('/tcp')
def tcp():
    dataframe = pd.read_csv("data.csv")
    #Extract only TCP protocol from the dataframe object
    tcp = dataframe[dataframe.Protocol == "TCP"]
    tcpfreq = len(tcp)    
    #plt.xticks(np.arange(51))
    return render_template("tcp.html", title="Chart", tcp=tcp, tcpfreq=tcpfreq)

#create URL and function for tcp
@app.route('/udp')
def udp():
    dataframe = pd.read_csv("data.csv")
    #Extract only UDP protocol from the dataframe object           
    udp = dataframe[dataframe.Protocol == "UDP"]
    udpfreq= len(udp)
    return render_template("udp.html", title="Chart", udp=udp, udpfreq=udpfreq)

#create URL and function for dns
@app.route('/dns')
def dns():    
    dataframe = pd.read_csv("data.csv")
    #Extract only DNS protocol from dataframe object        
    dns = dataframe[dataframe.Protocol == "DNS"]
    dnsfreq= len(dns)
    return render_template("dns.html", title="Chart", dns=dns, dnsfreq=dnsfreq)

#create URL and function for tlsv1
@app.route('/tlsv1')
def tlsv1():
    dataframe = pd.read_csv("data.csv")
    #Extract only TLSv1 protocol from dataframe object        
    tlsv1 = dataframe[dataframe.Protocol == "TLSv1"]
    tlsv1freq = len(tlsv1)   
    return render_template("tlsv1.html", title="Chart", tlsv1=tlsv1, tlsv1freq=tlsv1freq)

#create URL and function for tlsv1.2
@app.route('/tlsv1_2')
def tlsv1_2():
    dataframe = pd.read_csv("data.csv")
    #Extract only TLSv1.2 protocol from dataframe object        
    tlsv1_2 = dataframe[dataframe.Protocol == "TLSv1.2"]
    tlsv1_2freq = len(tlsv1_2)    
    return render_template("tlsv1_2.html", title="Chart", tlsv1_2=tlsv1_2, tlsv1_2freq=tlsv1_2freq)

#create URL and function for tlsv1.3
@app.route('/tlsv1_3')
def tlsv1_3():
    dataframe = pd.read_csv("data.csv")
    #Extract only TLSv1.3 protocol from dataframe object        
    tlsv1_3 = dataframe[dataframe.Protocol == "TLSv1.3"]
    tlsv1_3freq = len(tlsv1_3)       
    return render_template("tlsv1_3.html", title="Chart", tlsv1_3=tlsv1_3, tlsv1_3freq=tlsv1_3freq)

#create URL and function for telnet
@app.route('/telnet')
def telnet():
    dataframe = pd.read_csv("data.csv")
    #Extract only TELNET protocol from dataframe object        
    telnet = dataframe[dataframe.Protocol == "TELNET"]
    telnetfreq= len(telnet)    
    return render_template("telnet.html", title="Chart", telnet=telnet, telnetfreq=telnetfreq)

#create URL and function for ssdp
@app.route('/ssdp')
def ssdp():
    dataframe = pd.read_csv("data.csv")
    #Extract only SSDP protocol from dataframe object        
    ssdp = dataframe[dataframe.Protocol == "SSDP"]
    ssdpfreq= len(ssdp)    
    return render_template("ssdp.html", title="Chart", ssdp=ssdp, ssdpfreq=ssdpfreq)

#create URL and function for arp
@app.route('/arp')
def arp():    
    dataframe = pd.read_csv("data.csv") 
    #Extract only ARP protocol from dataframe object       
    arp = dataframe[dataframe.Protocol == "ARP"]
    arpfreq= len(arp)
    return render_template("arp.html", title="Chart", arp=arp, arpfreq=arpfreq)

#create URL and function for icmp
@app.route('/icmp')
def icmp():
    dataframe = pd.read_csv("data.csv")
    #Extract only ICMP protocol from dataframe object        
    icmp = dataframe[dataframe.Protocol == "ICMP"]
    frequency= len(icmp)
    return render_template("icmp.html", title="Chart", icmp=icmp, frequency=frequency)        

#create URL and function for icmpv6    
@app.route('/icmpv6')
def icmpv6():    
    dataframe = pd.read_csv("data.csv")
    #Extract only ICMPv6 protocol from dataframe object        
    icmpv6 = dataframe[dataframe.Protocol == "ICMPv6"]
    frequency= len(icmpv6)
    return render_template("icmpv6.html", title="Chart", icmp=icmp, frequency=frequency) 

#create URL and function for ocsp
@app.route('/ocsp')
def ocsp():
    dataframe = pd.read_csv("data.csv")
    #Extract only OCSP protocol from dataframe object        
    ocsp = dataframe[dataframe.Protocol == "OCSP"]
    frequency= len(ocsp)
    return render_template("ocsp.html", title="Chart", ocsp=ocsp, frequency=frequency)     

#create URL and function for dhcpv6    
@app.route('/dhcpv6')
def dhcpv6():
    dataframe = pd.read_csv("data.csv")
    #Extract only DHCPv6 protocol from dataframe object        
    dhcpv6 = dataframe[dataframe.Protocol == "DHCPv6"]
    frequency= len(dhcpv6)
    return render_template("dhcpv6.html", title="Chart", dhcpv6=dhcpv6, frequency=frequency)      

#create URL and function for mdns (Multicast Domain Name System query)
@app.route('/mdns')
def mdns():
    dataframe = pd.read_csv("data.csv")
    #Extract only MDNS protocol from dataframe object        
    mdns = dataframe[dataframe.Protocol == "MDNS"]
    frequency= len(mdns)
    return render_template("mdns.html", title="Chart", mdns=mdns, frequency=frequency)        
    
#create URL and function for db_lsp_disc (Dropbox LAN Sync Discovery Protocol)
@app.route('/db_lsp_disc')
def db_lsp_disc():
    dataframe = pd.read_csv("data.csv")
    #Extract only DB-LSD-DISC protocol from dataframe object        
    db_lsp_disc = dataframe[dataframe.Protocol == "DB-LSP-DISC"]
    db_lsp_discfreq= len(db_lsp_disc)    
    return render_template("db_lsp_disc.html", title="Chart", db_lsp_disc=db_lsp_disc, db_lsp_discfreq=db_lsp_discfreq)

#create URL and function for nbns (NetBIOS Name Service)
@app.route('/nbns')
def nbns():
    dataframe = pd.read_csv("data.csv")
    #Extract only NBNS protocol from dataframe object        
    nbns = dataframe[dataframe.Protocol == "NBNS"]
    frequency= len(nbns)
    return render_template("nbns.html", title="Chart", nbns=nbns, frequency=frequency)            
    
#create URL and function for browser (Microsoft Windows Browser Protocol)
@app.route('/browser')
def browser():
    dataframe = pd.read_csv("data.csv")
    #Extract only BROWSER protocol from dataframe object        
    browser = dataframe[dataframe.Protocol == "BROWSER"]
    browserfreq= len(browser)      
    return render_template("browser.html", title="Chart", browser=browser, browserfreq=browserfreq)

#create URL and function for igmpv2 (Internet Group Management Protoco v2)
@app.route('/igmpv2')
def igmpv2():
    dataframe = pd.read_csv("data.csv")
    #Extract only IGMPv2 protocol from dataframe object    
    igmpv2 = dataframe[dataframe.Protocol == "IGMPv2"]
    frequency= len(igmpv2)
    return render_template("igmpv2.html", title="Chart", igmpv2=igmpv2, frequency=frequency)          
    
#create URL and function for http
@app.route('/http')
def http():
    dataframe = pd.read_csv("data.csv")
    #Extract only HTTP protocol from dataframe object    
    http = dataframe[dataframe.Protocol == "HTTP"]
    frequency= len(http)

    return render_template("http.html", title="Chart", http=http, frequency=frequency)      


if __name__ == '__main__':
    app.run(host="localhost", port=5000, debug=False)
