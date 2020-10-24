from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
import os
import dpkt
import socket
from geoip import geolite2

def geoLoc(ip):
	loc=geolite2.lookup(ip)
	try:
		reg=loc.timezone
		Lat,Long=loc.location
		if reg=='None':
			return [Lat,Long,'N/A']
		else:
			return [Lat,Long,reg]
	except:
		return 'N/A' 
def printPcap(pcap):
	data=''	
	i=0
	for (ts, buf) in pcap:
		i+=1
		try:
			eth = dpkt.ethernet.Ethernet(buf)
			ip = eth.data
			src = socket.inet_ntoa(ip.src)
			srcLoc=geoLoc(src)
			dst = socket.inet_ntoa(ip.dst)
			dstLoc=geoLoc(dst)
			data+='<tr data-toggle="collapse" data-target="#demo'+str(i)+'" class="accordion-toggle" bgcolor="#E5FFCC"><td><button class="btn btn-default btn-xs"><span class="glyphicon glyphicon-eye-open"></span></button></td>'
			data+='<td style="text-align:center">'+ src +'</td><td style="text-align:center">'+srcLoc[2]+'</td><td style="text-align:center">--></td><td style="text-align:center">' + dst+'</td><td style="text-align:center">'+dstLoc[2]+'</td></tr>'
			data+='<tr><td colspan="12" class="hiddenRow"><div class="accordian-body collapse" id="demo'+str(i)+'"><p><b>SRC</b><br>Lat: '+str(srcLoc[0])+'<br> Long: '+str(srcLoc[1])+'<br>'
			data+='<b>DST</b><br>Lat: '+str(dstLoc[0])+'<br> Long: '+str(dstLoc[1])+'</p></div></td></tr>'
		except:
			pass
	return data			


ALLOWED_EXTENSIONS = {'pcap'}
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html', text="Attention here only .pcap file accepted")

@app.route('/', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        if f.filename == "":
            return render_template('index.html', text="No file Name")
        if not allowed_file(f.filename):
            return render_template('index.html', text="File extension not allowed!")
        else:
            full_filename = secure_filename(f.filename)
            f.seek(0)
            pcap = dpkt.pcap.Reader(f)
            
            content=printPcap(pcap)
            return render_template('result.html', text=content)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337)